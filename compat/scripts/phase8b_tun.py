#!/usr/bin/env python3
"""Phase 8B TUN config-identity and native Darwin arm64 gate.

Unprivileged: same stack identity as 8A (`smoltcp` only; Go stacks rejected
without remap). Device-name rules are unit-tested in rewrite-platform;
`-t` remains OS-neutral and still accepts `tun0` as a parse-time string.

Native traffic (YAML → utun → netstack-smoltcp → DIRECT, plus scutil DNS)
requires Darwin arm64 with root/passwordless sudo. Set PHASE8B_NATIVE=1;
missing capability fails closed instead of skipping green. System DNS
queries use `*.example.com` names because current macOS treats reserved
TLDs such as `.test` as mDNS and returns EAI_NONAME.
"""

from __future__ import annotations

import json
import os
import pathlib
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any

from phase1 import ROOT, assert_go_oracle_baseline, terminate_process
from phase3 import launch as launch_process
from phase5b1a import build_binaries
from phase8a_tun import (
    DNS_HIJACK_TARGET,
    FAKE_IP_RANGE,
    FAKE_IP_ROUTE,
    FixtureServers,
    HTTP_LARGE,
    HTTP_SMALL,
    MINIMAL,
    NATIVE_IO_DEADLINE,
    NATIVE_STARTUP_DEADLINE,
    SERVICE_IP,
    TUN_INET4,
    UDP_PAYLOAD,
    config_identity,
    expect_accept,
    make_query,
    parse_response,
    process_logs,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase8b-tun-diff.json"
CLEANUP_DEADLINE = 8.0
TUN_DNS = "198.18.0.2"
DARWIN_AUTO_PROBE = "1.1.1.1"
# Reserved TLDs such as `.test` are intercepted as mDNS on current macOS
# runners, so getaddrinfo returns EAI_NONAME even after scutil rewrite.
HTTP_NAME = "http.phase8b.example.com"
UDP_NAME = "udp.phase8b.example.com"
SYSTEM_DNS_DEADLINE = 15.0


def maybe_sudo(command: list[str]) -> list[str]:
    if os.geteuid() == 0:
        return command
    return ["sudo", "-n", "--", *command]


def run_cmd(command: list[str], *, check: bool = True, timeout: float = 15) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        maybe_sudo(command),
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"{' '.join(command)} failed: rc={result.returncode}\n{result.stdout}\n{result.stderr}"
        )
    return result


def native_prereq_error() -> str | None:
    if sys.platform != "darwin":
        return "PHASE8B_NATIVE requires Darwin"
    if platform.machine() != "arm64":
        return "PHASE8B_NATIVE requires Darwin arm64; refusing to skip green"
    for binary in ("ifconfig", "route", "scutil"):
        if shutil.which(binary) is None:
            return f"PHASE8B_NATIVE requires {binary}; refusing to skip green"
    if os.geteuid() == 0:
        return None
    probe = subprocess.run(
        ["sudo", "-n", "--", "true"],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if probe.returncode != 0:
        return (
            "PHASE8B_NATIVE requires root (passwordless sudo); refusing to skip green"
        )
    return None


def require_native_prereqs() -> None:
    error = native_prereq_error()
    if error:
        raise SystemExit(error)


def device_name_identity(binaries: dict[str, pathlib.Path], scratch: pathlib.Path) -> dict[str, Any]:
    rust = binaries["rust"]
    expect_accept(
        rust,
        MINIMAL + "\ntun:\n  enable: true\n  stack: smoltcp\n  device: utun8\n",
        scratch,
        "utun8 parse",
    )
    expect_accept(
        rust,
        MINIMAL + "\ntun:\n  enable: true\n  stack: smoltcp\n  device: tun0\n",
        scratch,
        "tun0 parse (OS-neutral; Darwin runtime rejects)",
    )
    expect_accept(
        rust,
        MINIMAL + "\ntun:\n  enable: true\n  stack: smoltcp\n",
        scratch,
        "empty device parse",
    )
    return {
        "rust-accepts-utunN": True,
        "rust-parse-accepts-tun0": True,
        "rust-accepts-empty-device": True,
    }


def tun_config(
    *,
    mixed_port: int,
    dns_listen: int,
    nameserver: str,
    device: str | None,
    auto_route: bool,
    stack: str,
) -> str:
    device_line = f"  device: {device}\n" if device else ""
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
dns:
  enable: true
  listen: 127.0.0.1:{dns_listen}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: fake-ip
  fake-ip-range: {FAKE_IP_RANGE}
  fake-ip-filter:
    - 'never-match.phase8b.example.com'
  nameserver:
    - udp://{nameserver}
tun:
  enable: true
{device_line}  stack: {stack}
  auto-route: {str(auto_route).lower()}
  inet4-address:
    - {TUN_INET4}
  dns-hijack:
    - 0.0.0.0:53
  mtu: 1500
rules:
  - DOMAIN,{HTTP_NAME},DIRECT
  - DOMAIN,{UDP_NAME},DIRECT
  - MATCH,REJECT
"""


def write_config(scratch: pathlib.Path, name: str, source: str) -> pathlib.Path:
    path = scratch / name
    path.write_text(source)
    return path


def stop_process(process: subprocess.Popen[bytes], scratch: pathlib.Path | None = None) -> int:
    try:
        return terminate_process(process, normalize_requested=True)
    except Exception:
        if scratch is not None:
            print(process_logs(scratch), file=sys.stderr)
        raise


def wait_mixed(process: subprocess.Popen[bytes], port: int, scratch: pathlib.Path) -> None:
    deadline = time.monotonic() + NATIVE_STARTUP_DEADLINE
    last_error = "not attempted"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"proxy exited during TUN startup with {process.returncode}\n"
                f"{process_logs(scratch)}"
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                return
        except Exception as error:  # noqa: BLE001 — surface last probe error
            last_error = str(error)
            time.sleep(0.1)
    raise TimeoutError(
        f"mixed-port {port} did not become ready: {last_error}\n{process_logs(scratch)}"
    )


def ifconfig_text() -> str:
    return run_cmd(["ifconfig"], check=False).stdout


def find_utun_name() -> str | None:
    current = None
    for line in ifconfig_text().splitlines():
        if line and not line.startswith("\t") and not line.startswith(" "):
            current = line.split(":", 1)[0]
        if current and current.startswith("utun") and "198.18.0.1" in line:
            return current
    return None


def wait_utun(process: subprocess.Popen[bytes], scratch: pathlib.Path) -> str:
    deadline = time.monotonic() + NATIVE_STARTUP_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"proxy exited before utun appeared: {process.returncode}\n"
                f"{process_logs(scratch)}"
            )
        name = find_utun_name()
        if name:
            return name
        time.sleep(0.05)
    raise TimeoutError(f"utun with {TUN_INET4} did not appear\n{process_logs(scratch)}")


def route_interface(host: str) -> str:
    result = run_cmd(["route", "-n", "get", "-inet", host], check=False)
    text = (result.stdout or "") + (result.stderr or "")
    for line in text.splitlines():
        if line.strip().startswith("interface:"):
            return line.split(":", 1)[1].strip()
    return ""


def scutil_show(key: str) -> str:
    result = subprocess.run(
        maybe_sudo(["scutil"]),
        input=f"show {key}\nquit\n",
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    return (result.stdout or "") + (result.stderr or "")


def primary_service_id() -> str:
    body = scutil_show("State:/Network/Global/IPv4")
    for line in body.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("PrimaryService"):
            return trimmed.split(":", 1)[1].strip()
    raise AssertionError(f"scutil Global/IPv4 has no PrimaryService:\n{body}")


def service_dns_text() -> str:
    service = primary_service_id()
    return scutil_show(f"State:/Network/Service/{service}/DNS")


def dns_points_at_tun() -> bool:
    return TUN_DNS in service_dns_text()


def flush_dns_cache() -> None:
    run_cmd(["dscacheutil", "-flushcache"], check=False)
    run_cmd(["killall", "-HUP", "mDNSResponder"], check=False)


def query_hijacked_dns(name: str) -> str:
    query = make_query(name, 1, 0x8B01)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(NATIVE_IO_DEADLINE)
    try:
        sock.sendto(query, (DNS_HIJACK_TARGET, 53))
        message, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    parsed = parse_response(message, 0x8B01)
    records = parsed.get("records") or []
    address = records[0]["data"] if records else ""
    if not str(address).startswith("198.19."):
        raise AssertionError(f"DNS hijack for {name} did not return fake-IP: {parsed}")
    return str(address)


def resolve_system(name: str) -> str:
    flush_dns_cache()
    query = name if name.endswith(".") else f"{name}."
    deadline = time.monotonic() + SYSTEM_DNS_DEADLINE
    last_error = "not attempted"
    while time.monotonic() < deadline:
        try:
            infos = socket.getaddrinfo(query, None, socket.AF_INET, socket.SOCK_STREAM)
            address = str(infos[0][4][0])
            if address.startswith("198.19."):
                return address
            last_error = f"got {address}"
        except Exception as error:  # noqa: BLE001 — retry until TUN DNS is visible
            last_error = str(error)
        time.sleep(0.1)
        flush_dns_cache()
    details = (
        f"{last_error}\nscutil DNS:\n{service_dns_text()}\n"
        f"route {TUN_DNS} via {route_interface(TUN_DNS)!r}\n"
        f"scutil --dns:\n{run_cmd(['scutil', '--dns'], check=False).stdout[:2000]}"
    )
    raise AssertionError(f"system resolver did not return fake-IP for {name}: {details}")


def http_get(host: str, port: int, path: str) -> bytes:
    timeout = 20.0 if path == "/large" else NATIVE_IO_DEADLINE
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {HTTP_NAME}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(request)
        chunks: list[bytes] = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    finally:
        sock.close()
    raw = b"".join(chunks)
    header, _, body = raw.partition(b"\r\n\r\n")
    status = header.split(b"\r\n", 1)[0]
    if b" 200 " not in status:
        raise AssertionError(f"HTTP failed: {header!r}")
    return body


def udp_echo(host: str, port: int, payload: bytes) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(NATIVE_IO_DEADLINE)
    try:
        sock.sendto(payload, (host, port))
        echoed, _ = sock.recvfrom(65536)
    finally:
        sock.close()
    return echoed


def install_manual_routes(utun: str) -> None:
    run_cmd(["route", "-n", "add", "-inet", "-net", FAKE_IP_ROUTE, "-interface", utun], check=False)
    run_cmd(
        ["route", "-n", "add", "-inet", "-host", DNS_HIJACK_TARGET, "-interface", utun],
        check=False,
    )
    run_cmd(
        ["route", "-n", "add", "-inet", "-host", TUN_DNS, "-interface", utun],
        check=False,
    )


def delete_manual_routes() -> None:
    run_cmd(["route", "-n", "delete", "-inet", "-net", FAKE_IP_ROUTE], check=False)
    run_cmd(["route", "-n", "delete", "-inet", "-host", DNS_HIJACK_TARGET], check=False)
    run_cmd(["route", "-n", "delete", "-inet", "-host", TUN_DNS], check=False)


def assert_auto_routes(utun: str, stack: str) -> None:
    iface = route_interface(DARWIN_AUTO_PROBE)
    if stack == "smoltcp":
        if iface != utun:
            raise AssertionError(
                f"auto-route probe {DARWIN_AUTO_PROBE} uses {iface!r}, expected {utun}"
            )
        return
    if not iface.startswith("utun"):
        raise AssertionError(f"Go auto-route probe uses {iface!r}, expected a utun")


def wait_cleanup(utun: str | None, *, dns_was_tun: bool) -> None:
    deadline = time.monotonic() + CLEANUP_DEADLINE
    last = ""
    while time.monotonic() < deadline:
        iface = route_interface(DARWIN_AUTO_PROBE)
        dns_text = service_dns_text()
        still_device = bool(utun) and utun in ifconfig_text() and "198.18.0.1" in ifconfig_text()
        tun_dns = TUN_DNS in dns_text
        if iface != utun and not still_device and not tun_dns:
            return
        last = f"iface={iface} device={still_device} dns={dns_text!r}"
        time.sleep(0.05)
    raise AssertionError(
        f"TUN leftovers after stop (dns_was_tun={dns_was_tun}): {last}"
    )


class LoAlias:
    def __init__(self, address: str) -> None:
        self.address = address
        self._owned = False

    def __enter__(self) -> LoAlias:
        already = self.address in run_cmd(["ifconfig", "lo0"], check=False).stdout
        if not already:
            run_cmd(
                [
                    "ifconfig",
                    "lo0",
                    "alias",
                    self.address,
                    "netmask",
                    "255.255.255.255",
                ]
            )
            self._owned = True
        return self

    def __exit__(self, *args: object) -> None:
        if self._owned:
            run_cmd(["ifconfig", "lo0", "-alias", self.address], check=False)
            self._owned = False


def run_closed_loop(
    binary: pathlib.Path,
    servers: FixtureServers,
    scratch: pathlib.Path,
    *,
    auto_route: bool,
    stack: str,
    large: bool,
    udp: bool,
    system_dns: bool,
    label: str,
    mixed_port: int,
    dns_listen: int,
) -> dict[str, Any]:
    case_dir = scratch / label
    case_dir.mkdir(parents=True, exist_ok=True)
    config = write_config(
        case_dir,
        "config.yaml",
        tun_config(
            mixed_port=mixed_port,
            dns_listen=dns_listen,
            nameserver=f"{SERVICE_IP}:{servers.dns_port}",
            device=None,
            auto_route=auto_route,
            stack=stack,
        ),
    )
    process, stdout, stderr = launch_process(binary, config, case_dir)
    observation: dict[str, Any] = {"label": label, "stack": stack, "auto_route": auto_route}
    utun = None
    try:
        wait_mixed(process, mixed_port, case_dir)
        utun = wait_utun(process, case_dir)
        observation["utun"] = utun
        if auto_route:
            assert_auto_routes(utun, stack)
        else:
            install_manual_routes(utun)
        if route_interface(SERVICE_IP) not in {"lo0", "lo"}:
            raise AssertionError(
                f"{SERVICE_IP} was not protected via lo0: {route_interface(SERVICE_IP)}"
            )
        if not dns_points_at_tun():
            raise AssertionError(f"scutil DNS was not rewritten to {TUN_DNS}:\n{service_dns_text()}")
        observation["scutil-dns"] = True
        fake_http = query_hijacked_dns(HTTP_NAME)
        if system_dns:
            system_http = resolve_system(HTTP_NAME)
            observation["system-dns-http"] = system_http
            fake_http = system_http
        body = http_get(fake_http, servers.http_port, "/small")
        if body != HTTP_SMALL:
            raise AssertionError(f"{label} small HTTP mismatch: {body!r}")
        observation["http-small"] = True
        observation["fake-ip-http"] = fake_http
        if large:
            large_body = http_get(fake_http, servers.http_port, "/large")
            if large_body != HTTP_LARGE:
                raise AssertionError(
                    f"{label} large HTTP length {len(large_body)} != {len(HTTP_LARGE)}"
                )
            observation["http-large"] = True
        if udp:
            fake_udp = resolve_system(UDP_NAME) if system_dns else query_hijacked_dns(UDP_NAME)
            echoed = udp_echo(fake_udp, servers.udp_port, UDP_PAYLOAD)
            if echoed != UDP_PAYLOAD:
                raise AssertionError(f"{label} UDP echo mismatch: {echoed!r}")
            observation["udp-echo"] = True
            observation["fake-ip-udp"] = fake_udp
        return observation
    except Exception:
        print(process_logs(case_dir), file=sys.stderr)
        raise
    finally:
        stdout.close()
        stderr.close()
        stop_process(process, case_dir)
        if not auto_route:
            delete_manual_routes()
        wait_cleanup(utun, dns_was_tun=True)
        observation["stop-cleanup"] = True


def run_invalid_device(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    case_dir = scratch / "invalid-device"
    case_dir.mkdir(parents=True, exist_ok=True)
    before_dns = service_dns_text()
    before_probe = route_interface(DARWIN_AUTO_PROBE)
    config = write_config(
        case_dir,
        "config.yaml",
        tun_config(
            mixed_port=17890,
            dns_listen=5353,
            nameserver=f"{SERVICE_IP}:53",
            device="tun0",
            auto_route=True,
            stack="smoltcp",
        ),
    )
    process, stdout, stderr = launch_process(binary, config, case_dir)
    try:
        deadline = time.monotonic() + NATIVE_STARTUP_DEADLINE
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        code = process.poll()
        logs = process_logs(case_dir)
        if code is None:
            stop_process(process, case_dir)
            raise AssertionError(f"invalid tun0 stayed up\n{logs}")
        if code == 0:
            raise AssertionError(f"invalid tun0 exited 0\n{logs}")
        if "does not remap" not in logs:
            raise AssertionError(f"invalid tun0 missing remap rejection:\n{logs}")
        if TUN_DNS in service_dns_text() and TUN_DNS not in before_dns:
            raise AssertionError(f"invalid tun0 leaked TUN DNS:\n{service_dns_text()}")
        after_probe = route_interface(DARWIN_AUTO_PROBE)
        if after_probe.startswith("utun") and after_probe != before_probe:
            raise AssertionError(f"invalid tun0 leaked auto-route via {after_probe}")
        return {
            "exited": True,
            "nonzero-exit": True,
            "remap-rejected": True,
            "no-leftover-dns": True,
            "no-leftover-routes": True,
        }
    finally:
        stdout.close()
        stderr.close()
        if process.poll() is None:
            stop_process(process, case_dir)


def native_gate(binaries: dict[str, pathlib.Path], scratch: pathlib.Path) -> dict[str, Any]:
    if os.environ.get("PHASE8B_NATIVE") != "1":
        print(
            "native Darwin traffic gate not requested "
            "(set PHASE8B_NATIVE=1 on a privileged Darwin arm64 runner)"
        )
        return {"requested": False}
    require_native_prereqs()
    observations: dict[str, Any] = {"requested": True}
    with LoAlias(SERVICE_IP):
        with FixtureServers(SERVICE_IP) as servers:
            observations["rust-manual"] = run_closed_loop(
                binaries["rust"],
                servers,
                scratch,
                auto_route=False,
                stack="smoltcp",
                large=False,
                udp=False,
                system_dns=True,
                label="rust-manual",
                mixed_port=17890,
                dns_listen=15353,
            )
            observations["rust-auto"] = run_closed_loop(
                binaries["rust"],
                servers,
                scratch,
                auto_route=True,
                stack="smoltcp",
                large=True,
                udp=True,
                system_dns=True,
                label="rust-auto",
                mixed_port=17891,
                dns_listen=15354,
            )
            observations["go-auto"] = run_closed_loop(
                binaries["go"],
                servers,
                scratch,
                auto_route=True,
                stack="system",
                large=True,
                udp=True,
                system_dns=True,
                label="go-auto",
                mixed_port=17892,
                dns_listen=15355,
            )
            if not observations["rust-auto"].get("fake-ip-http") or not observations["go-auto"].get(
                "fake-ip-http"
            ):
                raise AssertionError("Go/Rust fake-IP HTTP addresses missing")
            observations["go-rust-http-body-match"] = True
            observations["go-rust-fake-ip-not-compared"] = True
    observations["rust-invalid-device"] = run_invalid_device(binaries["rust"], scratch)
    return observations


def main() -> int:
    assert_go_oracle_baseline()
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phase8b-tun-") as scratch_dir:
        scratch = pathlib.Path(scratch_dir)
        binaries = build_binaries(
            scratch,
            cargo_target_variable="PHASE8B_CARGO_TARGET",
            default_target_name="phase8b",
            stage_runtime=True,
        )
        observations: dict[str, Any] = {
            "identity": config_identity(binaries, scratch),
            "device-names": device_name_identity(binaries, scratch),
        }
        native = native_gate(binaries, scratch)
        observations["native"] = native
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, default=str) + "\n")
        print("phase8b observations:")
        print(json.dumps(observations, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

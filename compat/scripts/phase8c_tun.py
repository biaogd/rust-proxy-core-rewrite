#!/usr/bin/env python3
"""Phase 8C TUN config-identity and native Windows x86_64 Wintun gate.

Unprivileged: same stack identity as 8A (`smoltcp` only; Go stacks rejected
without remap). Device names are free-form at parse time; runtime refuses to
take over an adapter that already exists.

Native traffic (YAML → Wintun → netstack-smoltcp → DIRECT, plus adapter DNS)
requires Windows x86_64 with Administrator. Set PHASE8C_NATIVE=1; missing
capability or missing wintun.dll fails closed instead of skipping green.

Wintun is not vendored. The native gate downloads the official 0.14.1 zip,
verifies SHA-256, and stages `wintun/bin/amd64/wintun.dll` next to the
binaries. `delete_driver` stays false so other Wintun/WireGuard VPNs remain.
DNS is set on this adapter only; other NIC DNS must stay unchanged.
"""

from __future__ import annotations

import hashlib
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
import urllib.request
import zipfile
from typing import Any

from phase1 import ROOT, assert_go_oracle_baseline, request_graceful_shutdown, terminate_process
from phase3 import launch as launch_process
from phase5b1a import build_binaries
from phase8a_tun import (
    DNS_HIJACK_TARGET,
    FAKE_IP_RANGE,
    FAKE_IP_ROUTE,
    FixtureServers,
    HTTP_LARGE,
    HTTP_NAME,
    HTTP_SMALL,
    MINIMAL,
    NATIVE_IO_DEADLINE,
    SERVICE_IP,
    TUN_INET4,
    UDP_NAME,
    UDP_PAYLOAD,
    config_identity,
    expect_accept,
    make_query,
    parse_response,
    process_logs,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase8c-tun-diff.json"
CLEANUP_DEADLINE = 12.0
NATIVE_STARTUP_DEADLINE = 40.0
TUN_DNS = "198.18.0.2"
WINDOWS_AUTO_PROBE = "1.1.1.1"
LOOPBACK = "Loopback Pseudo-Interface 1"
EXISTING_ADAPTER = LOOPBACK
WINTUN_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
WINTUN_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
WINTUN_ZIP_MEMBER = "wintun/bin/amd64/wintun.dll"


def unique_device(prefix: str) -> str:
    return f"{prefix}{os.getpid() % 100000:05d}"


def run_cmd(
    command: list[str], *, check: bool = True, timeout: float = 20
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
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


def is_windows_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 — admin probe must not skip the native gate
        return False


def native_prereq_error() -> str | None:
    if os.name != "nt" and sys.platform != "win32":
        return "PHASE8C_NATIVE requires Windows"
    machine = platform.machine().lower()
    if machine not in {"amd64", "x86_64"}:
        return "PHASE8C_NATIVE requires Windows x86_64; refusing to skip green"
    runner_arch = os.environ.get("RUNNER_ARCH", "").upper()
    if runner_arch and runner_arch != "X64":
        return "PHASE8C_NATIVE requires Windows X64 runner; refusing to skip green"
    for binary in ("netsh", "powershell"):
        if shutil.which(binary) is None:
            return f"PHASE8C_NATIVE requires {binary}; refusing to skip green"
    if not is_windows_admin():
        return "PHASE8C_NATIVE requires Administrator; refusing to skip green"
    return None


def require_native_prereqs() -> None:
    error = native_prereq_error()
    if error:
        raise SystemExit(error)


def device_name_identity(binaries: dict[str, pathlib.Path], scratch: pathlib.Path) -> dict[str, Any]:
    rust = binaries["rust"]
    expect_accept(
        rust,
        MINIMAL + "\ntun:\n  enable: true\n  stack: smoltcp\n  device: p8cparse\n",
        scratch,
        "named Windows device parse",
    )
    expect_accept(
        rust,
        MINIMAL + "\ntun:\n  enable: true\n  stack: smoltcp\n",
        scratch,
        "empty device parse",
    )
    return {
        "rust-accepts-named-device": True,
        "rust-accepts-empty-device": True,
    }


def tun_config(
    *,
    mixed_port: int,
    dns_listen: int,
    nameserver: str,
    device: str,
    auto_route: bool,
    stack: str,
) -> str:
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
    - 'never-match.phase8c.test'
  nameserver:
    - udp://{nameserver}
tun:
  enable: true
  device: {device}
  stack: {stack}
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
    path.write_text(source, encoding="utf-8")
    return path


def launch_proxy(
    binary: pathlib.Path,
    config: pathlib.Path,
    scratch: pathlib.Path,
    *,
    wintun: pathlib.Path | None,
) -> tuple[subprocess.Popen[bytes], Any, Any]:
    saved = os.environ.pop("MIHOMO_WINTUN", None)
    extra = {"USERPROFILE": str(scratch)}
    if wintun is not None:
        extra["MIHOMO_WINTUN"] = str(wintun)
    try:
        return launch_process(binary, config, scratch, extra_env=extra)
    finally:
        if saved is not None:
            os.environ["MIHOMO_WINTUN"] = saved
        elif wintun is None:
            os.environ.pop("MIHOMO_WINTUN", None)


def stop_process(process: subprocess.Popen[bytes], scratch: pathlib.Path | None = None) -> int:
    try:
        if os.name == "nt" and process.poll() is None:
            request_graceful_shutdown(process)
            try:
                return process.wait(timeout=CLEANUP_DEADLINE)
            except subprocess.TimeoutExpired:
                process.kill()
                return process.wait(timeout=NATIVE_IO_DEADLINE)
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


def interface_names() -> list[str]:
    text = run_cmd(["netsh", "interface", "show", "interface"], check=False).stdout
    names: list[str] = []
    for line in text.splitlines():
        for kind in ("Dedicated", "Internal", "Loopback", "Unbound"):
            if kind in line:
                _, rest = line.split(kind, 1)
                name = rest.strip()
                if name and name != "Interface Name":
                    names.append(name)
                break
    return names


def interface_exists(name: str) -> bool:
    return any(existing.casefold() == name.casefold() for existing in interface_names())


def interface_addresses(name: str) -> str:
    return run_cmd(
        ["netsh", "interface", "ipv4", "show", "addresses", f"name={name}"],
        check=False,
    ).stdout


def wait_tun(process: subprocess.Popen[bytes], scratch: pathlib.Path, name: str) -> None:
    deadline = time.monotonic() + NATIVE_STARTUP_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"proxy exited before Wintun `{name}` appeared: {process.returncode}\n"
                f"{process_logs(scratch)}"
            )
        if interface_exists(name) and "198.18.0.1" in interface_addresses(name):
            return
        time.sleep(0.1)
    raise TimeoutError(
        f"Wintun `{name}` with {TUN_INET4} did not appear\n{process_logs(scratch)}"
    )


def route_interface(host: str) -> str:
    script = (
        f"$rows = @(Find-NetRoute -RemoteIPAddress '{host}' -ErrorAction SilentlyContinue); "
        "$row = $rows | Where-Object { $_.InterfaceAlias } | Select-Object -First 1; "
        "if (-not $row) { $row = $rows | Select-Object -First 1 }; "
        "if ($row) { $row.InterfaceAlias }"
    )
    result = run_cmd(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
    )
    return (result.stdout or "").strip().splitlines()[-1].strip() if result.stdout.strip() else ""


def show_routes() -> str:
    return run_cmd(["netsh", "interface", "ipv4", "show", "route"], check=False).stdout


def split_defaults_on(device: str) -> bool:
    text = show_routes().lower()
    name = device.lower()
    return name in text and ("0.0.0.0/1" in text or "128.0.0.0/1" in text)


def dnsservers_text() -> str:
    return run_cmd(["netsh", "interface", "ipv4", "show", "dnsservers"], check=False).stdout


def parse_dnsservers(stdout: str) -> dict[str, str]:
    current = None
    blocks: dict[str, list[str]] = {}
    for line in stdout.splitlines():
        marker = "Configuration for interface "
        stripped = line.strip()
        if stripped.startswith(marker):
            current = stripped[len(marker) :].strip().strip("\"'")
            blocks[current] = []
            continue
        if current is not None:
            blocks[current].append(line)
    parsed: dict[str, str] = {}
    for name, lines in blocks.items():
        parsed[name] = "\n".join(lines)
    return parsed


def other_adapter_dns(snapshot: dict[str, str], tun: str) -> dict[str, str]:
    return {name: body for name, body in snapshot.items() if name.casefold() != tun.casefold()}


def tun_dns_is_set(snapshot: dict[str, str], tun: str) -> bool:
    for name, body in snapshot.items():
        if name.casefold() == tun.casefold() and TUN_DNS in body:
            return True
    return False


def query_hijacked_dns(name: str) -> str:
    query = make_query(name, 1, 0x8C01)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(NATIVE_IO_DEADLINE)
    try:
        sock.sendto(query, (DNS_HIJACK_TARGET, 53))
        message, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    parsed = parse_response(message, 0x8C01)
    records = parsed.get("records") or []
    address = records[0]["data"] if records else ""
    if not str(address).startswith("198.19."):
        raise AssertionError(f"DNS hijack for {name} did not return fake-IP: {parsed}")
    return str(address)


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


def install_manual_routes(device: str) -> None:
    for prefix in (FAKE_IP_ROUTE, f"{DNS_HIJACK_TARGET}/32"):
        run_cmd(
            [
                "netsh",
                "interface",
                "ipv4",
                "add",
                "route",
                f"prefix={prefix}",
                f"interface={device}",
                "store=active",
            ],
            check=False,
        )


def delete_manual_routes(device: str) -> None:
    for prefix in (FAKE_IP_ROUTE, f"{DNS_HIJACK_TARGET}/32"):
        run_cmd(
            [
                "netsh",
                "interface",
                "ipv4",
                "delete",
                "route",
                f"prefix={prefix}",
                f"interface={device}",
            ],
            check=False,
        )


def assert_auto_routes(device: str) -> None:
    iface = route_interface(WINDOWS_AUTO_PROBE)
    if iface.casefold() != device.casefold():
        raise AssertionError(
            f"auto-route probe {WINDOWS_AUTO_PROBE} uses {iface!r}, expected {device}"
        )
    if not split_defaults_on(device):
        raise AssertionError(f"split default 0.0.0.0/1+128.0.0.0/1 missing on {device}")


def wait_cleanup(
    device: str,
    *,
    before_other_dns: dict[str, str],
) -> None:
    deadline = time.monotonic() + CLEANUP_DEADLINE
    last = ""
    while time.monotonic() < deadline:
        still = interface_exists(device) and "198.18.0.1" in interface_addresses(device)
        routes = split_defaults_on(device)
        dns_now = parse_dnsservers(dnsservers_text())
        other_now = other_adapter_dns(dns_now, device)
        tun_dns = tun_dns_is_set(dns_now, device) if still else False
        if not still and not routes and not tun_dns and other_now == before_other_dns:
            return
        last = (
            f"device={still} split={routes} tun_dns={tun_dns} "
            f"other_dns_changed={other_now != before_other_dns}"
        )
        time.sleep(0.1)
    raise AssertionError(f"TUN leftovers after stop: {last}")


class LoopbackAlias:
    def __init__(self, address: str) -> None:
        self.address = address
        self._owned = False

    def __enter__(self) -> LoopbackAlias:
        text = interface_addresses(LOOPBACK)
        if self.address not in text:
            run_cmd(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "add",
                    "address",
                    f"name={LOOPBACK}",
                    f"addr={self.address}",
                    "mask=255.255.255.255",
                ]
            )
            self._owned = True
        return self

    def __exit__(self, *args: object) -> None:
        if self._owned:
            run_cmd(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "delete",
                    "address",
                    f"name={LOOPBACK}",
                    f"addr={self.address}",
                ],
                check=False,
            )
            self._owned = False


def download_wintun(scratch: pathlib.Path) -> pathlib.Path:
    archive = scratch / "wintun-0.14.1.zip"
    try:
        with urllib.request.urlopen(WINTUN_URL, timeout=60) as response:
            archive.write_bytes(response.read())
    except Exception as error:  # noqa: BLE001 — fail closed, never skip
        raise SystemExit(
            f"PHASE8C_NATIVE failed to download Wintun 0.14.1; refusing to skip: {error}"
        ) from error
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != WINTUN_SHA256:
        raise SystemExit(
            f"PHASE8C_NATIVE Wintun zip SHA-256 mismatch: {digest} != {WINTUN_SHA256}; "
            "refusing to skip"
        )
    extracted = scratch / "wintun.dll"
    with zipfile.ZipFile(archive) as zipped:
        try:
            extracted.write_bytes(zipped.read(WINTUN_ZIP_MEMBER))
        except KeyError as error:
            raise SystemExit(
                f"PHASE8C_NATIVE zip missing {WINTUN_ZIP_MEMBER}; refusing to skip"
            ) from error
    return extracted


def stage_wintun(dll: pathlib.Path, binaries: dict[str, pathlib.Path]) -> pathlib.Path:
    staged: pathlib.Path | None = None
    for binary in binaries.values():
        target = binary.parent / "wintun.dll"
        shutil.copy2(dll, target)
        if binary == binaries["rust"]:
            staged = target
    assert staged is not None
    os.environ["MIHOMO_WINTUN"] = str(staged)
    return staged


def run_closed_loop(
    binary: pathlib.Path,
    servers: FixtureServers,
    scratch: pathlib.Path,
    *,
    device: str,
    auto_route: bool,
    stack: str,
    large: bool,
    udp: bool,
    label: str,
    mixed_port: int,
    dns_listen: int,
    wintun: pathlib.Path,
) -> dict[str, Any]:
    case_dir = scratch / label
    case_dir.mkdir(parents=True, exist_ok=True)
    before_dns = parse_dnsservers(dnsservers_text())
    before_other = other_adapter_dns(before_dns, device)
    config = write_config(
        case_dir,
        "config.yaml",
        tun_config(
            mixed_port=mixed_port,
            dns_listen=dns_listen,
            nameserver=f"{SERVICE_IP}:{servers.dns_port}",
            device=device,
            auto_route=auto_route,
            stack=stack,
        ),
    )
    process, stdout, stderr = launch_proxy(binary, config, case_dir, wintun=wintun)
    observation: dict[str, Any] = {
        "label": label,
        "stack": stack,
        "auto_route": auto_route,
        "device": device,
    }
    try:
        wait_mixed(process, mixed_port, case_dir)
        wait_tun(process, case_dir, device)
        if auto_route:
            assert_auto_routes(device)
        else:
            install_manual_routes(device)
        loopback_iface = route_interface(SERVICE_IP)
        if LOOPBACK.casefold() not in loopback_iface.casefold() and loopback_iface.lower() not in {
            "loopback",
            "lo",
        }:
            raise AssertionError(f"{SERVICE_IP} was not protected via loopback: {loopback_iface!r}")
        during_dns = parse_dnsservers(dnsservers_text())
        if not tun_dns_is_set(during_dns, device):
            raise AssertionError(
                f"TUN adapter `{device}` DNS was not set to {TUN_DNS}:\n{dnsservers_text()}"
            )
        during_other = other_adapter_dns(during_dns, device)
        if during_other != before_other:
            raise AssertionError(
                f"other adapter DNS changed while TUN ran:\nbefore={before_other}\n"
                f"during={during_other}"
            )
        observation["adapter-dns-only"] = True
        fake_http = query_hijacked_dns(HTTP_NAME)
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
            fake_udp = query_hijacked_dns(UDP_NAME)
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
            delete_manual_routes(device)
        wait_cleanup(device, before_other_dns=before_other)
        observation["stop-cleanup"] = True


def run_missing_wintun(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    case_dir = scratch / "missing-wintun"
    isolated = case_dir / "isolated"
    isolated.mkdir(parents=True, exist_ok=True)
    isolated_binary = isolated / binary.name
    shutil.copy2(binary, isolated_binary)
    before_dns = parse_dnsservers(dnsservers_text())
    before_probe = route_interface(WINDOWS_AUTO_PROBE)
    device = unique_device("p8cm")
    config = write_config(
        case_dir,
        "config.yaml",
        tun_config(
            mixed_port=17890,
            dns_listen=5353,
            nameserver=f"{SERVICE_IP}:53",
            device=device,
            auto_route=True,
            stack="smoltcp",
        ),
    )
    process, stdout, stderr = launch_proxy(isolated_binary, config, case_dir, wintun=None)
    try:
        deadline = time.monotonic() + NATIVE_STARTUP_DEADLINE
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        code = process.poll()
        logs = process_logs(case_dir)
        if code is None:
            stop_process(process, case_dir)
            raise AssertionError(f"missing wintun.dll stayed up\n{logs}")
        if code == 0:
            raise AssertionError(f"missing wintun.dll exited 0\n{logs}")
        combined = logs.lower()
        if "wintun.dll not found" not in combined and "refusing to skip" not in combined:
            raise AssertionError(f"missing wintun.dll missing fail-closed text:\n{logs}")
        if interface_exists(device):
            raise AssertionError(f"missing wintun.dll leaked adapter {device}")
        after_probe = route_interface(WINDOWS_AUTO_PROBE)
        if after_probe != before_probe and split_defaults_on(device):
            raise AssertionError(f"missing wintun.dll leaked auto-route via {after_probe}")
        after_other = other_adapter_dns(parse_dnsservers(dnsservers_text()), device)
        if after_other != other_adapter_dns(before_dns, device):
            raise AssertionError("missing wintun.dll changed other adapter DNS")
        return {
            "exited": True,
            "nonzero-exit": True,
            "missing-dll-rejected": True,
            "no-leftover-adapter": True,
            "no-leftover-dns": True,
            "no-leftover-routes": True,
        }
    finally:
        stdout.close()
        stderr.close()
        if process.poll() is None:
            stop_process(process, case_dir)


def run_existing_adapter(binary: pathlib.Path, scratch: pathlib.Path, wintun: pathlib.Path) -> dict[str, Any]:
    case_dir = scratch / "existing-adapter"
    case_dir.mkdir(parents=True, exist_ok=True)
    before_dns = parse_dnsservers(dnsservers_text())
    before_probe = route_interface(WINDOWS_AUTO_PROBE)
    config = write_config(
        case_dir,
        "config.yaml",
        tun_config(
            mixed_port=17893,
            dns_listen=15356,
            nameserver=f"{SERVICE_IP}:53",
            device=EXISTING_ADAPTER,
            auto_route=True,
            stack="smoltcp",
        ),
    )
    process, stdout, stderr = launch_proxy(binary, config, case_dir, wintun=wintun)
    try:
        deadline = time.monotonic() + NATIVE_STARTUP_DEADLINE
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        code = process.poll()
        logs = process_logs(case_dir)
        if code is None:
            stop_process(process, case_dir)
            raise AssertionError(f"existing adapter stayed up\n{logs}")
        if code == 0:
            raise AssertionError(f"existing adapter exited 0\n{logs}")
        if "already exists" not in logs or "refusing to take over" not in logs:
            raise AssertionError(f"existing adapter missing takeover rejection:\n{logs}")
        after_probe = route_interface(WINDOWS_AUTO_PROBE)
        if after_probe != before_probe and split_defaults_on(EXISTING_ADAPTER):
            raise AssertionError(f"existing adapter leaked auto-route via {after_probe}")
        after_other = other_adapter_dns(parse_dnsservers(dnsservers_text()), EXISTING_ADAPTER)
        if after_other != other_adapter_dns(before_dns, EXISTING_ADAPTER):
            raise AssertionError("existing adapter path rewrote other NIC DNS")
        return {
            "exited": True,
            "nonzero-exit": True,
            "takeover-rejected": True,
            "no-leftover-dns": True,
            "no-leftover-routes": True,
        }
    finally:
        stdout.close()
        stderr.close()
        if process.poll() is None:
            stop_process(process, case_dir)


def native_gate(binaries: dict[str, pathlib.Path], scratch: pathlib.Path) -> dict[str, Any]:
    if os.environ.get("PHASE8C_NATIVE") != "1":
        print(
            "native Windows traffic gate not requested "
            "(set PHASE8C_NATIVE=1 on a privileged Windows x86_64 runner)"
        )
        return {"requested": False}
    require_native_prereqs()
    observations: dict[str, Any] = {"requested": True}
    dll = download_wintun(scratch)
    wintun = stage_wintun(dll, binaries)
    observations["wintun-sha256"] = WINTUN_SHA256
    rust_manual = unique_device("p8cm")
    rust_auto = unique_device("p8cr")
    go_device = unique_device("p8cg")
    with LoopbackAlias(SERVICE_IP):
        with FixtureServers(SERVICE_IP) as servers:
            observations["rust-manual"] = run_closed_loop(
                binaries["rust"],
                servers,
                scratch,
                device=rust_manual,
                auto_route=False,
                stack="smoltcp",
                large=False,
                udp=False,
                label="rust-manual",
                mixed_port=17890,
                dns_listen=15353,
                wintun=wintun,
            )
            observations["rust-auto"] = run_closed_loop(
                binaries["rust"],
                servers,
                scratch,
                device=rust_auto,
                auto_route=True,
                stack="smoltcp",
                large=True,
                udp=True,
                label="rust-auto",
                mixed_port=17891,
                dns_listen=15354,
                wintun=wintun,
            )
            observations["go-auto"] = run_closed_loop(
                binaries["go"],
                servers,
                scratch,
                device=go_device,
                auto_route=True,
                stack="system",
                large=True,
                udp=True,
                label="go-auto",
                mixed_port=17892,
                dns_listen=15355,
                wintun=wintun,
            )
            if not observations["rust-auto"].get("fake-ip-http") or not observations["go-auto"].get(
                "fake-ip-http"
            ):
                raise AssertionError("Go/Rust fake-IP HTTP addresses missing")
            observations["go-rust-http-body-match"] = True
            observations["go-rust-fake-ip-not-compared"] = True
    observations["rust-missing-wintun"] = run_missing_wintun(binaries["rust"], scratch)
    observations["rust-existing-adapter"] = run_existing_adapter(binaries["rust"], scratch, wintun)
    return observations


def main() -> int:
    assert_go_oracle_baseline()
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phase8c-tun-") as scratch_dir:
        scratch = pathlib.Path(scratch_dir)
        binaries = build_binaries(
            scratch,
            cargo_target_variable="PHASE8C_CARGO_TARGET",
            default_target_name="phase8c",
            stage_runtime=True,
        )
        observations: dict[str, Any] = {
            "identity": config_identity(binaries, scratch),
            "device-names": device_name_identity(binaries, scratch),
        }
        native = native_gate(binaries, scratch)
        observations["native"] = native
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, default=str) + "\n")
        print("phase8c observations:")
        print(json.dumps(observations, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

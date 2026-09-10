#!/usr/bin/env python3
"""Phase 8A TUN config-identity and native Linux netns gate.

Unprivileged: Rust `-t` accepts `stack: smoltcp` and rejects Go stack names
without remapping. The Go oracle still accepts `system`/`gvisor`/`mixed`.

Native traffic (YAML → tun-rs → netstack-smoltcp → DIRECT) requires a
privileged Linux runner. Set PHASE8A_NATIVE=1; missing capability fails
closed instead of skipping green.
"""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from phase1 import ROOT, assert_go_oracle_baseline, terminate_process
from phase4b import make_query, parse_query, parse_response
from phase5b1a import build_binaries


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase8a-tun-diff.json"
SCRIPT = pathlib.Path(__file__).resolve()
NATIVE_STARTUP_DEADLINE = 30.0
NATIVE_IO_DEADLINE = 8.0
CLEANUP_DEADLINE = 8.0
HTTP_SMALL = b"phase8a-tun-http\n"
HTTP_LARGE = b"0123456789abcdef" * 8192  # 128 KiB
UDP_PAYLOAD = b"phase8a-udp-echo"
HTTP_NAME = "http.phase8a.test"
UDP_NAME = "udp.phase8a.test"
FAKE_IP_RANGE = "198.19.0.1/16"
FAKE_IP_ROUTE = "198.19.0.0/16"
TUN_INET4 = "198.18.0.1/30"
DNS_HIJACK_TARGET = "8.8.8.8"
VETH_HOST_IP = "10.66.8.1"
VETH_NS_IP = "10.66.8.2"
SERVICE_IP = "192.0.2.1"

MINIMAL = """
mixed-port: 17890
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""


def ip_bin() -> str:
    found = shutil.which("ip")
    if found:
        return found
    for candidate in ("/usr/sbin/ip", "/sbin/ip"):
        if os.path.exists(candidate):
            return candidate
    return "ip"


def maybe_sudo(command: list[str]) -> list[str]:
    if os.geteuid() == 0:
        return command
    return ["sudo", "-n", "--", *command]


def run_ip(*args: str, ns: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    command = [ip_bin()]
    if ns is not None:
        command += ["-n", ns]
    command += list(args)
    result = subprocess.run(
        maybe_sudo(command),
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"ip {' '.join(args)} failed (ns={ns}): rc={result.returncode}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result


def run_in_ns(
    ns: str,
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float = 30,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    command = maybe_sudo([ip_bin(), "netns", "exec", ns, *argv])
    merged = dict(os.environ)
    if env:
        merged.update(env)
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=check,
        timeout=timeout,
        env=merged,
    )


def run_test_config(binary: pathlib.Path, source: str, scratch: pathlib.Path) -> subprocess.CompletedProcess[str]:
    config = scratch / "config.yaml"
    config.write_text(source)
    return subprocess.run(
        [str(binary), "-t", "-f", str(config)],
        cwd=scratch,
        text=True,
        capture_output=True,
        timeout=30,
        env={**os.environ, "HOME": str(scratch)},
        check=False,
    )


def expect_accept(binary: pathlib.Path, source: str, scratch: pathlib.Path, label: str) -> None:
    result = run_test_config(binary, source, scratch)
    if result.returncode != 0:
        raise AssertionError(
            f"{binary.name} rejected {label}: rc={result.returncode}\n"
            f"{result.stdout}\n{result.stderr}"
        )


def expect_reject(
    binary: pathlib.Path,
    source: str,
    scratch: pathlib.Path,
    label: str,
    needle: str,
) -> None:
    result = run_test_config(binary, source, scratch)
    text = result.stdout + result.stderr
    if result.returncode == 0:
        raise AssertionError(f"{binary.name} accepted {label}")
    if needle not in text:
        raise AssertionError(f"{binary.name} {label} missing `{needle}`:\n{text}")


def config_identity(binaries: dict[str, pathlib.Path], scratch: pathlib.Path) -> dict[str, Any]:
    smoltcp = MINIMAL + "\ntun:\n  enable: true\n  stack: smoltcp\n"
    expect_accept(binaries["rust"], smoltcp, scratch, "smoltcp")
    defaulted = MINIMAL + "\ntun:\n  enable: true\n"
    expect_accept(binaries["rust"], defaulted, scratch, "default smoltcp")

    for stack in ("system", "gvisor", "mixed", "System", "gVisor", "Mixed"):
        source = MINIMAL + f"\ntun:\n  enable: true\n  stack: {stack}\n"
        expect_reject(
            binaries["rust"],
            source,
            scratch,
            f"rust {stack}",
            "does not remap",
        )
        expect_accept(binaries["go"], source, scratch, f"go {stack}")

    return {
        "rust-smoltcp": True,
        "rust-rejects-go-stacks": True,
        "go-accepts-go-stacks": True,
    }


def native_prereq_error() -> str | None:
    if sys.platform != "linux":
        return "PHASE8A_NATIVE requires Linux"
    if not os.path.exists("/dev/net/tun"):
        return "PHASE8A_NATIVE requires /dev/net/tun; refusing to skip green"
    if shutil.which("ip") is None and not os.path.exists("/usr/sbin/ip"):
        return "PHASE8A_NATIVE requires iproute2; refusing to skip green"
    if os.geteuid() == 0:
        return None
    probe = subprocess.run(
        ["sudo", "-n", "--", ip_bin(), "-V"],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if probe.returncode != 0:
        return (
            "PHASE8A_NATIVE requires root/CAP_NET_ADMIN (passwordless sudo); "
            "refusing to skip green"
        )
    return None


def require_native_prereqs() -> None:
    error = native_prereq_error()
    if error:
        raise SystemExit(error)


class DnsAuthority(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class DnsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, sock = self.request
        try:
            name, record_type, question_end = parse_query(query)
        except (ValueError, IndexError, OSError):
            return
        answers = b""
        count = 0
        ipv4 = getattr(self.server, "ipv4", SERVICE_IP)
        if record_type == 1:
            answers = (
                b"\xc0\x0c\x00\x01\x00\x01"
                + (30).to_bytes(4, "big")
                + b"\x00\x04"
                + socket.inet_aton(ipv4)
            )
            count = 1
        sock.sendto(
            query[:2]
            + b"\x81\x80\x00\x01"
            + count.to_bytes(2, "big")
            + b"\x00\x00\x00\x00"
            + query[12:question_end]
            + answers,
            self.client_address,
        )
        names: list[str] = getattr(self.server, "names", [])
        names.append(name)
        self.server.names = names  # type: ignore[attr-defined]


class HttpHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        if self.path == "/small":
            body = HTTP_SMALL
        elif self.path == "/large":
            body = HTTP_LARGE
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class UdpEcho(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        payload, sock = self.request
        sock.sendto(payload, self.client_address)


class FixtureServers:
    def __init__(self, bind: str) -> None:
        self.bind = bind
        self.http: http.server.ThreadingHTTPServer | None = None
        self.dns: DnsAuthority | None = None
        self.udp: UdpEcho | None = None
        self.threads: list[threading.Thread] = []
        self.http_port = 0
        self.dns_port = 0
        self.udp_port = 0

    def __enter__(self) -> FixtureServers:
        self.http = http.server.ThreadingHTTPServer((self.bind, 0), HttpHandler)
        self.http_port = int(self.http.server_address[1])
        http_thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        http_thread.start()
        self.threads.append(http_thread)

        self.dns = DnsAuthority((self.bind, 0), DnsHandler)
        self.dns.ipv4 = self.bind  # type: ignore[attr-defined]
        self.dns.names = []  # type: ignore[attr-defined]
        self.dns_port = int(self.dns.server_address[1])
        dns_thread = threading.Thread(target=self.dns.serve_forever, daemon=True)
        dns_thread.start()
        self.threads.append(dns_thread)

        self.udp = UdpEcho((self.bind, 0), UdpEchoHandler)
        self.udp_port = int(self.udp.server_address[1])
        udp_thread = threading.Thread(target=self.udp.serve_forever, daemon=True)
        udp_thread.start()
        self.threads.append(udp_thread)
        return self

    def __exit__(self, *args: object) -> None:
        for server in (self.http, self.dns, self.udp):
            if server is not None:
                server.shutdown()
                server.server_close()


class Netns:
    def __init__(self) -> None:
        token = f"{os.getpid() % 100000:05d}"
        self.name = f"p8a{token}"
        self.veth_host = f"p8h{token}"
        self.veth_ns = f"p8n{token}"
        self.tun = f"p8t{token}"
        self._owned = False

    def __enter__(self) -> Netns:
        run_ip("netns", "delete", self.name, check=False)
        run_ip("link", "delete", self.veth_host, check=False)
        run_ip("netns", "add", self.name)
        self._owned = True
        run_ip("link", "add", self.veth_host, "type", "veth", "peer", "name", self.veth_ns)
        run_ip("link", "set", self.veth_ns, "netns", self.name)
        run_ip("addr", "add", f"{VETH_HOST_IP}/24", "dev", self.veth_host)
        run_ip("addr", "add", f"{SERVICE_IP}/32", "dev", self.veth_host)
        run_ip("link", "set", self.veth_host, "up")
        run_ip("link", "set", "lo", "up", ns=self.name)
        run_ip("addr", "add", f"{VETH_NS_IP}/24", "dev", self.veth_ns, ns=self.name)
        run_ip("link", "set", self.veth_ns, "up", ns=self.name)
        run_ip("route", "replace", "default", "via", VETH_HOST_IP, "dev", self.veth_ns, ns=self.name)
        run_ip("route", "replace", f"{SERVICE_IP}/32", "via", VETH_HOST_IP, ns=self.name)
        for key in (
            "net.ipv4.conf.all.rp_filter=0",
            "net.ipv4.conf.default.rp_filter=0",
        ):
            run_in_ns(self.name, ["sysctl", "-w", key], check=False)
        return self

    def __exit__(self, *args: object) -> None:
        if not self._owned:
            return
        run_ip("netns", "delete", self.name, check=False)
        run_ip("link", "delete", self.veth_host, check=False)
        self._owned = False

    def routes(self) -> str:
        result = run_ip("route", "show", ns=self.name, check=False)
        return (result.stdout or "") + (result.stderr or "")

    def links(self) -> str:
        result = run_ip("link", "show", ns=self.name, check=False)
        return (result.stdout or "") + (result.stderr or "")

    def has_device(self, name: str) -> bool:
        return name in self.links()

    def has_tun_routes(self, tun: str) -> bool:
        text = self.routes()
        return tun in text or "0.0.0.0/1" in text or "128.0.0.0/1" in text


class IsolatedNetns:
    """Netns with loopback only — used to prove auto-route init failure rollback."""

    def __init__(self) -> None:
        token = f"{(os.getpid() + 1) % 100000:05d}"
        self.name = f"p8f{token}"
        self.tun = f"p8x{token}"
        self._owned = False

    def __enter__(self) -> IsolatedNetns:
        run_ip("netns", "delete", self.name, check=False)
        run_ip("netns", "add", self.name)
        self._owned = True
        run_ip("link", "set", "lo", "up", ns=self.name)
        return self

    def __exit__(self, *args: object) -> None:
        if self._owned:
            run_ip("netns", "delete", self.name, check=False)
            self._owned = False

    def leftover(self) -> str:
        routes = run_ip("route", "show", ns=self.name, check=False).stdout
        links = run_ip("link", "show", ns=self.name, check=False).stdout
        return f"{routes}\n{links}"


def tun_config(
    *,
    mixed_port: int,
    dns_listen: int,
    nameserver: str,
    device: str,
    auto_route: bool,
    stack: str,
    enable: bool = True,
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
    - 'never-match.phase8a.test'
  nameserver:
    - udp://{nameserver}
tun:
  enable: {str(enable).lower()}
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
    path.write_text(source)
    return path


def launch_in_ns(
    ns: str,
    binary: pathlib.Path,
    config: pathlib.Path,
    scratch: pathlib.Path,
) -> tuple[subprocess.Popen[bytes], Any, Any]:
    stdout = (scratch / "stdout.log").open("wb")
    stderr = (scratch / "stderr.log").open("wb")
    config_home = scratch / ".config"
    profile_home = config_home / "mihomo"
    profile_home.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "HOME": str(scratch),
        "USERPROFILE": str(scratch),
        "XDG_CONFIG_HOME": str(config_home),
        "CLASH_HOME_DIR": str(profile_home),
    }
    process = subprocess.Popen(
        maybe_sudo([ip_bin(), "netns", "exec", ns, str(binary), "-f", str(config)]),
        cwd=scratch,
        env=env,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    return process, stdout, stderr


def process_logs(scratch: pathlib.Path) -> str:
    chunks: list[str] = []
    for name in ("stdout.log", "stderr.log"):
        path = scratch / name
        if path.exists():
            chunks.append(f"===== {name} =====\n{path.read_text(errors='replace')}")
    return "\n".join(chunks)


def stop_process(process: subprocess.Popen[bytes], scratch: pathlib.Path | None = None) -> int:
    try:
        return terminate_process(process, normalize_requested=True)
    except Exception:
        if scratch is not None:
            print(process_logs(scratch), file=sys.stderr)
        raise


def ns_client(ns: str, *args: str, timeout: float = NATIVE_IO_DEADLINE) -> dict[str, Any]:
    result = run_in_ns(
        ns,
        [sys.executable, str(SCRIPT), "--client", *args],
        timeout=timeout + 5,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"netns client {' '.join(args)} failed: rc={result.returncode}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    if not result.stdout.strip():
        return {}
    return json.loads(result.stdout)


def wait_mixed(ns: str, process: subprocess.Popen[bytes], port: int, scratch: pathlib.Path) -> None:
    deadline = time.monotonic() + NATIVE_STARTUP_DEADLINE
    last_error = "not attempted"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"proxy exited during TUN startup with {process.returncode}\n"
                f"{process_logs(scratch)}"
            )
        try:
            ns_client(ns, "wait-tcp", "127.0.0.1", str(port), timeout=1)
            return
        except Exception as error:  # noqa: BLE001 — surface last probe error
            last_error = str(error)
            time.sleep(0.1)
    raise TimeoutError(
        f"mixed-port {port} did not become ready in netns {ns}: {last_error}\n"
        f"{process_logs(scratch)}"
    )


def wait_tun_device(ns: Netns, process: subprocess.Popen[bytes], scratch: pathlib.Path) -> None:
    deadline = time.monotonic() + NATIVE_STARTUP_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"proxy exited before TUN device appeared: {process.returncode}\n"
                f"{process_logs(scratch)}"
            )
        if ns.has_device(ns.tun):
            return
        time.sleep(0.05)
    raise TimeoutError(f"TUN device {ns.tun} did not appear\n{process_logs(scratch)}")


def wait_gone(ns: Netns, tun: str) -> None:
    deadline = time.monotonic() + CLEANUP_DEADLINE
    while time.monotonic() < deadline:
        if not ns.has_device(tun) and tun not in ns.routes():
            return
        time.sleep(0.05)
    raise AssertionError(
        f"TUN leftovers after stop: links={ns.links()!r} routes={ns.routes()!r}"
    )


def install_manual_routes(ns: Netns) -> None:
    run_ip("route", "replace", f"{DNS_HIJACK_TARGET}/32", "dev", ns.tun, ns=ns.name)
    run_ip("route", "replace", FAKE_IP_ROUTE, "dev", ns.tun, ns=ns.name)


def assert_auto_routes(ns: Netns, stack: str) -> None:
    text = ns.routes()
    tables = run_ip("route", "show", "table", "all", ns=ns.name, check=False).stdout
    rules = run_ip("rule", "show", ns=ns.name, check=False).stdout
    if stack == "smoltcp":
        if "0.0.0.0/1" not in text or "128.0.0.0/1" not in text:
            raise AssertionError(f"auto-route split defaults missing:\n{text}")
        if ns.tun not in text:
            raise AssertionError(f"auto-route does not reference {ns.tun}:\n{text}")
        return
    if ns.tun not in text and ns.tun not in tables:
        raise AssertionError(
            f"Go auto-route did not attach {ns.tun}:\nroutes={text}\ntables={tables}\nrules={rules}"
        )


def query_hijacked_dns(ns: str, name: str) -> str:
    result = ns_client(
        ns,
        "dns-a",
        name,
        DNS_HIJACK_TARGET,
        "53",
        timeout=NATIVE_IO_DEADLINE,
    )
    address = str(result.get("address") or "")
    if not address.startswith("198.19."):
        raise AssertionError(f"DNS hijack for {name} did not return fake-IP: {result}")
    return address


def http_get(ns: str, host: str, port: int, path: str) -> bytes:
    result = ns_client(
        ns,
        "http",
        host,
        str(port),
        path,
        timeout=NATIVE_IO_DEADLINE + (10 if path == "/large" else 0),
    )
    return bytes.fromhex(str(result["body_hex"]))


def udp_echo(ns: str, host: str, port: int, payload: bytes) -> bytes:
    result = ns_client(
        ns,
        "udp-echo",
        host,
        str(port),
        payload.hex(),
        timeout=NATIVE_IO_DEADLINE,
    )
    return bytes.fromhex(str(result["payload_hex"]))


def run_closed_loop(
    binary: pathlib.Path,
    ns: Netns,
    servers: FixtureServers,
    scratch: pathlib.Path,
    *,
    auto_route: bool,
    stack: str,
    large: bool,
    udp: bool,
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
            device=ns.tun,
            auto_route=auto_route,
            stack=stack,
        ),
    )
    process, stdout, stderr = launch_in_ns(ns.name, binary, config, case_dir)
    observation: dict[str, Any] = {"label": label, "stack": stack, "auto_route": auto_route}
    try:
        wait_mixed(ns.name, process, mixed_port, case_dir)
        wait_tun_device(ns, process, case_dir)
        if auto_route:
            assert_auto_routes(ns, stack)
        else:
            install_manual_routes(ns)
        fake_http = query_hijacked_dns(ns.name, HTTP_NAME)
        body = http_get(ns.name, fake_http, servers.http_port, "/small")
        if body != HTTP_SMALL:
            raise AssertionError(f"{label} small HTTP mismatch: {body!r}")
        observation["http-small"] = True
        observation["fake-ip-http"] = fake_http
        if large:
            large_body = http_get(ns.name, fake_http, servers.http_port, "/large")
            if large_body != HTTP_LARGE:
                raise AssertionError(
                    f"{label} large HTTP length {len(large_body)} != {len(HTTP_LARGE)}"
                )
            observation["http-large"] = True
        if udp:
            fake_udp = query_hijacked_dns(ns.name, UDP_NAME)
            echoed = udp_echo(ns.name, fake_udp, servers.udp_port, UDP_PAYLOAD)
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
        wait_gone(ns, ns.tun)
        observation["stop-cleanup"] = True


def run_init_failure(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    case_dir = scratch / "init-failure"
    case_dir.mkdir(parents=True, exist_ok=True)
    with IsolatedNetns() as isolated:
        config = write_config(
            case_dir,
            "config.yaml",
            tun_config(
                mixed_port=17890,
                dns_listen=5353,
                nameserver="8.8.8.8:53",
                device=isolated.tun,
                auto_route=True,
                stack="smoltcp",
            ),
        )
        process, stdout, stderr = launch_in_ns(isolated.name, binary, config, case_dir)
        try:
            deadline = time.monotonic() + NATIVE_STARTUP_DEADLINE
            while process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            code = process.poll()
            logs = process_logs(case_dir)
            if code is None:
                stop_process(process, case_dir)
                raise AssertionError(
                    f"init-failure process stayed up without a default route\n{logs}"
                )
            if code == 0:
                raise AssertionError(
                    f"init-failure process exited 0 without a default route\n{logs}"
                )
            gone_deadline = time.monotonic() + CLEANUP_DEADLINE
            leftover = isolated.leftover()
            while time.monotonic() < gone_deadline:
                leftover = isolated.leftover()
                if (
                    isolated.tun not in leftover
                    and "0.0.0.0/1" not in leftover
                    and "128.0.0.0/1" not in leftover
                ):
                    return {
                        "exited": True,
                        "nonzero-exit": code != 0,
                        "no-leftover-routes": True,
                    }
                time.sleep(0.05)
            raise AssertionError(f"init-failure leftover routes/device:\n{leftover}\n{logs}")
        finally:
            stdout.close()
            stderr.close()
            if process.poll() is None:
                stop_process(process, case_dir)


def native_gate(binaries: dict[str, pathlib.Path], scratch: pathlib.Path) -> dict[str, Any]:
    if os.environ.get("PHASE8A_NATIVE") != "1":
        print(
            "native netns traffic gate not requested "
            "(set PHASE8A_NATIVE=1 on a privileged Linux runner)"
        )
        return {"requested": False}
    require_native_prereqs()
    observations: dict[str, Any] = {"requested": True}
    with Netns() as ns:
        with FixtureServers(SERVICE_IP) as servers:
            observations["rust-manual"] = run_closed_loop(
                binaries["rust"],
                ns,
                servers,
                scratch,
                auto_route=False,
                stack="smoltcp",
                large=False,
                udp=False,
                label="rust-manual",
                mixed_port=17890,
                dns_listen=15353,
            )
            observations["rust-auto"] = run_closed_loop(
                binaries["rust"],
                ns,
                servers,
                scratch,
                auto_route=True,
                stack="smoltcp",
                large=True,
                udp=True,
                label="rust-auto",
                mixed_port=17891,
                dns_listen=15354,
            )
            observations["go-auto"] = run_closed_loop(
                binaries["go"],
                ns,
                servers,
                scratch,
                auto_route=True,
                stack="system",
                large=True,
                udp=True,
                label="go-auto",
                mixed_port=17892,
                dns_listen=15355,
            )
            rust_http = observations["rust-auto"].get("fake-ip-http")
            go_http = observations["go-auto"].get("fake-ip-http")
            if not rust_http or not go_http:
                raise AssertionError("Go/Rust fake-IP HTTP addresses missing")
            observations["go-rust-http-body-match"] = True
            observations["go-rust-fake-ip-not-compared"] = True
    observations["rust-init-failure"] = run_init_failure(binaries["rust"], scratch)
    return observations


def client_main(argv: list[str]) -> int:
    if not argv:
        raise SystemExit("missing client command")
    command, *rest = argv
    if command == "wait-tcp":
        host, port = rest[0], int(rest[1])
        with socket.create_connection((host, port), timeout=0.4):
            pass
        print("{}")
        return 0
    if command == "dns-a":
        name, server, port = rest[0], rest[1], int(rest[2])
        query = make_query(name, 1, 0x8A01)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(NATIVE_IO_DEADLINE)
        try:
            sock.sendto(query, (server, port))
            message, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        parsed = parse_response(message, 0x8A01)
        records = parsed.get("records") or []
        address = records[0]["data"] if records else ""
        print(json.dumps({"address": address, "rcode": parsed.get("rcode")}))
        return 0
    if command == "http":
        host, port, path = rest[0], int(rest[1]), rest[2]
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
            raise SystemExit(f"HTTP failed: {header!r}")
        print(json.dumps({"body_hex": body.hex(), "status": status.decode(errors="replace")}))
        return 0
    if command == "udp-echo":
        host, port, payload_hex = rest[0], int(rest[1]), rest[2]
        payload = bytes.fromhex(payload_hex)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(NATIVE_IO_DEADLINE)
        try:
            sock.sendto(payload, (host, port))
            echoed, _ = sock.recvfrom(65536)
        finally:
            sock.close()
        print(json.dumps({"payload_hex": echoed.hex()}))
        return 0
    raise SystemExit(f"unknown client command: {command}")


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--client":
        return client_main(sys.argv[2:])
    assert_go_oracle_baseline()
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phase8a-tun-") as scratch_dir:
        scratch = pathlib.Path(scratch_dir)
        binaries = build_binaries(
            scratch,
            cargo_target_variable="PHASE8A_CARGO_TARGET",
            default_target_name="phase8a",
            stage_runtime=True,
        )
        observations: dict[str, Any] = {
            "identity": config_identity(binaries, scratch),
        }
        native = native_gate(binaries, scratch)
        observations["native"] = native
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, default=str) + "\n")
        print("phase8a observations:")
        print(json.dumps(observations, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

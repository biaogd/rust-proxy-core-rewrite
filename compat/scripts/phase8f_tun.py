#!/usr/bin/env python3
"""Phase 8F TUN network-change monitor and session-bound identity gate.

Unprivileged: same stack identity as 8A (`smoltcp` only; Go stacks rejected
without remap), plus `auto-detect-interface: true` accepted by Rust.

Native traffic (YAML → tun-rs → netstack-smoltcp → DIRECT / domain TUIC, then a
default uplink switch that also takes the old veth down) requires a privileged
Linux runner. The flap keeps one client UDP socket across the switch and, with
TUN up, sends mixed/SOCKS UDP to localhost. Set PHASE8F_NATIVE=1; missing
capability fails closed instead of skipping green. This gate is Rust-only: it
does not flap a Go TUN.

Out of this gate: UDP fragment/loss, TUN TCP half-close/RST fixtures,
Android netlink (8D), Darwin/Windows FFI monitors, native NIC flap on
Darwin/Windows, and 8D/8E.
"""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from typing import Any

from phase1 import ROOT, assert_go_oracle_baseline
from phase3 import launch as launch_go, stop as stop_go
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries
from phase6h_tuic_tcp import PASSWORD as TUIC_PASSWORD, SNI as TUIC_SNI, UUID as TUIC_UUID
from phase8a_tun import (
    CLEANUP_DEADLINE,
    FAKE_IP_RANGE,
    FixtureServers,
    HTTP_NAME,
    HTTP_SMALL,
    HttpHandler,
    MINIMAL,
    NATIVE_IO_DEADLINE,
    NATIVE_STARTUP_DEADLINE,
    SERVICE_IP,
    TUN_INET4,
    UDP_NAME,
    config_identity,
    expect_accept,
    http_get,
    ip_bin,
    launch_in_ns,
    maybe_sudo,
    ns_client,
    process_logs,
    query_hijacked_dns,
    run_in_ns,
    run_ip,
    stop_process,
    udp_echo,
    wait_mixed,
    write_config,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase8f-tun-diff.json"
CHANGE_DEADLINE = 10.0
UDP_LARGE = b"phase8f-udp-echo" * 64  # 1024 bytes; not a fragment/loss claim
VETH_A_HOST = "10.66.8.1"
VETH_A_NS = "10.66.8.2"
VETH_B_HOST = "10.66.9.1"
VETH_B_NS = "10.66.9.2"
DIRECT_IP = "192.0.2.8"
PROXY_IP = "192.0.2.9"
PROXY_NAME = "proxy.phase8f.test"


def identity_auto_detect(binaries: dict[str, pathlib.Path], scratch: pathlib.Path) -> dict[str, Any]:
    source = MINIMAL + (
        "\ntun:\n  enable: true\n  stack: smoltcp\n"
        "  auto-route: true\n  auto-detect-interface: true\n"
    )
    expect_accept(binaries["rust"], source, scratch, "auto-detect-interface")
    go_source = MINIMAL + (
        "\ntun:\n  enable: true\n  stack: system\n"
        "  auto-route: true\n  auto-detect-interface: true\n"
    )
    expect_accept(binaries["go"], go_source, scratch, "go auto-detect-interface")
    return {"rust-auto-detect-interface": True, "go-auto-detect-interface": True}


def native_prereq_error() -> str | None:
    if sys.platform != "linux":
        return "PHASE8F_NATIVE requires Linux"
    if not os.path.exists("/dev/net/tun"):
        return "PHASE8F_NATIVE requires /dev/net/tun; refusing to skip green"
    if shutil.which("ip") is None and not os.path.exists("/usr/sbin/ip"):
        return "PHASE8F_NATIVE requires iproute2; refusing to skip green"
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
            "PHASE8F_NATIVE requires root/CAP_NET_ADMIN (passwordless sudo); "
            "refusing to skip green"
        )
    return None


def require_native_prereqs() -> None:
    error = native_prereq_error()
    if error:
        raise SystemExit(error)


def run_sysctl(key: str, ns: str | None = None) -> None:
    argv = ["sysctl", "-w", key]
    if ns is None:
        subprocess.run(
            maybe_sudo(argv),
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        return
    run_in_ns(ns, argv, check=False)


class DualUplinkNetns:
    """Two veth uplinks so the physical default can move without a real NIC flap."""

    def __init__(self) -> None:
        token = f"{os.getpid() % 100000:05d}"
        self.name = f"p8fs{token}"
        self.veth_a_host = f"p8fa{token}"
        self.veth_a_ns = f"p8na{token}"
        self.veth_b_host = f"p8fb{token}"
        self.veth_b_ns = f"p8nb{token}"
        self.tun = f"p8ft{token}"
        self._owned = False

    def __enter__(self) -> DualUplinkNetns:
        run_ip("netns", "delete", self.name, check=False)
        run_ip("link", "delete", self.veth_a_host, check=False)
        run_ip("link", "delete", self.veth_b_host, check=False)
        run_ip("netns", "add", self.name)
        self._owned = True
        run_ip("link", "add", self.veth_a_host, "type", "veth", "peer", "name", self.veth_a_ns)
        run_ip("link", "add", self.veth_b_host, "type", "veth", "peer", "name", self.veth_b_ns)
        run_ip("link", "set", self.veth_a_ns, "netns", self.name)
        run_ip("link", "set", self.veth_b_ns, "netns", self.name)
        run_ip("addr", "add", f"{VETH_A_HOST}/24", "dev", self.veth_a_host)
        run_ip("addr", "add", f"{VETH_B_HOST}/24", "dev", self.veth_b_host)
        run_ip("addr", "add", f"{SERVICE_IP}/32", "dev", self.veth_a_host)
        run_ip("addr", "add", f"{SERVICE_IP}/32", "dev", self.veth_b_host, check=False)
        run_ip("addr", "add", f"{DIRECT_IP}/32", "dev", self.veth_a_host)
        run_ip("addr", "add", f"{DIRECT_IP}/32", "dev", self.veth_b_host, check=False)
        run_ip("addr", "add", f"{PROXY_IP}/32", "dev", self.veth_a_host)
        run_ip("addr", "add", f"{PROXY_IP}/32", "dev", self.veth_b_host, check=False)
        run_ip("link", "set", self.veth_a_host, "up")
        run_ip("link", "set", self.veth_b_host, "up")
        run_ip("link", "set", "lo", "up", ns=self.name)
        run_ip("addr", "add", f"{VETH_A_NS}/24", "dev", self.veth_a_ns, ns=self.name)
        run_ip("addr", "add", f"{VETH_B_NS}/24", "dev", self.veth_b_ns, ns=self.name)
        run_ip("link", "set", self.veth_a_ns, "up", ns=self.name)
        run_ip("link", "set", self.veth_b_ns, "up", ns=self.name)
        run_ip(
            "route",
            "replace",
            "default",
            "via",
            VETH_A_HOST,
            "dev",
            self.veth_a_ns,
            ns=self.name,
        )
        run_ip("route", "replace", f"{SERVICE_IP}/32", "via", VETH_A_HOST, ns=self.name)
        for key in (
            "net.ipv4.conf.all.rp_filter=0",
            "net.ipv4.conf.default.rp_filter=0",
        ):
            run_sysctl(key, ns=self.name)
        for iface in (self.veth_a_host, self.veth_b_host):
            run_sysctl(f"net.ipv4.conf.{iface}.rp_filter=0")
        return self

    def __exit__(self, *args: object) -> None:
        if not self._owned:
            return
        run_ip("netns", "delete", self.name, check=False)
        run_ip("link", "delete", self.veth_a_host, check=False)
        run_ip("link", "delete", self.veth_b_host, check=False)
        self._owned = False

    def routes(self) -> str:
        result = run_ip("route", "show", ns=self.name, check=False)
        return (result.stdout or "") + (result.stderr or "")

    def links(self) -> str:
        result = run_ip("link", "show", ns=self.name, check=False)
        return (result.stdout or "") + (result.stderr or "")

    def has_device(self, name: str) -> bool:
        return name in self.links()

    def default_device(self) -> str:
        result = run_ip("route", "show", "default", ns=self.name, check=False)
        text = result.stdout or ""
        words = text.split()
        if "dev" in words:
            index = words.index("dev")
            if index + 1 < len(words):
                return words[index + 1]
        return ""


class PersistentNsUdp:
    """One UDP client socket in the netns so flap recovery is not a new session."""

    def __init__(self, ns: str, host: str, port: int) -> None:
        script = r"""
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(8)
while True:
    line = sys.stdin.readline()
    if not line:
        break
    payload = bytes.fromhex(line.strip())
    sock.sendto(payload, (host, port))
    data, _ = sock.recvfrom(65536)
    sys.stdout.write(data.hex() + "\n")
    sys.stdout.flush()
"""
        self.proc = subprocess.Popen(
            maybe_sudo(
                [ip_bin(), "netns", "exec", ns, sys.executable, "-c", script, host, str(port)]
            ),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def echo(self, payload: bytes) -> bytes:
        if self.proc.stdin is None or self.proc.stdout is None:
            raise RuntimeError("persistent UDP process has no pipes")
        self.proc.stdin.write(payload.hex().encode() + b"\n")
        self.proc.stdin.flush()
        ready, _, _ = select.select([self.proc.stdout], [], [], NATIVE_IO_DEADLINE + 2)
        if not ready:
            raise AssertionError("persistent UDP echo timed out on the same client socket")
        line = self.proc.stdout.readline()
        if not line:
            err = b""
            if self.proc.poll() is not None and self.proc.stderr is not None:
                err = self.proc.stderr.read()
            raise AssertionError(f"persistent UDP client exited: {err!r}")
        return bytes.fromhex(line.decode().strip())

    def close(self) -> None:
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        self.proc.kill()
        self.proc.wait(timeout=5)


class NetnsLoopbackUdpEcho:
    def __init__(self, ns: str) -> None:
        script = r"""
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
sys.stdout.write(str(sock.getsockname()[1]) + "\n")
sys.stdout.flush()
while True:
    data, addr = sock.recvfrom(65536)
    sock.sendto(data, addr)
"""
        self.proc = subprocess.Popen(
            maybe_sudo([ip_bin(), "netns", "exec", ns, sys.executable, "-c", script]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if self.proc.stdout is None:
            raise RuntimeError("loopback UDP echo has no stdout")
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read() if self.proc.stderr else b""
            raise AssertionError(f"loopback UDP echo failed to bind: {err!r}")
        self.port = int(line.decode().strip())

    def close(self) -> None:
        self.proc.kill()
        self.proc.wait(timeout=5)


def tun_config(
    *,
    mixed_port: int,
    dns_listen: int,
    nameserver: str,
    device: str,
    extra: str = "",
    extra_rules: str = "",
    http_outbound: str = "DIRECT",
) -> str:
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
dns:
  enable: true
  listen: 127.0.0.1:{dns_listen}
  ipv6: false
  use-hosts: true
  use-system-hosts: false
  enhanced-mode: fake-ip
  fake-ip-range: {FAKE_IP_RANGE}
  fake-ip-filter:
    - 'never-match.phase8f.test'
    - '{PROXY_NAME}'
  nameserver:
    - udp://{nameserver}
{extra}tun:
  enable: true
  device: {device}
  stack: smoltcp
  auto-route: true
  auto-detect-interface: true
  inet4-address:
    - {TUN_INET4}
  dns-hijack:
    - 0.0.0.0:53
  mtu: 1500
rules:
{extra_rules}  - DOMAIN,{HTTP_NAME},{http_outbound}
  - DOMAIN,{UDP_NAME},DIRECT
  - MATCH,REJECT
"""


class ExtraServers:
    def __init__(self) -> None:
        self.direct: http.server.ThreadingHTTPServer | None = None
        self.reject: http.server.ThreadingHTTPServer | None = None
        self.direct_port = 0
        self.reject_port = 0
        self.threads: list[threading.Thread] = []

    def __enter__(self) -> ExtraServers:
        self.direct = http.server.ThreadingHTTPServer((DIRECT_IP, 0), HttpHandler)
        self.direct_port = int(self.direct.server_address[1])
        direct_thread = threading.Thread(target=self.direct.serve_forever, daemon=True)
        direct_thread.start()
        self.threads.append(direct_thread)
        self.reject = http.server.ThreadingHTTPServer((DIRECT_IP, 0), HttpHandler)
        self.reject_port = int(self.reject.server_address[1])
        reject_thread = threading.Thread(target=self.reject.serve_forever, daemon=True)
        reject_thread.start()
        self.threads.append(reject_thread)
        return self

    def __exit__(self, *args: object) -> None:
        for server in (self.direct, self.reject):
            if server is not None:
                server.shutdown()
                server.server_close()


def socks_udp_echo(
    ns: str, mixed_port: int, host: str, port: int, payload: bytes
) -> bytes:
    result = ns_client(
        ns,
        "socks-udp-echo",
        str(mixed_port),
        host,
        str(port),
        payload.hex(),
        timeout=NATIVE_IO_DEADLINE,
    )
    return bytes.fromhex(str(result["payload_hex"]))


def route_get(ns: DualUplinkNetns, destination: str) -> str:
    result = run_ip("route", "get", destination, ns=ns.name, check=False)
    return (result.stdout or "") + (result.stderr or "")


def assert_not_via_tun(ns: DualUplinkNetns, destination: str) -> None:
    text = route_get(ns, destination)
    if ns.tun in text.split():
        raise AssertionError(f"{destination} is routed via TUN {ns.tun}:\n{text}\n{ns.routes()}")


def assert_via_tun(ns: DualUplinkNetns, destination: str) -> None:
    text = route_get(ns, destination)
    if ns.tun not in text.split():
        raise AssertionError(
            f"{destination} left TUN {ns.tun}; per-port rules would be skipped:\n"
            f"{text}\n{ns.routes()}"
        )


def http_get_must_fail(ns: str, host: str, port: int, path: str) -> None:
    try:
        body = http_get(ns, host, port, path)
    except Exception:
        return
    raise AssertionError(f"{host}:{port} leaked past REJECT: {body!r}")



def wait_tun_device(
    ns: DualUplinkNetns, process: subprocess.Popen[bytes], scratch: pathlib.Path
) -> None:
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


def wait_gone(ns: DualUplinkNetns, tun: str) -> None:
    deadline = time.monotonic() + CLEANUP_DEADLINE
    while time.monotonic() < deadline:
        leftover = f"{ns.links()}\n{ns.routes()}"
        if tun not in leftover and "0.0.0.0/1" not in leftover and "128.0.0.0/1" not in leftover:
            return
        time.sleep(0.05)
    raise AssertionError(
        f"TUN leftovers after stop: links={ns.links()!r} routes={ns.routes()!r}"
    )


def assert_split_defaults(ns: DualUplinkNetns) -> None:
    text = ns.routes()
    if "0.0.0.0/1" not in text or "128.0.0.0/1" not in text:
        raise AssertionError(f"auto-route split defaults missing:\n{text}")
    if ns.tun not in text:
        raise AssertionError(f"auto-route does not reference {ns.tun}:\n{text}")


def wait_monitor_log(
    process: subprocess.Popen[bytes],
    scratch: pathlib.Path,
    needle: str,
    expected_iface: str,
) -> str:
    deadline = time.monotonic() + CHANGE_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"proxy exited during network-change wait: {process.returncode}\n"
                f"{process_logs(scratch)}"
            )
        logs = process_logs(scratch)
        if needle in logs and expected_iface in logs:
            return logs
        time.sleep(0.1)
    raise TimeoutError(
        f"did not observe `{needle}` for {expected_iface} within {CHANGE_DEADLINE}s\n"
        f"{process_logs(scratch)}"
    )


def wait_udp_listen(ip: str, port: int, process: subprocess.Popen[bytes], scratch: pathlib.Path) -> None:
    deadline = time.monotonic() + NATIVE_STARTUP_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"TUIC authority exited before listen: {process.returncode}\n"
                f"{process_logs(scratch)}"
            )
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind((ip, port))
        except OSError:
            return
        finally:
            probe.close()
        time.sleep(0.05)
    raise TimeoutError(f"TUIC authority did not bind {ip}:{port}\n{process_logs(scratch)}")


def start_tuic_authority(
    go_binary: pathlib.Path,
    listen_ip: str,
    listen_port: int,
    scratch: pathlib.Path,
) -> tuple[subprocess.Popen[bytes], Any, Any]:
    case = scratch / "tuic-authority"
    case.mkdir(parents=True, exist_ok=True)
    cert_pem = textwrap.indent(SERVER_CERTIFICATE.read_text().strip(), "      ")
    key_pem = textwrap.indent(SERVER_KEY.read_text().strip(), "      ")
    config = write_config(
        case,
        "authority.yaml",
        f"""mixed-port: 0
mode: rule
log-level: warning
ipv6: false
hosts:
  {HTTP_NAME}: {SERVICE_IP}
listeners:
  - name: tuic-in
    type: tuic
    listen: {listen_ip}
    port: {listen_port}
    users:
      {TUIC_UUID}: {TUIC_PASSWORD}
    certificate: |-
{cert_pem}
    private-key: |-
{key_pem}
    alpn:
      - h3
rules:
  - MATCH,DIRECT
""",
    )
    process, stdout, stderr = launch_go(go_binary, config, case)
    try:
        wait_udp_listen(listen_ip, listen_port, process, case)
    except Exception:
        stdout.close()
        stderr.close()
        stop_go(process)
        raise
    return process, stdout, stderr


def reserve_udp_port(ip: str) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def run_uplink_switch(
    rust_binary: pathlib.Path,
    go_binary: pathlib.Path,
    ns: DualUplinkNetns,
    servers: FixtureServers,
    extra: ExtraServers,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    case_dir = scratch / "rust-flap"
    case_dir.mkdir(parents=True, exist_ok=True)
    tuic_port = reserve_udp_port(PROXY_IP)
    tuic_process, tuic_stdout, tuic_stderr = start_tuic_authority(
        go_binary, PROXY_IP, tuic_port, scratch
    )
    extra_yaml = f"""hosts:
  {PROXY_NAME}: {PROXY_IP}
proxies:
  - name: p8f-tuic
    type: tuic
    server: {PROXY_NAME}
    port: {tuic_port}
    uuid: {TUIC_UUID}
    password: {TUIC_PASSWORD}
    sni: {TUIC_SNI}
    skip-cert-verify: true
    alpn: [h3]
"""
    extra_rules = (
        f"  - DST-PORT,{extra.direct_port},DIRECT\n"
        f"  - IP-CIDR,{DIRECT_IP}/32,REJECT\n"
        "  - IP-CIDR,127.0.0.1/32,DIRECT\n"
    )
    config = write_config(
        case_dir,
        "config.yaml",
        tun_config(
            mixed_port=17890,
            dns_listen=15353,
            nameserver=f"{SERVICE_IP}:{servers.dns_port}",
            device=ns.tun,
            extra=extra_yaml,
            extra_rules=extra_rules,
            http_outbound="p8f-tuic",
        ),
    )
    process, stdout, stderr = launch_in_ns(ns.name, rust_binary, config, case_dir)
    observation: dict[str, Any] = {"label": "rust-flap", "stack": "smoltcp"}
    persistent_udp: PersistentNsUdp | None = None
    loopback_echo: NetnsLoopbackUdpEcho | None = None
    try:
        wait_mixed(ns.name, process, 17890, case_dir)
        wait_tun_device(ns, process, case_dir)
        assert_split_defaults(ns)
        if ns.default_device() != ns.veth_a_ns:
            raise AssertionError(
                f"expected initial default {ns.veth_a_ns}, got {ns.default_device()!r}\n"
                f"{ns.routes()}"
            )
        assert_not_via_tun(ns, SERVICE_IP)
        body = http_get(ns.name, DIRECT_IP, extra.direct_port, "/small")
        if body != HTTP_SMALL:
            raise AssertionError(f"public DIRECT mismatch: {body!r}")
        observation["public-direct"] = True
        assert_via_tun(ns, DIRECT_IP)
        observation["direct-stays-in-tun-table"] = True
        http_get_must_fail(ns.name, DIRECT_IP, extra.reject_port, "/small")
        observation["same-ip-reject-still-applies"] = True
        fake_http = query_hijacked_dns(ns.name, HTTP_NAME)
        body = http_get(ns.name, fake_http, servers.http_port, "/small")
        if body != HTTP_SMALL:
            raise AssertionError(f"domain TUIC HTTP mismatch: {body!r}")
        observation["domain-tuic"] = True
        observation["fake-ip-http"] = fake_http
        assert_via_tun(ns, PROXY_IP)
        observation["tuic-server-stays-in-tun-table"] = True
        fake_udp = query_hijacked_dns(ns.name, UDP_NAME)
        persistent_udp = PersistentNsUdp(ns.name, fake_udp, servers.udp_port)
        before = b"phase8f-udp-before"
        echoed = persistent_udp.echo(before)
        if echoed != before:
            raise AssertionError(f"persistent UDP before flap: {echoed!r}")
        observation["udp-persistent-before"] = True
        loopback_echo = NetnsLoopbackUdpEcho(ns.name)
        loopback_payload = b"phase8f-socks-loopback"
        echoed = socks_udp_echo(
            ns.name, 17890, "127.0.0.1", loopback_echo.port, loopback_payload
        )
        if echoed != loopback_payload:
            raise AssertionError(f"SOCKS UDP localhost with TUN up: {echoed!r}")
        observation["socks-udp-loopback"] = True

        run_ip(
            "route",
            "replace",
            "default",
            "via",
            VETH_B_HOST,
            "dev",
            ns.veth_b_ns,
            ns=ns.name,
        )
        run_ip("route", "replace", f"{SERVICE_IP}/32", "via", VETH_B_HOST, ns=ns.name)
        if ns.default_device() != ns.veth_b_ns:
            raise AssertionError(
                f"failed to move default to {ns.veth_b_ns}: {ns.default_device()!r}\n"
                f"{ns.routes()}"
            )
        wait_monitor_log(
            process,
            case_dir,
            "default interface changed by monitor",
            ns.veth_b_ns,
        )
        wait_monitor_log(
            process,
            case_dir,
            "rebound QUIC endpoints onto",
            ns.veth_b_ns,
        )
        observation["monitor-log"] = True
        run_ip("link", "set", ns.veth_a_ns, "down", ns=ns.name)
        if ns.default_device() != ns.veth_b_ns:
            raise AssertionError(
                f"old uplink down left default on {ns.default_device()!r}\n"
                f"{ns.routes()}\n{ns.links()}"
            )
        observation["old-uplink-down"] = True
        assert_split_defaults(ns)
        observation["split-defaults-after"] = True
        assert_not_via_tun(ns, SERVICE_IP)
        assert_via_tun(ns, PROXY_IP)
        observation["dns-not-via-tun-after"] = True
        body = http_get(ns.name, fake_http, servers.http_port, "/small")
        if body != HTTP_SMALL:
            raise AssertionError(f"post-flap TUIC HTTP mismatch: {body!r}")
        observation["http-after"] = True
        body = http_get(ns.name, DIRECT_IP, extra.direct_port, "/small")
        if body != HTTP_SMALL:
            raise AssertionError(f"post-flap public DIRECT mismatch: {body!r}")
        observation["public-direct-after"] = True
        http_get_must_fail(ns.name, DIRECT_IP, extra.reject_port, "/small")
        observation["same-ip-reject-after"] = True
        if persistent_udp is None:
            raise AssertionError("persistent UDP client was not started before flap")
        after = b"phase8f-udp-after"
        echoed = persistent_udp.echo(after)
        if echoed != after:
            raise AssertionError(f"persistent UDP after flap: {echoed!r}")
        observation["udp-persistent-after"] = True
        echoed = udp_echo(ns.name, fake_udp, servers.udp_port, UDP_LARGE)
        if echoed != UDP_LARGE:
            raise AssertionError(
                f"post-flap UDP echo length {len(echoed)} != {len(UDP_LARGE)}"
            )
        observation["udp-large-after"] = True
        return observation
    except Exception:
        print(process_logs(case_dir), file=sys.stderr)
        print(process_logs(scratch / "tuic-authority"), file=sys.stderr)
        raise
    finally:
        if persistent_udp is not None:
            persistent_udp.close()
        if loopback_echo is not None:
            loopback_echo.close()
        stdout.close()
        stderr.close()
        stop_process(process, case_dir)
        tuic_stdout.close()
        tuic_stderr.close()
        stop_go(tuic_process)
        wait_gone(ns, ns.tun)
        run_ip("link", "set", ns.veth_a_ns, "up", ns=ns.name, check=False)
        observation["stop-cleanup"] = True


def run_route_conflict(
    binary: pathlib.Path,
    ns: DualUplinkNetns,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    case_dir = scratch / "route-conflict"
    case_dir.mkdir(parents=True, exist_ok=True)
    run_ip(
        "route",
        "replace",
        "0.0.0.0/1",
        "via",
        VETH_A_HOST,
        "dev",
        ns.veth_a_ns,
        ns=ns.name,
    )
    before = ns.routes()
    if "0.0.0.0/1" not in before or ns.veth_a_ns not in before:
        raise AssertionError(f"failed to preinstall foreign 0.0.0.0/1:\n{before}")
    config = write_config(
        case_dir,
        "config.yaml",
        tun_config(
            mixed_port=17891,
            dns_listen=15354,
            nameserver="8.8.8.8:53",
            device=ns.tun,
        ),
    )
    process, stdout, stderr = launch_in_ns(ns.name, binary, config, case_dir)
    try:
        deadline = time.monotonic() + NATIVE_STARTUP_DEADLINE
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        code = process.poll()
        logs = process_logs(case_dir)
        if code is None:
            stop_process(process, case_dir)
            raise AssertionError(f"conflict process stayed up over a foreign 0.0.0.0/1\n{logs}")
        if code == 0:
            raise AssertionError(f"conflict process exited 0 over a foreign route\n{logs}")
        if "refusing to replace existing route" not in logs:
            raise AssertionError(f"conflict missing refuse-to-replace:\n{logs}")
        after = ns.routes()
        if "0.0.0.0/1" not in after or ns.veth_a_ns not in after:
            raise AssertionError(f"foreign 0.0.0.0/1 was overwritten:\n{after}")
        if ns.tun in after:
            raise AssertionError(f"TUN leftover after conflict:\n{after}\n{ns.links()}")
        return {
            "exited": True,
            "nonzero-exit": True,
            "refused-foreign-route": True,
            "foreign-route-kept": True,
        }
    finally:
        stdout.close()
        stderr.close()
        if process.poll() is None:
            stop_process(process, case_dir)
        run_ip("route", "del", "0.0.0.0/1", ns=ns.name, check=False)


def native_gate(binaries: dict[str, pathlib.Path], scratch: pathlib.Path) -> dict[str, Any]:
    if os.environ.get("PHASE8F_NATIVE") != "1":
        print(
            "native netns network-change gate not requested "
            "(set PHASE8F_NATIVE=1 on a privileged Linux runner)"
        )
        return {"requested": False}
    require_native_prereqs()
    observations: dict[str, Any] = {"requested": True}
    with DualUplinkNetns() as ns:
        with FixtureServers(SERVICE_IP) as servers:
            with ExtraServers() as extra:
                observations["rust-flap"] = run_uplink_switch(
                    binaries["rust"], binaries["go"], ns, servers, extra, scratch
                )
        observations["route-conflict"] = run_route_conflict(binaries["rust"], ns, scratch)
    return observations


def main() -> int:
    assert_go_oracle_baseline()
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phase8f-tun-") as scratch_dir:
        scratch = pathlib.Path(scratch_dir)
        binaries = build_binaries(
            scratch,
            cargo_target_variable="PHASE8F_CARGO_TARGET",
            default_target_name="phase8f",
            stage_runtime=True,
        )
        observations: dict[str, Any] = {
            "identity": config_identity(binaries, scratch),
            "auto-detect": identity_auto_detect(binaries, scratch),
        }
        native = native_gate(binaries, scratch)
        observations["native"] = native
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, default=str) + "\n")
        print("phase8f observations:")
        print(json.dumps(observations, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

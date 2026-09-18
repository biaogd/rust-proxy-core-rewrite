#!/usr/bin/env python3
"""Go/Rust differential for Phase 7T1-A TCP dialer-proxy chains.

Proves hop path (not echo-only):

  SOCKS5 A → HTTP B → TCP echo
  HTTP A   → SOCKS5 B → TCP echo
  SOCKS5 A → Snell v2 B → half-close destination
  SOCKS5 A → VMess / VLESS / Trojan B → authority echo (W5.5)

Each fixture records which hop received which target so B must reach its
server through A.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import selectors
import socket
import socketserver
import subprocess
import tempfile
import textwrap
import threading
import time
from pathlib import Path
from typing import Any

from hy2_support import build_binaries
from phase1 import (
    EchoHandler,
    HalfCloseHandler,
    IO_DEADLINE,
    ROOT,
    cargo_target_path,
    recv_exact,
    recv_until,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE
from phase5b1a import connect_domain, debug_files
from phase6d_vmess_tcp import UUID as VMESS_UUID
from phase6d_vmess_tcp import build_authority as build_vmess_authority
from phase6d_vmess_tcp import start_authority as start_vmess_authority
from phase6e_vless_tcp import STANDARD_UUID as VLESS_UUID
from phase6e_vless_tcp import VlessAuthority
from phase6f_trojan_tcp import PASSWORD as TROJAN_PASSWORD
from phase6f_trojan_tcp import TrojanAuthority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase7t1-dialer-proxy-tcp-diff.json"
HTTP_AUTH = "Basic " + base64.b64encode(b"http-user:http-pass").decode()
SNELL_PSK = "phase7t1-snell-psk"
HALF_CLOSE_PAYLOAD = b"phase7t1-snell-half-close"
CARGO_TARGET_ENV = "PHASE7T1_DIALER_PROXY_CARGO_TARGET"
CARGO_TARGET_NAME = "phase7t1-dialer-proxy"
PROTOCOL_DEST_HOST = "dialer.phase7t1"
PROTOCOL_DEST_PORT = 28071


def trojan_roots() -> str:
    root = Path(ROOT_CERTIFICATE).read_text().strip()
    return "tls:\n  custom-certifactes:\n    - |-\n" + textwrap.indent(root, "      ") + "\n"


def relay(left: socket.socket, right: socket.socket) -> None:
    poller = selectors.DefaultSelector()
    poller.register(left, selectors.EVENT_READ, right)
    poller.register(right, selectors.EVENT_READ, left)
    while True:
        events = poller.select(timeout=5)
        if not events:
            return
        for key, _ in events:
            data = key.fileobj.recv(65536)
            if not data:
                return
            key.data.sendall(data)


class RecordingHttpProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, label: str) -> None:
        super().__init__(("127.0.0.1", 0), HttpConnectHandler)
        self.label = label
        self.observations: list[dict[str, Any]] = []
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)


class HttpConnectHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        request = recv_until(self.request, b"\r\n\r\n")
        lines = request.decode("latin1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = {
            name.lower(): value.strip()
            for line in lines[1:]
            if ":" in line
            for name, value in [line.split(":", 1)]
        }
        self.server.observations.append(
            {
                "hop": self.server.label,
                "kind": "http",
                "method": method,
                "target_host": target.rsplit(":", 1)[0].strip("[]"),
                "authorized": headers.get("proxy-authorization") == HTTP_AUTH,
            }
        )
        if method != "CONNECT" or headers.get("proxy-authorization") != HTTP_AUTH:
            self.request.sendall(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"
            )
            return
        host, port = target.rsplit(":", 1)
        with socket.create_connection((host.strip("[]"), int(port)), timeout=5) as upstream:
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            relay(self.request, upstream)


class RecordingSocks5Proxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, label: str) -> None:
        super().__init__(("127.0.0.1", 0), Socks5Handler)
        self.label = label
        self.observations: list[dict[str, Any]] = []
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)


class Socks5Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        version, count = recv_exact(self.request, 2)
        methods = list(recv_exact(self.request, count))
        if version != 5 or 2 not in methods:
            self.request.sendall(b"\x05\xff")
            return
        self.request.sendall(b"\x05\x02")
        auth_version, username_length = recv_exact(self.request, 2)
        username = recv_exact(self.request, username_length).decode()
        password_length = recv_exact(self.request, 1)[0]
        password = recv_exact(self.request, password_length).decode()
        accepted = auth_version == 1 and username == "socks-user" and password == "socks-pass"
        self.request.sendall(bytes((1, 0 if accepted else 1)))
        if not accepted:
            return
        _version, command, _reserved, address_type = recv_exact(self.request, 4)
        if address_type == 1:
            host = str(ipaddress.ip_address(recv_exact(self.request, 4)))
        elif address_type == 4:
            host = str(ipaddress.ip_address(recv_exact(self.request, 16)))
        elif address_type == 3:
            length = recv_exact(self.request, 1)[0]
            host = recv_exact(self.request, length).decode()
        else:
            self.request.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        port = int.from_bytes(recv_exact(self.request, 2), "big")
        self.server.observations.append(
            {
                "hop": self.server.label,
                "kind": "socks5",
                "command": command,
                "target_host": host,
                "authorized": True,
            }
        )
        if command != 1:
            self.request.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        with socket.create_connection((host, port), timeout=5) as upstream:
            self.request.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            relay(self.request, upstream)


def proxied_echo(mixed_port: int, echo_port: int, payload: bytes) -> bool:
    with connect_domain(mixed_port, "localhost", echo_port) as stream:
        stream.sendall(payload)
        try:
            return recv_exact(stream, len(payload)) == payload
        except (EOFError, ConnectionResetError):
            return False


def proxied_half_close(mixed_port: int, echo_port: int, payload: bytes) -> bool:
    with connect_domain(mixed_port, "localhost", echo_port) as stream:
        stream.sendall(payload)
        stream.shutdown(socket.SHUT_WR)
        expected = b"after:" + payload
        try:
            return recv_exact(stream, len(expected)) == expected
        except (EOFError, ConnectionResetError, TimeoutError):
            return False


def build_profile() -> str:
    """Same profile used by `hy2_support.build_binaries` and authority lookup."""
    return os.environ.get("HY2_BUILD_PROFILE", "debug")


def snell_authority_binary(profile: str | None = None) -> Path:
    target = cargo_target_path(CARGO_TARGET_ENV, CARGO_TARGET_NAME)
    resolved = profile or build_profile()
    suffix = ".exe" if os.name == "nt" else ""
    return target / resolved / f"rewrite-snell-authority{suffix}"


def start_snell_authority(
    binary: Path, scratch: Path, listen_port: int, psk: str, version: int
) -> tuple[subprocess.Popen[bytes], Any, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    stdout_path = scratch / "authority-stdout.log"
    stderr_path = scratch / "authority-stderr.log"
    stdout = stdout_path.open("wb")
    stderr = stderr_path.open("wb")
    process = subprocess.Popen(
        [str(binary), f"127.0.0.1:{listen_port}", psk, str(version)],
        cwd=scratch,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            logs = ""
            for path in (stdout_path, stderr_path):
                if path.exists():
                    logs += f"\n[{path.name}]\n{path.read_text(errors='replace')[-4000:]}"
            raise RuntimeError(f"Snell authority exited with {process.returncode}:{logs}")
        if stdout_path.exists() and "READY" in stdout_path.read_text(errors="replace"):
            return process, stdout, stderr
        time.sleep(0.02)
    raise TimeoutError("Snell authority did not become ready")


def wait_proxy_route(process, mixed_port: int, echo_port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during readiness with {process.returncode}")
        try:
            if proxied_echo(mixed_port, echo_port, b"ready"):
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError("dialer-proxy outbound did not become ready")


def run_chain(
    binary,
    scratch: Path,
    *,
    chain: str,
    hop_a,
    hop_b,
    echo_port: int,
) -> dict[str, Any]:
    mixed_port = reserve_port()
    if chain == "socks5-http":
        proxies = f"""proxies:
  - name: hop-a
    type: socks5
    server: 127.0.0.1
    port: {hop_a.port}
    username: socks-user
    password: socks-pass
  - name: hop-b
    type: http
    server: 127.0.0.1
    port: {hop_b.port}
    username: http-user
    password: http-pass
    dialer-proxy: hop-a
"""
    elif chain == "http-socks5":
        proxies = f"""proxies:
  - name: hop-a
    type: http
    server: 127.0.0.1
    port: {hop_a.port}
    username: http-user
    password: http-pass
  - name: hop-b
    type: socks5
    server: 127.0.0.1
    port: {hop_b.port}
    username: socks-user
    password: socks-pass
    dialer-proxy: hop-a
"""
    else:
        raise ValueError(chain)
    config = scratch / f"{chain}-config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
{proxies}
rules:
  - DOMAIN,localhost,hop-b
  - MATCH,REJECT
"""
    )
    hop_a.observations.clear()
    hop_b.observations.clear()
    run_scratch = scratch / chain
    run_scratch.mkdir(parents=True, exist_ok=True)
    process, stdout, stderr = launch(binary, config, run_scratch)
    try:
        wait_ready(process, mixed_port)
        wait_proxy_route(process, mixed_port, echo_port)
        hop_a.observations.clear()
        hop_b.observations.clear()
        payload = b"phase7t1-dialer-proxy-" + chain.encode()
        echoed = proxied_echo(mixed_port, echo_port, payload)
        path_ok = path_proves_chain(chain, hop_a.observations, hop_b.observations)
        a_saw_b_server = any(
            item.get("target_host") == "127.0.0.1" for item in hop_a.observations
        )
        b_saw_echo = any(
            item.get("target_host") in {"localhost", "127.0.0.1"}
            for item in hop_b.observations
        )
        hop_a.observations.clear()
        hop_b.observations.clear()
        big = b"Z" * (128 * 1024)
        big_ok = proxied_echo(mixed_port, echo_port, big)
        # Cancel / early client close should not leave the process dead.
        with connect_domain(mixed_port, "localhost", echo_port) as stream:
            stream.sendall(b"partial")
        survived = process.poll() is None
        return {
            "echo": echoed,
            "large-echo": big_ok,
            "survived": survived,
            "path-ok": path_ok,
            "a-saw-b-server": a_saw_b_server,
            "b-saw-echo": b_saw_echo,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def run_socks5_snell_half_close(
    binary,
    scratch: Path,
    hop_a: RecordingSocks5Proxy,
    snell_port: int,
    half_close_port: int,
) -> dict[str, Any]:
    """SOCKS5 A → Snell v2 B (dialer-proxy) → EOF-waiting destination."""
    mixed_port = reserve_port()
    config = scratch / "socks5-snell-half-close.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: hop-a
    type: socks5
    server: 127.0.0.1
    port: {hop_a.port}
    username: socks-user
    password: socks-pass
  - name: hop-b
    type: snell
    server: 127.0.0.1
    port: {snell_port}
    psk: {SNELL_PSK}
    version: 2
    dialer-proxy: hop-a
rules:
  - DOMAIN,localhost,hop-b
  - MATCH,REJECT
"""
    )
    hop_a.observations.clear()
    run_scratch = scratch / "socks5-snell-half-close"
    run_scratch.mkdir(parents=True, exist_ok=True)
    process, stdout, stderr = launch(binary, config, run_scratch)
    try:
        wait_ready(process, mixed_port)
        # Warm the route with a normal echo-style readiness check first; the
        # half-close destination only replies after SHUT_WR.
        deadline = time.monotonic() + IO_DEADLINE
        ready = False
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                if proxied_half_close(mixed_port, half_close_port, b"ready"):
                    ready = True
                    break
            except (AssertionError, OSError, EOFError, TimeoutError):
                pass
            time.sleep(0.05)
        if not ready:
            raise TimeoutError("socks5→snell half-close route did not become ready")
        hop_a.observations.clear()
        half_ok = proxied_half_close(mixed_port, half_close_port, HALF_CLOSE_PAYLOAD)
        a_saw_snell = any(
            item.get("target_host") == "127.0.0.1"
            and item.get("kind") == "socks5"
            for item in hop_a.observations
        )
        survived = process.poll() is None
        return {
            "half-close": half_ok,
            "a-saw-snell-server": a_saw_snell,
            "survived": survived,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def run_socks5_protocol_b(
    binary,
    scratch: Path,
    *,
    label: str,
    hop_a: RecordingSocks5Proxy,
    hop_b_yaml: str,
    authority_ready,
    authority_saw_dest,
    config_prefix: str = "",
) -> dict[str, Any]:
    """SOCKS5 A → protocol B (dialer-proxy) → authority-echo destination."""
    mixed_port = reserve_port()
    config = scratch / f"{label}.yaml"
    config.write_text(
        f"""{config_prefix}mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: hop-a
    type: socks5
    server: 127.0.0.1
    port: {hop_a.port}
    username: socks-user
    password: socks-pass
{hop_b_yaml}
rules:
  - DOMAIN,{PROTOCOL_DEST_HOST},hop-b
  - MATCH,REJECT
"""
    )
    hop_a.observations.clear()
    run_scratch = scratch / label
    run_scratch.mkdir(parents=True, exist_ok=True)
    process, stdout, stderr = launch(binary, config, run_scratch)

    def exchange(payload: bytes) -> bool:
        with connect_domain(mixed_port, PROTOCOL_DEST_HOST, PROTOCOL_DEST_PORT) as stream:
            stream.sendall(payload)
            try:
                return recv_exact(stream, len(payload)) == payload
            except (EOFError, ConnectionResetError):
                return False

    try:
        wait_ready(process, mixed_port)
        deadline = time.monotonic() + IO_DEADLINE
        ready = False
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                if exchange(b"ready"):
                    ready = True
                    break
            except (AssertionError, OSError, EOFError, TimeoutError):
                pass
            time.sleep(0.05)
        if not ready:
            raise TimeoutError(f"{label} dialer-proxy route did not become ready")
        hop_a.observations.clear()
        authority_ready()
        payload = f"phase7t1-{label}".encode()
        echoed = exchange(payload)
        a_saw_b = any(
            item.get("target_host") == "127.0.0.1" and item.get("kind") == "socks5"
            for item in hop_a.observations
        )
        b_saw = authority_saw_dest()
        survived = process.poll() is None
        return {
            "echo": echoed,
            "a-saw-b-server": a_saw_b,
            "b-saw-dest": b_saw,
            "survived": survived,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def path_proves_chain(chain: str, hop_a: list[dict[str, Any]], hop_b: list[dict[str, Any]]) -> bool:
    if not hop_a or not hop_b:
        return False
    # A must have been asked for B's loopback server, not only the echo target.
    a_targets = {item.get("target_host") for item in hop_a}
    b_targets = {item.get("target_host") for item in hop_b}
    if "127.0.0.1" not in a_targets and "localhost" not in a_targets:
        # B's server is always 127.0.0.1 in this fixture.
        return False
    if not any(host in {"localhost", "127.0.0.1"} for host in b_targets):
        return False
    if chain == "socks5-http":
        return all(item.get("kind") == "socks5" for item in hop_a) and all(
            item.get("kind") == "http" for item in hop_b
        )
    return all(item.get("kind") == "http" for item in hop_a) and all(
        item.get("kind") == "socks5" for item in hop_b
    )


def exercise(binary, scratch: Path, snell_authority: Path, vmess_authority: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    half_close = start_server(HalfCloseHandler)
    socks_a = RecordingSocks5Proxy("hop-a-socks")
    http_b = RecordingHttpProxy("hop-b-http")
    http_a = RecordingHttpProxy("hop-a-http")
    socks_b = RecordingSocks5Proxy("hop-b-socks")
    snell_port = reserve_port()
    authority_process = None
    authority_stdout = None
    authority_stderr = None
    trojan = TrojanAuthority()
    vless = VlessAuthority()
    vmess_port = reserve_port()
    vmess_process = None
    vmess_stdout = None
    vmess_stderr = None
    vmess_log = None
    try:
        authority_process, authority_stdout, authority_stderr = start_snell_authority(
            snell_authority,
            scratch / "snell-authority",
            snell_port,
            SNELL_PSK,
            2,
        )
        trojan.start()
        vless.start()
        (scratch / "vmess-authority").mkdir(parents=True, exist_ok=True)
        vmess_process, vmess_stdout, vmess_stderr, vmess_log = start_vmess_authority(
            vmess_authority,
            scratch / "vmess-authority",
            vmess_port,
        )

        def trojan_ready() -> None:
            with trojan.lock:
                trojan.observations.clear()

        def trojan_saw() -> bool:
            return any(
                f"CONNECT {PROTOCOL_DEST_HOST}:{PROTOCOL_DEST_PORT}" in item
                for item in trojan.snapshot()
            )

        def vless_ready() -> None:
            with vless.lock:
                vless.observations.clear()

        def vless_saw() -> bool:
            with vless.lock:
                observed = set(vless.observations)
            return any(
                f"CONNECT {PROTOCOL_DEST_HOST}:{PROTOCOL_DEST_PORT}" in item
                for item in observed
            )

        def vmess_ready() -> None:
            if vmess_log is not None and vmess_log.exists():
                # Truncate observation window by noting current size.
                vmess_ready.offset = vmess_log.stat().st_size  # type: ignore[attr-defined]

        def vmess_saw() -> bool:
            if vmess_log is None or not vmess_log.exists():
                return False
            offset = getattr(vmess_ready, "offset", 0)
            text = vmess_log.read_text(errors="replace")[offset:]
            needle = f"{PROTOCOL_DEST_HOST}:{PROTOCOL_DEST_PORT}"
            return needle in text

        return {
            "socks5-http": run_chain(
                binary,
                scratch,
                chain="socks5-http",
                hop_a=socks_a,
                hop_b=http_b,
                echo_port=echo.port,
            ),
            "http-socks5": run_chain(
                binary,
                scratch,
                chain="http-socks5",
                hop_a=http_a,
                hop_b=socks_b,
                echo_port=echo.port,
            ),
            "socks5-snell-half-close": run_socks5_snell_half_close(
                binary,
                scratch,
                hop_a=socks_a,
                snell_port=snell_port,
                half_close_port=half_close.port,
            ),
            "socks5-trojan": run_socks5_protocol_b(
                binary,
                scratch,
                label="socks5-trojan",
                hop_a=socks_a,
                config_prefix=trojan_roots(),
                hop_b_yaml=f"""  - name: hop-b
    type: trojan
    server: 127.0.0.1
    port: {trojan.port}
    password: {TROJAN_PASSWORD}
    sni: dot.phase4.test
    alpn: [h2, http/1.1]
    dialer-proxy: hop-a
""",
                authority_ready=trojan_ready,
                authority_saw_dest=trojan_saw,
            ),
            "socks5-vless": run_socks5_protocol_b(
                binary,
                scratch,
                label="socks5-vless",
                hop_a=socks_a,
                hop_b_yaml=f"""  - name: hop-b
    type: vless
    server: 127.0.0.1
    port: {vless.port}
    uuid: {VLESS_UUID}
    dialer-proxy: hop-a
""",
                authority_ready=vless_ready,
                authority_saw_dest=vless_saw,
            ),
            "socks5-vmess": run_socks5_protocol_b(
                binary,
                scratch,
                label="socks5-vmess",
                hop_a=socks_a,
                hop_b_yaml=f"""  - name: hop-b
    type: vmess
    server: 127.0.0.1
    port: {vmess_port}
    uuid: {VMESS_UUID}
    alterId: 0
    cipher: auto
    dialer-proxy: hop-a
""",
                authority_ready=vmess_ready,
                authority_saw_dest=vmess_saw,
            ),
            "reject-missing-ref": ConfigReject.check(binary, scratch),
        }
    finally:
        if authority_process is not None:
            stop(authority_process)
        if authority_stdout is not None:
            authority_stdout.close()
        if authority_stderr is not None:
            authority_stderr.close()
        if vmess_process is not None:
            stop(vmess_process)
        if vmess_stdout is not None:
            vmess_stdout.close()
        if vmess_stderr is not None:
            vmess_stderr.close()
        trojan.close()
        vless.close()
        socks_a.close()
        http_b.close()
        http_a.close()
        socks_b.close()
        echo.close()
        half_close.close()


class ConfigReject:
    @staticmethod
    def check(binary, scratch: Path) -> dict[str, Any]:
        # Both binaries must refuse a missing dialer-proxy at -t / load time.
        config = scratch / "missing.yaml"
        config.write_text(
            """mixed-port: 0
mode: rule
log-level: info
ipv6: false
proxies:
  - name: hop-b
    type: http
    server: 127.0.0.1
    port: 1
    dialer-proxy: does-not-exist
rules:
  - MATCH,DIRECT
"""
        )
        result = subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=IO_DEADLINE,
        )
        text = (result.stderr + result.stdout).decode("utf-8", "replace").lower()
        return {
            "exit-nonzero": result.returncode != 0,
            "mentions-missing": "not found" in text
            or "does-not-exist" in text
            or "dialer" in text,
        }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase7t1-dialer-proxy-") as temporary:
        root = Path(temporary)
        profile = build_profile()
        binaries = build_binaries(root, CARGO_TARGET_ENV, CARGO_TARGET_NAME)
        authority = snell_authority_binary(profile)
        if not authority.exists():
            raise RuntimeError(
                "rewrite-snell-authority was not built: "
                f"{authority} (profile={profile})"
            )
        vmess_authority = build_vmess_authority(root)
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch, authority, vmess_authority)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "error": f"{type(error).__name__}: {error}",
                        "observations": observations,
                        "debug": debug_files(root),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            raise
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    for side in ("go", "rust"):
        for chain in ("socks5-http", "http-socks5"):
            result = observations[side][chain]
            if not (
                result["echo"]
                and result["path-ok"]
                and result["large-echo"]
                and result["a-saw-b-server"]
                and result["b-saw-echo"]
                and result["survived"]
            ):
                FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
                FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
                return 1
        half = observations[side]["socks5-snell-half-close"]
        if not (
            half["half-close"] and half["a-saw-snell-server"] and half["survived"]
        ):
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            return 1
        for protocol in ("socks5-trojan", "socks5-vless", "socks5-vmess"):
            result = observations[side][protocol]
            if not (
                result["echo"]
                and result["a-saw-b-server"]
                and result["b-saw-dest"]
                and result["survived"]
            ):
                FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
                FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
                return 1
        if not observations[side]["reject-missing-ref"]["exit-nonzero"]:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 7T1-A TCP dialer-proxy differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

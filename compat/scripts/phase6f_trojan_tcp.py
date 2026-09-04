#!/usr/bin/env python3
"""Go/Rust differential for Phase 6F-A Trojan native TCP over TLS."""

from __future__ import annotations

import hashlib
import json
import pathlib
import socket
import socketserver
import ssl
import tempfile
import textwrap
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, connect_domain, debug_files
from phase6e_vless_tcp import rejected_exchange


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6f-trojan-tcp-diff.json"
PASSWORD = "phase6f-password"
LARGE_PAYLOAD = bytes(range(256)) * 512


class TrojanHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        stream: socket.socket = self.request
        try:
            password = recv_exact(stream, 56).decode()
            if recv_exact(stream, 2) != b"\r\n":
                return
            command = recv_exact(stream, 1)[0]
            address_type = recv_exact(stream, 1)[0]
            if address_type == 1:
                host = socket.inet_ntop(socket.AF_INET, recv_exact(stream, 4))
            elif address_type == 4:
                host = socket.inet_ntop(socket.AF_INET6, recv_exact(stream, 16))
            elif address_type == 3:
                host = recv_exact(stream, recv_exact(stream, 1)[0]).decode()
            else:
                return
            port = int.from_bytes(recv_exact(stream, 2), "big")
            if recv_exact(stream, 2) != b"\r\n":
                return
        except (EOFError, OSError, UnicodeError):
            return
        authority: TrojanAuthority = self.server.authority
        authority.observe(f"CONNECT {host}:{port} COMMAND {command}")
        if password != hashlib.sha224(PASSWORD.encode()).hexdigest() or command != 1:
            return
        while True:
            payload = stream.recv(64 * 1024)
            if not payload:
                return
            stream.sendall(payload)


class TrojanServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, authority: "TrojanAuthority") -> None:
        self.authority = authority
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        self.context.set_alpn_protocols(["h2", "http/1.1"])
        self.context.set_servername_callback(
            lambda stream, name, _context: authority.observe(f"TLS {name or '<none>'}")
        )
        super().__init__(("127.0.0.1", 0), TrojanHandler)

    def get_request(self) -> tuple[socket.socket, Any]:
        stream, address = super().get_request()
        try:
            tls = self.context.wrap_socket(stream, server_side=True)
            self.authority.observe(f"ALPN {tls.selected_alpn_protocol() or '<none>'}")
            return tls, address
        except Exception:
            stream.close()
            raise


class TrojanAuthority:
    def __init__(self) -> None:
        self.observations: set[str] = set()
        self.lock = threading.Lock()
        self.server = TrojanServer(self)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def observe(self, value: str) -> None:
        with self.lock:
            self.observations.add(value)

    def snapshot(self) -> list[str]:
        with self.lock:
            return sorted(self.observations)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def roots() -> str:
    root = pathlib.Path(ROOT_CERTIFICATE).read_text().strip()
    return "tls:\n  custom-certifactes:\n    - |-\n" + textwrap.indent(root, "      ") + "\n"


def exchange(port: int, host: str, target_port: int, payload: bytes, half_close: bool) -> bool:
    with connect_domain(port, host, target_port) as stream:
        stream.settimeout(IO_DEADLINE)
        stream.sendall(payload)
        if half_close:
            stream.shutdown(socket.SHUT_WR)
        return recv_exact(stream, len(payload)) == payload


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority = TrojanAuthority()
    authority.start()
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        roots()
        + f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: trojan-native
    type: trojan
    server: 127.0.0.1
    port: {authority.port}
    password: {PASSWORD}
    sni: dot.phase4.test
    alpn: [h2, http/1.1]
  - name: trojan-wrong-password
    type: trojan
    server: 127.0.0.1
    port: {authority.port}
    password: wrong-password
    sni: dot.phase4.test
    alpn: [h2, http/1.1]
rules:
  - DST-PORT,28004,trojan-wrong-password
  - MATCH,trojan-native
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        deadline = time.monotonic() + IO_DEADLINE
        while True:
            try:
                small = exchange(mixed_port, "trojan.phase6f", 28001, b"trojan", False)
                break
            except (AssertionError, EOFError, OSError):
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
        large = exchange(mixed_port, "large.phase6f", 28002, LARGE_PAYLOAD, False)
        half_close = exchange(mixed_port, "half.phase6f", 28003, b"half-close", True)
        wrong_password = rejected_exchange(mixed_port, "wrong.phase6f", 28004)
        return {
            "small": small,
            "large": large,
            "half-close": half_close,
            "wrong-password-rejected": wrong_password,
            "process-alive": process.poll() is None,
            "wire": authority.snapshot(),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6f-trojan-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6FTROJAN_CARGO_TARGET", "phase6f-trojan")
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], scratch)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(json.dumps({
                "error": f"{type(error).__name__}: {error}",
                "observations": observations,
                "debug": debug_files(root),
            }, indent=2, sort_keys=True))
            raise
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6F-A Trojan native-TLS differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

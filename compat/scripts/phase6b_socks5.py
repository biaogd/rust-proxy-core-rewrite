#!/usr/bin/env python3
"""Go/Rust differential for one authenticated SOCKS5 TCP outbound."""

from __future__ import annotations

import ipaddress
import json
import selectors
import socket
import socketserver
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, recv_exact, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files
from phase5d_proxies import normalize, request
from phase5d_streams import wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6b-socks5-diff.json"


class Socks5Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        version, count = recv_exact(self.request, 2)
        methods = list(recv_exact(self.request, count))
        observation: dict[str, Any] = {"methods": methods}
        self.server.observations.append(observation)
        if version != 5 or 2 not in methods:
            self.request.sendall(b"\x05\xff")
            return
        self.request.sendall(b"\x05\x02")
        auth_version, username_length = recv_exact(self.request, 2)
        username = recv_exact(self.request, username_length).decode()
        password_length = recv_exact(self.request, 1)[0]
        password = recv_exact(self.request, password_length).decode()
        accepted = auth_version == 1 and username == "proxy-user" and password == "proxy-pass"
        self.request.sendall(bytes((1, 0 if accepted else 1)))
        if not accepted:
            return
        request_version, command, reserved, address_type = recv_exact(self.request, 4)
        if address_type == 1:
            host = str(ipaddress.ip_address(recv_exact(self.request, 4)))
        elif address_type == 4:
            host = str(ipaddress.ip_address(recv_exact(self.request, 16)))
        elif address_type == 3:
            host = recv_exact(self.request, recv_exact(self.request, 1)[0]).decode()
        else:
            return
        port = int.from_bytes(recv_exact(self.request, 2), "big")
        observation.update(
            {
                "username": username,
                "password": password,
                "request": [request_version, command, reserved],
                "address-type": address_type,
                "target": f"{host}:<port>",
            }
        )
        with socket.create_connection((host, port), timeout=5) as upstream:
            self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            relay(self.request, upstream)


class Socks5Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), Socks5Handler)
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


def proxied_route(mixed_port: int, echo_port: int) -> bool:
    with connect_domain(mixed_port, "localhost", echo_port) as stream:
        stream.sendall(b"socks-outbound")
        try:
            return recv_exact(stream, 14) == b"socks-outbound"
        except (EOFError, ConnectionResetError):
            return False


def wait_proxy_route(process, mixed_port: int, echo_port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during readiness with {process.returncode}")
        try:
            if proxied_route(mixed_port, echo_port):
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError("SOCKS5 outbound did not become ready")


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    upstream = Socks5Server()
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-socks
    type: socks5
    server: 127.0.0.1
    port: {upstream.port}
    username: proxy-user
    password: proxy-pass
rules:
  - DOMAIN,localhost,local-socks
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        adapter = request(controller_port, "GET", "/proxies/local-socks")
        wait_proxy_route(process, mixed_port, echo.port)
        upstream.observations.clear()
        echoed = proxied_route(mixed_port, echo.port)
        with connect_domain(mixed_port, "127.0.0.1", echo.port) as stream:
            try:
                stream.sendall(b"reject")
                rejected = stream.recv(1) == b""
            except (BrokenPipeError, ConnectionResetError):
                rejected = True
        return {
            "adapter": (adapter[0], normalize(json.loads(adapter[1]))),
            "echo": echoed,
            "fallback-rejected": rejected,
            "upstream": upstream.observations,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        upstream.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6b-socks5-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(root, "PHASE6BSOCKS_CARGO_TARGET", "phase6b-socks5")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
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
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6B authenticated SOCKS5 TCP outbound differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

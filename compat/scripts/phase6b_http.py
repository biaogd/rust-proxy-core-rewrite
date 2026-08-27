#!/usr/bin/env python3
"""Go/Rust differential for one plaintext HTTP CONNECT outbound."""

from __future__ import annotations

import base64
import json
import selectors
import socket
import socketserver
import tempfile
import threading
from typing import Any

from phase1 import EchoHandler, ROOT, recv_exact, recv_until, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6b-http-diff.json"
AUTHORIZATION = "Basic " + base64.b64encode(b"proxy-user:proxy-pass").decode()


class ConnectProxyHandler(socketserver.BaseRequestHandler):
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
                "method": method,
                "target": target,
                "host": headers.get("host"),
                "authorization": headers.get("proxy-authorization"),
            }
        )
        if method != "CONNECT" or headers.get("proxy-authorization") != AUTHORIZATION:
            self.request.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            return
        host, port = target.rsplit(":", 1)
        with socket.create_connection((host.strip("[]"), int(port)), timeout=5) as upstream:
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            relay(self.request, upstream)


class ConnectProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), ConnectProxyHandler)
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


def exercise(binary, scratch) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    upstream = ConnectProxyServer()
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-http
    type: http
    server: 127.0.0.1
    port: {upstream.port}
    username: proxy-user
    password: proxy-pass
rules:
  - DOMAIN,localhost,local-http
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        with connect_domain(mixed_port, "localhost", echo.port) as stream:
            stream.sendall(b"http-outbound")
            echoed = recv_exact(stream, 13) == b"http-outbound"
        with connect_domain(mixed_port, "127.0.0.1", echo.port) as stream:
            try:
                stream.sendall(b"reject")
                rejected = stream.recv(1) == b""
            except (BrokenPipeError, ConnectionResetError):
                rejected = True
        normalized_upstream = []
        for observation in upstream.observations:
            normalized = dict(observation)
            normalized["target"] = normalized["target"].rsplit(":", 1)[0] + ":<port>"
            normalized["host"] = normalized["host"].rsplit(":", 1)[0] + ":<port>"
            normalized_upstream.append(normalized)
        return {
            "echo": echoed,
            "fallback-rejected": rejected,
            "upstream": normalized_upstream,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        upstream.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6b-http-") as temporary:
        from pathlib import Path

        root = Path(temporary)
        binaries = build_binaries(root, "PHASE6BHTTP_CARGO_TARGET", "phase6b-http")
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
    print("Phase 6B plaintext HTTP CONNECT outbound differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for the Phase 6B1c HTTP CONNECT contract."""

from __future__ import annotations

import base64
import json
import pathlib
import selectors
import socket
import socketserver
import tempfile
import threading
import time
from typing import Any

from phase1 import (
    IO_DEADLINE,
    EchoHandler,
    ROOT,
    recv_exact,
    recv_until,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6b-http-contract-diff.json"
AUTHORIZATION = "Basic " + base64.b64encode(b"proxy-user:proxy-pass").decode()


class ConnectHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            request = recv_until(self.request, b"\r\n\r\n")
        except (EOFError, OSError):
            return
        lines = request.decode("latin1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = {
            name.lower(): value.strip()
            for line in lines[1:]
            if ":" in line
            for name, value in [line.split(":", 1)]
        }
        host = headers.get("host")
        if host is not None and host.startswith("127.0.0.1:"):
            host = "127.0.0.1:<port>"
        self.server.observations.append(
            {
                "method": method,
                "target": target.rsplit(":", 1)[0] + ":<port>",
                "host": host,
                "authorization": headers.get("proxy-authorization"),
                "user-agent": headers.get("user-agent"),
                "proxy-connection": headers.get("proxy-connection"),
                "x-phase": headers.get("x-phase"),
            }
        )
        if self.server.response_mode == "close":
            return
        if self.server.response_mode == "malformed":
            self.request.sendall(b"not-an-http-response\r\n\r\n")
            return
        if self.server.response_mode == "delayed":
            time.sleep(0.25)
        status = self.server.status
        if status != 200:
            self.request.sendall(
                f"HTTP/1.1 {status} fixture-status\r\nContent-Length: 0\r\n\r\n".encode()
            )
            return
        host, port = target.rsplit(":", 1)
        with socket.create_connection((host.strip("[]"), int(port)), timeout=5) as upstream:
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            relay(self.request, upstream)


class ConnectServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, status: int, response_mode: str = "status") -> None:
        self.status = status
        self.response_mode = response_mode
        self.observations: list[dict[str, Any]] = []
        super().__init__(("127.0.0.1", 0), ConnectHandler)
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
            data = key.fileobj.recv(65_536)
            if not data:
                return
            key.data.sendall(data)


def render_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    proxy_port: int,
    credentials: str,
    custom_headers: bool,
) -> None:
    if credentials == "both":
        credentials = "    username: proxy-user\n    password: proxy-pass\n"
    elif credentials == "user":
        credentials = "    username: proxy-user\n"
    elif credentials == "password":
        credentials = "    password: proxy-pass\n"
    else:
        credentials = ""
    headers = ""
    if custom_headers:
        headers = """    headers:
      Host: override.phase6b.test:9443
      User-Agent: phase6b-custom
      Proxy-Connection: close
      X-Phase: contract
      Proxy-Authorization: Basic d3Jvbmc6d3Jvbmc=
"""
    path.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-http
    type: http
    server: 127.0.0.1
    port: {proxy_port}
{credentials}{headers}rules:
  - MATCH,local-http
"""
    )


def try_route(mixed_port: int, echo_port: int) -> bool:
    try:
        with connect_domain(mixed_port, "localhost", echo_port) as stream:
            stream.sendall(b"http-contract")
            return recv_exact(stream, 13) == b"http-contract"
    except (EOFError, OSError):
        return False


def wait_route(process, mixed_port: int, echo_port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during HTTP contract readiness with {process.returncode}")
        if try_route(mixed_port, echo_port):
            return
        time.sleep(0.02)
    raise TimeoutError("HTTP contract outbound did not become ready")


def wait_observation(process, proxy: ConnectServer, mixed_port: int, echo_port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if proxy.observations:
            return
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during HTTP status observation with {process.returncode}")
        try_route(mixed_port, echo_port)
        time.sleep(0.02)
    raise TimeoutError("HTTP proxy did not observe CONNECT")


def collapse_retries(values: list[Any]) -> list[Any]:
    if values and all(value == values[0] for value in values):
        return values[:1]
    return values


def exercise_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    status: int,
    credentials: str = "none",
    custom_headers: bool = False,
    response_mode: str = "status",
) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    proxy = ConnectServer(status, response_mode)
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        proxy_port=proxy.port,
        credentials=credentials,
        custom_headers=custom_headers,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        if status == 200 and response_mode in ("status", "delayed"):
            wait_route(process, mixed_port, echo.port)
            proxy.observations.clear()
        routed = try_route(mixed_port, echo.port)
        wait_observation(process, proxy, mixed_port, echo.port)
        return {
            "routed": routed,
            "process-alive": process.poll() is None,
            "connect": collapse_retries(proxy.observations),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        proxy.close()
        echo.close()


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    cases = {
        "no-auth-defaults": (200, "none", False, "status"),
        "user-only": (200, "user", False, "status"),
        "password-only": (200, "password", False, "status"),
        "custom-headers": (200, "both", True, "status"),
        "delayed-response": (200, "none", False, "delayed"),
        "closed-response": (200, "none", False, "close"),
        "malformed-response": (200, "none", False, "malformed"),
        "status-204": (204, "none", False, "status"),
        "status-301": (301, "none", False, "status"),
        "status-400": (400, "none", False, "status"),
        "status-405": (405, "none", False, "status"),
        "status-407": (407, "none", False, "status"),
        "status-500": (500, "none", False, "status"),
    }
    observations = {}
    for name, (status, credentials, custom_headers, response_mode) in cases.items():
        case = scratch / name
        case.mkdir(parents=True)
        observations[name] = exercise_case(
            binary,
            case,
            status=status,
            credentials=credentials,
            custom_headers=custom_headers,
            response_mode=response_mode,
        )
    return observations


def satisfies_contract(observation: dict[str, Any]) -> bool:
    defaults = observation["no-auth-defaults"]
    custom = observation["custom-headers"]
    return (
        defaults["routed"] is True
        and defaults["connect"]
        == [
            {
                "method": "CONNECT",
                "target": "127.0.0.1:<port>",
                "host": "127.0.0.1:<port>",
                "authorization": None,
                "user-agent": "Go-http-client/1.1",
                "proxy-connection": "Keep-Alive",
                "x-phase": None,
            }
        ]
        and custom["routed"] is True
        and custom["connect"]
        == [
            {
                "method": "CONNECT",
                "target": "127.0.0.1:<port>",
                "host": "override.phase6b.test:9443",
                "authorization": AUTHORIZATION,
                "user-agent": "phase6b-custom",
                "proxy-connection": "close",
                "x-phase": "contract",
            }
        ]
        and all(
            observation[name]["routed"] is True
            and observation[name]["connect"][0]["authorization"] is None
            for name in ("user-only", "password-only")
        )
        and observation["delayed-response"]["routed"] is True
        and all(
            observation[name]["routed"] is False
            and len(observation[name]["connect"]) == 1
            for name in ("closed-response", "malformed-response")
        )
        and all(
            observation[name]["routed"] is False
            and len(observation[name]["connect"]) == 1
            for name in observation
            if name.startswith("status-")
        )
        and all(case["process-alive"] for case in observation.values())
    )


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6b-http-contract-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6BHTTPCONTRACT_CARGO_TARGET", "phase6b-http-contract")
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
    if observations["go"] != observations["rust"] or not satisfies_contract(observations["go"]):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6B1c HTTP CONNECT request/response contract differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

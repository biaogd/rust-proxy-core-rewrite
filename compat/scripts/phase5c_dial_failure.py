#!/usr/bin/env python3
"""Go/Rust differential for group dial-failure health activation."""

from __future__ import annotations

import json
import os
import socket
import socketserver
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, ROOT, recv_until, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_health_schedule import health_snapshot, wait_health
from phase5c_load_balance import proxy_route
from phase5c_selector import route
from phase5d_proxies import request, start_health_server
from phase5d_streams import wait_controller
from phase6b_http import AUTHORIZATION, relay


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-dial-failure-diff.json"


class ToggleProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        request_bytes = recv_until(self.request, b"\r\n\r\n")
        lines = request_bytes.decode("latin1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = {
            name.lower(): value.strip()
            for line in lines[1:]
            if ":" in line
            for name, value in [line.split(":", 1)]
        }
        server: ToggleProxyServer = self.server  # type: ignore[assignment]
        server.observations.append({"method": method, "target": target})
        if headers.get("proxy-authorization") != AUTHORIZATION:
            self.request.sendall(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            return
        if server.rejecting.is_set():
            self.request.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
            )
            return
        host, port = target.rsplit(":", 1)
        with socket.create_connection((host.strip("[]"), int(port)), timeout=5) as upstream:
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            relay(self.request, upstream)


class ToggleProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), ToggleProxyHandler)
        self.observations: list[dict[str, Any]] = []
        self.rejecting = threading.Event()
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def reject(self) -> None:
        self.rejecting.set()

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)


def render_config(
    path: Path,
    *,
    mixed_port: int,
    controller_port: int,
    first_port: int,
    second_port: int,
    health_url: str,
    timeout: int,
    max_failed_times: int,
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: proxy-a
    type: http
    server: 127.0.0.1
    port: {first_port}
    username: proxy-user
    password: proxy-pass
  - name: proxy-b
    type: http
    server: 127.0.0.1
    port: {second_port}
    username: proxy-user
    password: proxy-pass
proxy-groups:
  - name: recovery
    type: fallback
    proxies: [proxy-a, proxy-b]
    url: {health_url}
    expected-status: '204'
    interval: 600
    timeout: {timeout}
    max-failed-times: {max_failed_times}
    lazy: true
rules:
  - MATCH,recovery
"""
    )


def failed_route(mixed_port: int, echo_port: int) -> bool:
    return route(mixed_port, echo_port) == "reject"


def exercise_threshold(
    binary: Path, scratch: Path, *, max_failed_times: int, should_activate: bool
) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    health = start_health_server()
    first = ToggleProxyServer()
    second = ToggleProxyServer()
    mixed_port, controller_port = reserve_port(), reserve_port()
    health_url = f"http://127.0.0.1:{health.server_port}/generate_204"
    timeout = 1000
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        controller_port=controller_port,
        first_port=first.port,
        second_port=second.port,
        health_url=health_url,
        timeout=timeout,
        max_failed_times=max_failed_times,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        initial = wait_health(process, controller_port, "proxy-a", health_url, True)
        # Go coalesces provider health checks for one second. Let the startup
        # result leave that window so a dial-failure activation is observable.
        time.sleep(1.1)
        first.reject()

        _ = failed_route(mixed_port, echo.port)
        if should_activate:
            failed = wait_health(
                process, controller_port, "proxy-a", health_url, False
            )
            health_contract = not failed[0] and failed[1] > initial[1]
            routed = proxy_route(mixed_port, echo.port, first, second)
        else:
            time.sleep(0.3)
            health_contract = (
                health_snapshot(controller_port, "proxy-a", health_url) == initial
            )
            routed = None
        return {
            "max-failed-times": max_failed_times,
            "activation-contract": health_contract,
            "survivor-route": None if routed is None else routed == "proxy-b",
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        first.close()
        second.close()
        health.shutdown()
        health.server_close()
        echo.close()


def exercise_refused(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    health = start_health_server()
    first = ToggleProxyServer()
    second = ToggleProxyServer()
    first_closed = False
    mixed_port, controller_port = reserve_port(), reserve_port()
    health_url = f"http://127.0.0.1:{health.server_port}/generate_204"
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        controller_port=controller_port,
        first_port=first.port,
        second_port=second.port,
        health_url=health_url,
        timeout=300,
        max_failed_times=99,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        initial = wait_health(process, controller_port, "proxy-a", health_url, True)
        time.sleep(1.1)
        first.close()
        first_closed = True
        _ = failed_route(mixed_port, echo.port)
        if os.name == "nt":
            # The pinned Go oracle detects this special case with a literal
            # "connection refused" substring. Winsock renders WSAECONNREFUSED
            # as "actively refused it", so Windows follows the ordinary
            # failure counter and does not activate at max-failed-times=99.
            time.sleep(0.5)
            failed = health_snapshot(controller_port, "proxy-a", health_url)
            routed = None
        else:
            failed = wait_health(
                process, controller_port, "proxy-a", health_url, False
            )
            routed = proxy_route(mixed_port, echo.port, first, second)
        return {
            "health-triggered": not failed[0] and failed[1] > initial[1],
            "survivor-route": None if routed is None else routed == "proxy-b",
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        if not first_closed:
            first.close()
        second.close()
        health.shutdown()
        health.server_close()
        echo.close()


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    observations = {}
    for name, max_failed_times, should_activate in (
        ("threshold", 2, True),
        ("below-threshold", 99, False),
    ):
        case = scratch / name
        case.mkdir()
        observations[name] = exercise_threshold(
            binary,
            case,
            max_failed_times=max_failed_times,
            should_activate=should_activate,
        )
    refused = scratch / "connection-refused"
    refused.mkdir()
    observations["connection-refused"] = exercise_refused(binary, refused)
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-dial-failure-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CDIALFAILURE_CARGO_TARGET",
            "phase5c-dial-failure",
        )
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
    print("Phase 5C dial-failure health activation differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for URL-test selection, control and routing."""

from __future__ import annotations

import json
import socketserver
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_selector import route
from phase5d_proxies import request, start_health_server
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyHandler


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-url-test-diff.json"


class DelayedConnectProxyHandler(ConnectProxyHandler):
    def handle(self) -> None:
        time.sleep(self.server.connect_delay)
        super().handle()


class DelayedConnectProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, delay: float) -> None:
        super().__init__(("127.0.0.1", 0), DelayedConnectProxyHandler)
        self.connect_delay = delay
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


def snapshot(controller_port: int, health_url: str) -> dict[str, Any]:
    status, body = request(controller_port, "GET", "/group/speed")
    if status != 200:
        raise AssertionError((status, body))
    value = json.loads(body)
    if value["testUrl"] != health_url:
        raise AssertionError(value["testUrl"])
    return {
        "all": value["all"],
        "emptyFallback": value["emptyFallback"],
        "expectedStatus": value["expectedStatus"],
        "fixed": value["fixed"],
        "hidden": value["hidden"],
        "icon": value["icon"],
        "now": value["now"],
        "testUrl": "health-url",
        "type": value["type"],
        "udp": value["udp"],
    }


def wait_snapshot(
    controller_port: int,
    health_url: str,
    now: str,
    fixed: str,
) -> dict[str, Any]:
    deadline = time.monotonic() + IO_DEADLINE
    current: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        current = snapshot(controller_port, health_url)
        if current["now"] == now and current["fixed"] == fixed:
            return current
        time.sleep(0.02)
    raise TimeoutError(f"URL-test did not become {now}/{fixed}: {current}")


def select(controller_port: int, member: str) -> tuple[int, bool]:
    status, body = request(
        controller_port,
        "PUT",
        "/proxies/speed",
        {"name": member},
    )
    return status, body == b""


def route_kind(
    mixed_port: int,
    echo_port: int,
    slow: DelayedConnectProxyServer,
    fast: DelayedConnectProxyServer,
) -> str:
    slow.observations.clear()
    fast.observations.clear()
    if route(mixed_port, echo_port) != "proxy":
        return "failed"
    suffix = f":{echo_port}"
    fast_route = any(item["target"].endswith(suffix) for item in fast.observations)
    slow_route = any(item["target"].endswith(suffix) for item in slow.observations)
    if fast_route and not slow_route:
        return "fast-http"
    if slow_route and not fast_route:
        return "slow-http"
    return "unexpected"


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    health = start_health_server()
    slow = DelayedConnectProxyServer(0.18)
    fast = DelayedConnectProxyServer(0.01)
    mixed_port, controller_port = reserve_port(), reserve_port()
    health_url = f"http://127.0.0.1:{health.server_port}/generate_204"
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
profile:
  store-selected: true
proxies:
  - name: slow-http
    type: http
    server: 127.0.0.1
    port: {slow.port}
    username: proxy-user
    password: proxy-pass
  - name: fast-http
    type: http
    server: 127.0.0.1
    port: {fast.port}
    username: proxy-user
    password: proxy-pass
proxy-groups:
  - name: speed
    type: url-test
    proxies: [slow-http, fast-http]
    url: {health_url}
    expected-status: '204'
    tolerance: 20
    hidden: true
    icon: speed.svg
    disable-udp: true
rules:
  - MATCH,speed
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        time.sleep(1.1)
        healthcheck = request(
            controller_port,
            "GET",
            "/providers/proxies/speed/healthcheck",
        )
        automatic = wait_snapshot(controller_port, health_url, "fast-http", "")
        automatic_route = route_kind(mixed_port, echo.port, slow, fast)
        fixed_status = select(controller_port, "slow-http")
        fixed = wait_snapshot(controller_port, health_url, "slow-http", "slow-http")
        fixed_route = route_kind(mixed_port, echo.port, slow, fast)
        invalid = select(controller_port, "missing")
        after_invalid = snapshot(controller_port, health_url)
    finally:
        stop(process)
        stdout.close()
        stderr.close()

    restarted, restart_stdout, restart_stderr = launch(binary, config, scratch)
    try:
        wait_ready(restarted, mixed_port)
        wait_controller(restarted, controller_port)
        restored = wait_snapshot(controller_port, health_url, "slow-http", "slow-http")
        restored_route = route_kind(mixed_port, echo.port, slow, fast)
        query = urllib.parse.urlencode(
            {"url": health_url, "timeout": "1000", "expected": "204"}
        )
        delay_status, delay_body = request(
            controller_port,
            "GET",
            f"/group/speed/delay?{query}",
        )
        delay_value = json.loads(delay_body)
        group_delay = {
            "status": delay_status,
            "keys": sorted(delay_value),
            "all-positive": all(value > 0 for value in delay_value.values()),
        }
        unfixed = wait_snapshot(controller_port, health_url, "fast-http", "")
        unfixed_route = route_kind(mixed_port, echo.port, slow, fast)
    finally:
        stop(restarted)
        restart_stdout.close()
        restart_stderr.close()
        slow.close()
        fast.close()
        health.shutdown()
        health.server_close()
        echo.close()
    return {
        "healthcheck": (healthcheck[0], healthcheck[1] == b""),
        "automatic": automatic,
        "automatic-route": automatic_route,
        "fixed-status": fixed_status,
        "fixed": fixed,
        "fixed-route": fixed_route,
        "invalid": invalid,
        "after-invalid": after_invalid,
        "restored": restored,
        "restored-route": restored_route,
        "group-delay": group_delay,
        "unfixed": unfixed,
        "unfixed-route": unfixed_route,
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-url-test-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(root, "PHASE5CURLTEST_CARGO_TARGET", "phase5c-url-test")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
        except Exception as exception:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "error": f"{type(exception).__name__}: {exception}",
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
    print("Phase 5C URL-test differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

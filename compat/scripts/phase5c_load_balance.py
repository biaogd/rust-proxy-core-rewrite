#!/usr/bin/env python3
"""Go/Rust differential for round-robin load-balance groups."""

from __future__ import annotations

import json
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_selector import route
from phase5d_proxies import request, start_health_server
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-load-balance-diff.json"


def snapshot(controller_port: int, health_url: str) -> dict[str, Any]:
    status, body = request(controller_port, "GET", "/group/balanced")
    if status != 200:
        raise AssertionError((status, body))
    value = json.loads(body)
    if value["testUrl"] != health_url:
        raise AssertionError(value["testUrl"])
    return {
        "all": value["all"],
        "emptyFallback": value["emptyFallback"],
        "expectedStatus": value["expectedStatus"],
        "has-fixed": "fixed" in value,
        "has-now": "now" in value,
        "hidden": value["hidden"],
        "icon": value["icon"],
        "testUrl": "health-url",
        "type": value["type"],
        "udp": value["udp"],
    }


def proxy_route(
    mixed_port: int,
    echo_port: int,
    first: ConnectProxyServer,
    second: ConnectProxyServer,
) -> str:
    first.observations.clear()
    second.observations.clear()
    if route(mixed_port, echo_port) != "proxy":
        return "failed"
    suffix = f":{echo_port}"
    first_route = any(item["target"].endswith(suffix) for item in first.observations)
    second_route = any(item["target"].endswith(suffix) for item in second.observations)
    if first_route and not second_route:
        return "proxy-a"
    if second_route and not first_route:
        return "proxy-b"
    return "unexpected"


def healthcheck(controller_port: int) -> tuple[int, bool]:
    status, body = request(
        controller_port,
        "GET",
        "/providers/proxies/balanced/healthcheck",
    )
    return status, body == b""


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    health = start_health_server()
    first = ConnectProxyServer()
    second = ConnectProxyServer()
    first_closed = False
    mixed_port, controller_port = reserve_port(), reserve_port()
    health_url = f"http://127.0.0.1:{health.server_port}/generate_204"
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: proxy-a
    type: http
    server: 127.0.0.1
    port: {first.port}
    username: proxy-user
    password: proxy-pass
  - name: proxy-b
    type: http
    server: 127.0.0.1
    port: {second.port}
    username: proxy-user
    password: proxy-pass
proxy-groups:
  - name: balanced
    type: load-balance
    strategy: round-robin
    proxies: [proxy-a, proxy-b]
    url: {health_url}
    expected-status: '204'
    hidden: true
    icon: balance.svg
    disable-udp: true
rules:
  - MATCH,balanced
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        time.sleep(1.1)
        initial_health = healthcheck(controller_port)
        view = snapshot(controller_port, health_url)
        sequence = [
            proxy_route(mixed_port, echo.port, first, second) for _ in range(4)
        ]
        put_status, put_body = request(
            controller_port,
            "PUT",
            "/proxies/balanced",
            {"name": "proxy-a"},
        )
        put_error = (put_status, json.loads(put_body)["message"])

        first.close()
        first_closed = True
        time.sleep(1.1)
        failure_health = healthcheck(controller_port)
        failover = [
            proxy_route(mixed_port, echo.port, first, second) for _ in range(3)
        ]
        query = urllib.parse.urlencode(
            {"url": health_url, "timeout": "1000", "expected": "204"}
        )
        delay_status, delay_body = request(
            controller_port,
            "GET",
            f"/group/balanced/delay?{query}",
        )
        delay_value = json.loads(delay_body)
        group_delay = {
            "status": delay_status,
            "keys": sorted(delay_value),
            "positive-b": delay_value.get("proxy-b", 0) > 0,
        }
        return {
            "initial-health": initial_health,
            "view": view,
            "sequence": sequence,
            "put-error": put_error,
            "failure-health": failure_health,
            "failover": failover,
            "group-delay": group_delay,
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


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-load-balance-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CLOADBALANCE_CARGO_TARGET",
            "phase5c-load-balance",
        )
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
    print("Phase 5C round-robin load-balance differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

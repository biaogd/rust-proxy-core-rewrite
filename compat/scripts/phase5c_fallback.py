#!/usr/bin/env python3
"""Go/Rust differential for manual-health fallback group routing."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_selector import route
from phase5d_proxies import request, start_health_server
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-fallback-diff.json"


def summary(controller_port: int, health_url: str) -> dict[str, Any]:
    status, body = request(controller_port, "GET", "/group/fallback-group")
    if status != 200:
        raise AssertionError((status, body))
    value = json.loads(body)
    if value["testUrl"] != health_url:
        raise AssertionError(value["testUrl"])
    result = {
        key: value[key]
        for key in (
            "all",
            "emptyFallback",
            "expectedStatus",
            "fixed",
            "hidden",
            "icon",
            "now",
            "testUrl",
            "type",
            "udp",
        )
    }
    result["testUrl"] = "health-url"
    return result


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    health_server = start_health_server()
    upstream = ConnectProxyServer()
    mixed_port, controller_port = reserve_port(), reserve_port()
    health_url = f"http://127.0.0.1:{health_server.server_port}/generate_204"
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: flaky-http
    type: http
    server: 127.0.0.1
    port: {upstream.port}
    username: proxy-user
    password: proxy-pass
proxy-groups:
  - name: fallback-group
    type: fallback
    proxies: [flaky-http, DIRECT]
    url: {health_url}
    expected-status: '204'
    hidden: true
    icon: https://assets.example.test/fallback.svg
    disable-udp: true
rules:
  - MATCH,fallback-group
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    upstream_closed = False
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        initial = summary(controller_port, health_url)
        initial_route = route(mixed_port, echo.port)
        upstream.close()
        upstream_closed = True
        # The Go compatible provider coalesces health checks for one second.
        # Cross that documented single-flight window before forcing the retry.
        time.sleep(1.1)

        healthcheck_status, healthcheck_body = request(
            controller_port,
            "GET",
            "/providers/proxies/fallback-group/healthcheck",
        )
        deadline = time.monotonic() + 5
        healthy = summary(controller_port, health_url)
        while healthy["now"] != "DIRECT" and time.monotonic() < deadline:
            time.sleep(0.02)
            healthy = summary(controller_port, health_url)
        healthy_route = route(mixed_port, echo.port)
        return {
            "initial": initial,
            "initial-route": initial_route,
            "healthcheck": {
                "status": healthcheck_status,
                "empty": healthcheck_body == b"",
            },
            "healthy": healthy,
            "healthy-route": healthy_route,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        health_server.shutdown()
        health_server.server_close()
        if not upstream_closed:
            upstream.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-fallback-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(root, "PHASE5CFALLBACK_CARGO_TARGET", "phase5c-fallback")
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
    print("Phase 5C fallback differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

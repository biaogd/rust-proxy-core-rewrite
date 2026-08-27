#!/usr/bin/env python3
"""Go/Rust differential for eager and lazy automatic group health checks."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_load_balance import proxy_route
from phase5d_proxies import request, start_health_server
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-health-schedule-diff.json"


def health_snapshot(controller_port: int, name: str, url: str) -> tuple[bool, int]:
    status, body = request(controller_port, "GET", f"/proxies/{name}")
    if status != 200:
        raise AssertionError((status, body))
    value = json.loads(body)
    health = value.get("extra", {}).get(url)
    if health is None:
        return bool(value["alive"]), 0
    return bool(health["alive"]), len(health["history"])


def wait_health(
    process,
    controller_port: int,
    name: str,
    url: str,
    expected: bool,
    require_record: bool = True,
) -> tuple[bool, int]:
    deadline = time.monotonic() + 7
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during health wait: {process.returncode}")
        health = health_snapshot(controller_port, name, url)
        if health[0] is expected and (health[1] > 0 or not require_record):
            return health
        time.sleep(0.05)
    raise TimeoutError((name, expected, health_snapshot(controller_port, name, url)))


def exercise_schedule(binary: Path, scratch: Path, lazy: bool) -> dict[str, Any]:
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
  - name: scheduled
    type: fallback
    proxies: [proxy-a, proxy-b]
    url: {health_url}
    expected-status: '204'
    interval: 1
    timeout: 500
    lazy: {str(lazy).lower()}
rules:
  - MATCH,scheduled
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        initial = wait_health(process, controller_port, "proxy-a", health_url, True)
        first.close()
        first_closed = True
        if lazy:
            time.sleep(2.2)
            skipped = health_snapshot(controller_port, "proxy-a", health_url)
            lazy_skipped = skipped == initial
            proxy_route(mixed_port, echo.port, first, second)
            failed = wait_health(process, controller_port, "proxy-a", health_url, False)
        else:
            lazy_skipped = None
            failed = wait_health(process, controller_port, "proxy-a", health_url, False)
        routed = proxy_route(mixed_port, echo.port, first, second)
        return {
            "lazy": lazy,
            "initial-recorded": initial[0] and initial[1] > 0,
            "lazy-skipped": lazy_skipped,
            "failure-recorded": not failed[0] and failed[1] > initial[1],
            "survivor-route": routed == "proxy-b",
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
    for lazy in (False, True):
        case = "lazy" if lazy else "eager"
        case_scratch = scratch / case
        case_scratch.mkdir()
        observations[case] = exercise_schedule(binary, case_scratch, lazy)
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-health-schedule-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CHEALTHSCHEDULE_CARGO_TARGET",
            "phase5c-health-schedule",
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
    print("Phase 5C automatic health schedule differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for SOCKS5 members in automatic proxy groups."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_health_schedule import health_snapshot, wait_health
from phase5c_selector import route
from phase5d_proxies import request, start_health_server
from phase5d_streams import wait_controller
from phase6b_socks5 import Socks5Server


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-socks5-health-diff.json"


def render_config(
    path: Path,
    *,
    mixed_port: int,
    controller_port: int,
    first_port: int,
    second_port: int,
    health_url: str,
    interval: int,
    lazy: bool,
    max_failed_times: int = 5,
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: socks-a
    type: socks5
    server: 127.0.0.1
    port: {first_port}
    username: proxy-user
    password: proxy-pass
  - name: socks-b
    type: socks5
    server: 127.0.0.1
    port: {second_port}
    username: proxy-user
    password: proxy-pass
proxy-groups:
  - name: recovery
    type: fallback
    proxies: [socks-a, socks-b]
    url: {health_url}
    expected-status: '204'
    interval: {interval}
    timeout: 500
    max-failed-times: {max_failed_times}
    lazy: {str(lazy).lower()}
rules:
  - MATCH,recovery
"""
    )


def group_now(controller_port: int) -> str:
    status, body = request(controller_port, "GET", "/group/recovery")
    if status != 200:
        raise AssertionError((status, body))
    return str(json.loads(body)["now"])


def healthcheck(controller_port: int) -> tuple[int, bool]:
    status, body = request(
        controller_port,
        "GET",
        "/providers/proxies/recovery/healthcheck",
    )
    return status, body == b""


def start_case(
    binary: Path,
    scratch: Path,
    *,
    interval: int,
    lazy: bool,
    max_failed_times: int = 5,
) -> tuple[Any, Any, Any, Any, Any, Any, int, int, str]:
    echo = start_server(EchoHandler)
    health = start_health_server()
    first = Socks5Server()
    second = Socks5Server()
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
        interval=interval,
        lazy=lazy,
        max_failed_times=max_failed_times,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    wait_ready(process, mixed_port)
    wait_controller(process, controller_port)
    return (
        process,
        stdout,
        stderr,
        echo,
        health,
        (first, second),
        mixed_port,
        controller_port,
        health_url,
    )


def stop_case(resources: tuple[Any, ...], first_closed: bool) -> None:
    process, stdout, stderr, echo, health, pair, *_ = resources
    first, second = pair
    stop(process)
    stdout.close()
    stderr.close()
    if not first_closed:
        first.close()
    second.close()
    health.shutdown()
    health.server_close()
    echo.close()


def exercise_manual(binary: Path, scratch: Path) -> dict[str, Any]:
    resources = start_case(binary, scratch, interval=600, lazy=True)
    process, _, _, echo, _, pair, mixed_port, controller_port, health_url = resources
    first, _ = pair
    first_closed = False
    try:
        initial = wait_health(process, controller_port, "socks-a", health_url, True)
        time.sleep(1.1)
        checked = healthcheck(controller_port)
        refreshed = health_snapshot(controller_port, "socks-a", health_url)
        initial_route = route(mixed_port, echo.port)
        initial_now = group_now(controller_port)

        first.close()
        first_closed = True
        time.sleep(1.1)
        failed_check = healthcheck(controller_port)
        failed = wait_health(process, controller_port, "socks-a", health_url, False)
        survivor_route = route(mixed_port, echo.port)
        return {
            "manual-status": checked,
            "healthy-history-advanced": refreshed[0] and refreshed[1] > initial[1],
            "initial-route": initial_route,
            "initial-now": initial_now,
            "failure-status": failed_check,
            "failure-history-advanced": not failed[0] and failed[1] > refreshed[1],
            "survivor-route": survivor_route,
            "survivor-now": group_now(controller_port),
        }
    finally:
        stop_case(resources, first_closed)


def exercise_scheduled(binary: Path, scratch: Path) -> dict[str, Any]:
    resources = start_case(binary, scratch, interval=1, lazy=False)
    process, _, _, echo, _, pair, mixed_port, controller_port, health_url = resources
    first, _ = pair
    first_closed = False
    try:
        initial = wait_health(process, controller_port, "socks-a", health_url, True)
        first.close()
        first_closed = True
        failed = wait_health(process, controller_port, "socks-a", health_url, False)
        return {
            "scheduled-history-advanced": not failed[0] and failed[1] > initial[1],
            "survivor-route": route(mixed_port, echo.port),
            "survivor-now": group_now(controller_port),
        }
    finally:
        stop_case(resources, first_closed)


def exercise_dial_failure(binary: Path, scratch: Path) -> dict[str, Any]:
    resources = start_case(
        binary,
        scratch,
        interval=600,
        lazy=True,
        max_failed_times=99,
    )
    process, _, _, echo, _, pair, mixed_port, controller_port, health_url = resources
    first, _ = pair
    first_closed = False
    try:
        initial = wait_health(process, controller_port, "socks-a", health_url, True)
        time.sleep(1.1)
        first.close()
        first_closed = True
        # The initiating tunnel is intentionally not compared: both products
        # schedule the health check asynchronously while their retry timing is
        # allowed to differ.  Stable health and the next route are the gate.
        _ = route(mixed_port, echo.port)
        failed = wait_health(process, controller_port, "socks-a", health_url, False)
        return {
            "refused-bypassed-high-threshold": not failed[0] and failed[1] > initial[1],
            "survivor-route": route(mixed_port, echo.port),
            "survivor-now": group_now(controller_port),
        }
    finally:
        stop_case(resources, first_closed)


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    cases = {
        "manual": exercise_manual,
        "scheduled": exercise_scheduled,
        "dial-failure": exercise_dial_failure,
    }
    observations = {}
    for name, case in cases.items():
        case_root = scratch / name
        case_root.mkdir()
        observations[name] = case(binary, case_root)
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-socks5-health-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CSOCKSHEALTH_CARGO_TARGET",
            "phase5c-socks5-health",
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
    print("Phase 5C SOCKS5 automatic-group health differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

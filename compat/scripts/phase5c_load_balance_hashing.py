#!/usr/bin/env python3
"""Go/Rust contract differential for hashing load-balance strategies."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_load_balance import healthcheck, proxy_route, snapshot
from phase5d_proxies import request, start_health_server
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = (
    ROOT / "compat" / "artifacts" / "phase5c-load-balance-hashing-diff.json"
)


def exercise_strategy(binary: Path, scratch: Path, strategy: str) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    health = start_health_server()
    first = ConnectProxyServer()
    second = ConnectProxyServer()
    first_closed = False
    second_closed = False
    mixed_port, controller_port = reserve_port(), reserve_port()
    health_url = f"http://127.0.0.1:{health.server_port}/generate_204"
    strategy_line = "" if strategy == "consistent-hashing" else f"    strategy: {strategy}\n"
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
{strategy_line}    proxies: [proxy-a, proxy-b]
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
        initial = [proxy_route(mixed_port, echo.port, first, second) for _ in range(4)]
        chosen = initial[0]
        initial_stable = chosen in {"proxy-a", "proxy-b"} and all(
            member == chosen for member in initial
        )

        if chosen == "proxy-a":
            first.close()
            first_closed = True
        elif chosen == "proxy-b":
            second.close()
            second_closed = True
        else:
            raise AssertionError(initial)
        time.sleep(1.1)
        failure_health = healthcheck(controller_port)
        replacement = [
            proxy_route(mixed_port, echo.port, first, second) for _ in range(3)
        ]
        failover_stable = all(
            member in {"proxy-a", "proxy-b"} and member != chosen
            for member in replacement
        )
        put_status, put_body = request(
            controller_port,
            "PUT",
            "/proxies/balanced",
            {"name": "proxy-a"},
        )
        return {
            "strategy": strategy,
            "view": view,
            "initial-health": initial_health,
            "initial-stable": initial_stable,
            "failure-health": failure_health,
            "healthy-failover-stable": failover_stable,
            "put-error": (put_status, json.loads(put_body)["message"]),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        if not first_closed:
            first.close()
        if not second_closed:
            second.close()
        health.shutdown()
        health.server_close()
        echo.close()


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    observations = {}
    for strategy in ("consistent-hashing", "sticky-sessions"):
        strategy_scratch = scratch / strategy
        strategy_scratch.mkdir()
        observations[strategy] = exercise_strategy(binary, strategy_scratch, strategy)
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-load-balance-hashing-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CLOADBALANCEHASH_CARGO_TARGET",
            "phase5c-load-balance-hashing",
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
    print("Phase 5C hashing load-balance differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust live differential for Phase 5B2d TCP port/network metadata."""

from __future__ import annotations

import json
import pathlib
import tempfile
import threading
from collections.abc import Callable
from typing import Any

from phase1 import EchoHandler, ROOT, RunningServer, ThreadingServer, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files, route
from phase5b2a import wait_route


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b2d-diff.json"
RuleFactory = Callable[[int, int], str]


def adjacent_port(port: int) -> int:
    return port - 1 if port == 65_535 else port + 1


def exercise_rule(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    rule_factory: RuleFactory,
    expected: str,
) -> str:
    server = ThreadingServer(("0.0.0.0", 0), EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    echo = RunningServer(server, thread)
    proxy_port = reserve_port()
    rule = rule_factory(proxy_port, echo.port)
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {proxy_port}
mode: rule
log-level: info
ipv6: false
rules:
  - {rule}
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, proxy_port)
        wait_route(process, proxy_port, "127.0.0.1", echo.port, expected)
        return route(proxy_port, "127.0.0.1", echo.port)
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    cases: dict[str, tuple[RuleFactory, str]] = {
        "destination-hit": (lambda _proxy, dest: f"DST-PORT,{dest},DIRECT", "direct"),
        "destination-miss": (
            lambda _proxy, dest: f"DST-PORT,{adjacent_port(dest)},DIRECT",
            "reject",
        ),
        "inbound-hit": (lambda proxy, _dest: f"IN-PORT,{proxy},DIRECT", "direct"),
        "inbound-miss": (
            lambda proxy, _dest: f"IN-PORT,{adjacent_port(proxy)},DIRECT",
            "reject",
        ),
        "network-tcp": (lambda _proxy, _dest: "NETWORK,TCP,DIRECT", "direct"),
        "network-udp": (lambda _proxy, _dest: "NETWORK,UDP,DIRECT", "reject"),
    }
    observations: dict[str, str] = {}
    for name, (factory, expected) in cases.items():
        case = scratch / name
        case.mkdir()
        observations[name] = exercise_rule(binary, case, factory, expected)
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    debug: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b2d-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5B2D_CARGO_TARGET", "phase5b2d")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
            debug = debug_files(root)
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
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {"observations": observations, "debug": debug},
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5B2d TCP port/network mixed-TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust fixed-listener differential for Phase 5B3c IN-NAME."""

from __future__ import annotations

import json
import pathlib
import tempfile
import time
from typing import Any, Callable

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files, route as http_route
from phase5b3a import socks5_route


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b3c-diff.json"


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    http_port, socks_port, mixed_port = reserve_port(), reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""port: {http_port}
socks-port: {socks_port}
mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
rules:
  - IN-NAME,DEFAULT-HTTP/DEFAULT-MIXED,DIRECT
  - IN-NAME,DEFAULT-SOCKS,REJECT
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    probes: dict[str, Callable[[], str]] = {
        "default-http": lambda: http_route(http_port, "127.0.0.1", echo.port),
        "default-socks": lambda: socks5_route(socks_port, echo.port),
        "default-mixed": lambda: http_route(mixed_port, "127.0.0.1", echo.port),
    }
    expected = {
        "default-http": "direct",
        "default-socks": "reject",
        "default-mixed": "direct",
    }
    try:
        for port in (http_port, socks_port, mixed_port):
            wait_ready(process, port)
        observations: dict[str, str] = {}
        order = sorted(probes, key=lambda name: expected[name] != "direct")
        for name in order:
            deadline = time.monotonic() + IO_DEADLINE
            while time.monotonic() < deadline:
                try:
                    observations[name] = probes[name]()
                    if observations[name] == expected[name]:
                        break
                except OSError:
                    pass
                time.sleep(0.02)
            else:
                raise TimeoutError(
                    f"{name} route did not become {expected[name]}: "
                    f"{observations.get(name)}"
                )
        return {name: observations[name] for name in probes}
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    debug: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b3c-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5B3C_CARGO_TARGET", "phase5b3c")
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
    print("Phase 5B3c IN-NAME fixed-listener differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

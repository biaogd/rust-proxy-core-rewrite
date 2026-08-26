#!/usr/bin/env python3
"""Go/Rust live mixed-TCP differential for Phase 5B3e PASS routing."""

from __future__ import annotations

import json
import pathlib
import threading
import tempfile
from typing import Any

from phase1 import EchoHandler, ROOT, RunningServer, ThreadingServer, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files, route
from phase5b2a import wait_route


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b3e-diff.json"


def exercise_rules(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    rules: list[str],
    probes: list[tuple[str, str]],
    extra_config: str = "",
) -> dict[str, str]:
    server = ThreadingServer(("0.0.0.0", 0), EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    echo = RunningServer(server, thread)
    proxy_port = reserve_port()
    rendered_rules = "\n".join(f"  - {rule}" for rule in rules)
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {proxy_port}
mode: rule
log-level: info
ipv6: false
rules:
{rendered_rules}
{extra_config}
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, proxy_port)
        for host, expected in probes:
            wait_route(process, proxy_port, host, echo.port, expected)
        return {host: route(proxy_port, host, echo.port) for host, _ in probes}
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    pass_to_direct = scratch / "pass-to-direct"
    pass_to_reject = scratch / "pass-to-reject"
    pass_to_direct.mkdir()
    pass_to_reject.mkdir()
    return {
        "pass-to-direct": exercise_rules(
            binary,
            pass_to_direct,
            [
                "DOMAIN,localhost,PASS",
                "DOMAIN,localhost,DIRECT",
                "MATCH,REJECT",
            ],
            [("localhost", "direct"), ("127.0.0.1", "reject")],
        ),
        "pass-to-reject": exercise_rules(
            binary,
            pass_to_reject,
            ["DOMAIN,localhost,PASS", "MATCH,REJECT"],
            [("localhost", "reject")],
        ),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    debug: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b3e-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5B3E_CARGO_TARGET", "phase5b3e")
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
    print("Phase 5B3e PASS mixed-TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

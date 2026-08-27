#!/usr/bin/env python3
"""Go/Rust differential for fallback group-delay and unfix behavior."""

from __future__ import annotations

import json
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

from phase1 import ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5d_proxies import request, start_health_server
from phase5d_streams import wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-fallback-delay-diff.json"


def group(controller_port: int) -> dict[str, str]:
    status, body = request(controller_port, "GET", "/group/recovery")
    if status != 200:
        raise AssertionError((status, body))
    value = json.loads(body)
    return {"now": value["now"], "fixed": value["fixed"]}


def select_direct(controller_port: int) -> tuple[int, bool]:
    status, body = request(
        controller_port,
        "PUT",
        "/proxies/recovery",
        {"name": "DIRECT"},
    )
    return status, body == b""


def error(result: tuple[int, bytes]) -> tuple[int, str]:
    status, body = result
    return status, json.loads(body)["message"]


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    health = start_health_server()
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
proxy-groups:
  - name: recovery
    type: fallback
    proxies: [DIRECT, REJECT]
    url: {health_url}
    expected-status: '204'
rules:
  - MATCH,recovery
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        fixed_before_invalid = select_direct(controller_port)
        invalid = error(
            request(
                controller_port,
                "GET",
                "/group/recovery/delay?timeout=1000&expected=invalid",
            )
        )
        after_invalid = group(controller_port)

        fixed_before_success = select_direct(controller_port)
        query = urllib.parse.urlencode(
            {"url": health_url, "timeout": "1000", "expected": "204"}
        )
        status, body = request(
            controller_port,
            "GET",
            f"/group/recovery/delay?{query}",
        )
        value = json.loads(body)
        success = {
            "status": status,
            "keys": sorted(value),
            "positive-direct": value.get("DIRECT", 0) > 0,
        }
        after_success = group(controller_port)
        fixed_before_timeout = select_direct(controller_port)
        timeout = error(
            request(
                controller_port,
                "GET",
                f"/group/recovery/delay?url={urllib.parse.quote(health_url)}&timeout=0&expected=204",
            )
        )
        after_timeout = group(controller_port)
    finally:
        stop(process)
        stdout.close()
        stderr.close()

    restarted, restart_stdout, restart_stderr = launch(binary, config, scratch)
    try:
        wait_ready(restarted, mixed_port)
        wait_controller(restarted, controller_port)
        after_restart = group(controller_port)
    finally:
        stop(restarted)
        restart_stdout.close()
        restart_stderr.close()
        health.shutdown()
        health.server_close()
    return {
        "fixed-before-invalid": fixed_before_invalid,
        "invalid": invalid,
        "after-invalid": after_invalid,
        "fixed-before-success": fixed_before_success,
        "success": success,
        "after-success": after_success,
        "fixed-before-timeout": fixed_before_timeout,
        "timeout": timeout,
        "after-timeout": after_timeout,
        "after-restart": after_restart,
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-fallback-delay-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CFALLBACKDELAY_CARGO_TARGET",
            "phase5c-fallback-delay",
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
    print("Phase 5C fallback group-delay differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

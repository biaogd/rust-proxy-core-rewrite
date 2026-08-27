#!/usr/bin/env python3
"""Go/Rust differential for the implicit provider controller boundary."""

from __future__ import annotations

import json
import pathlib
import tempfile
from typing import Any

from phase1 import ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5d_proxies import normalize, request
from phase5d_streams import wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5d-providers-diff.json"


def json_response(result: tuple[int, bytes]) -> tuple[int, Any]:
    status, body = result
    return status, normalize(json.loads(body))


def empty(result: tuple[int, bytes]) -> dict[str, Any]:
    status, body = result
    return {"status": status, "empty-body": body == b""}


def error(result: tuple[int, bytes]) -> dict[str, Any]:
    status, body = result
    return {"status": status, "message": json.loads(body)["message"]}


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: phase5d-streams-secret
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        return {
            "proxy-list": json_response(
                request(controller_port, "GET", "/providers/proxies")
            ),
            "proxy-detail": json_response(
                request(controller_port, "GET", "/providers/proxies/default")
            ),
            "direct-member": json_response(
                request(
                    controller_port,
                    "GET",
                    "/providers/proxies/default/DIRECT",
                )
            ),
            "update-default": empty(
                request(controller_port, "PUT", "/providers/proxies/default")
            ),
            "health-default": empty(
                request(
                    controller_port,
                    "GET",
                    "/providers/proxies/default/healthcheck",
                )
            ),
            "missing-provider": error(
                request(controller_port, "GET", "/providers/proxies/missing")
            ),
            "missing-member": error(
                request(
                    controller_port,
                    "GET",
                    "/providers/proxies/default/missing",
                )
            ),
            "rule-list": json_response(
                request(controller_port, "GET", "/providers/rules")
            ),
            "missing-rule-update": error(
                request(controller_port, "PUT", "/providers/rules/missing")
            ),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-providers-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE5DPROVIDERS_CARGO_TARGET", "phase5d-providers"
        )
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
        except Exception as exc:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "error": f"{type(exc).__name__}: {exc}",
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
            json.dumps({"observations": observations}, indent=2, sort_keys=True)
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5D implicit provider differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

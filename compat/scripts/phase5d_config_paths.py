#!/usr/bin/env python3
"""Controller default/safe-path configuration reload differential."""

from __future__ import annotations

import json
import pathlib
import tempfile
from typing import Any

from phase1 import ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5d_configs import json_request, request
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat/artifacts/phase5d-config-paths-diff.json"


def yaml_config(mixed: int, controller: int, level: str) -> str:
    return f"""mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
secret: {SECRET}
mode: rule
log-level: {level}
ipv6: false
rules:
  - MATCH,DIRECT
"""


def result(value: tuple[int, bytes]) -> dict[str, Any]:
    status, body = value
    parsed = json.loads(body) if body else None
    return {"status": status, "body": parsed}


def current_level(controller: int) -> str:
    status, body = request(controller, "GET", "/configs")
    if status != 200:
        raise AssertionError((status, body))
    return json.loads(body)["log-level"]


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    mixed, controller = reserve_port(), reserve_port()
    profile = scratch / ".config/mihomo"
    profile.mkdir(parents=True)
    config = scratch / "config.yaml"
    config.write_text(yaml_config(mixed, controller, "info"))
    safe = profile / "safe.yaml"
    safe.write_text(yaml_config(mixed, controller, "error"))
    malformed = profile / "malformed.yaml"
    malformed.write_text("mixed-port: [")
    outside = scratch / "outside.yaml"
    outside.write_text(yaml_config(mixed, controller, "warning"))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed)
        wait_controller(process, controller)
        before = current_level(controller)
        explicit_safe = result(
            json_request(controller, "PUT", "/configs", {"path": str(safe), "payload": ""})
        )
        after_safe = current_level(controller)
        malformed_result = result(
            json_request(controller, "PUT", "/configs", {"path": str(malformed), "payload": ""})
        )
        after_malformed = current_level(controller)
        relative = result(
            json_request(controller, "PUT", "/configs", {"path": "safe.yaml", "payload": ""})
        )
        unsafe = result(
            json_request(controller, "PUT", "/configs", {"path": str(outside), "payload": ""})
        )
        config.write_text(yaml_config(mixed, controller, "debug"))
        default_path = result(
            json_request(controller, "PUT", "/configs", {"path": "", "payload": ""})
        )
        after_default = current_level(controller)
        return {
            "before": before,
            "safe": explicit_safe,
            "after-safe": after_safe,
            "malformed-status": malformed_result["status"],
            "after-malformed": after_malformed,
            "relative": relative,
            "unsafe-status": unsafe["status"],
            "unsafe-message-prefix": unsafe["body"]["message"].split(":", 1)[0],
            "default": default_path,
            "after-default": after_default,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-config-paths-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5DCONFIGPATH_CARGO_TARGET", "phase5d-config-paths")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(json.dumps({
                "error": f"{type(error).__name__}: {error}",
                "observations": observations,
                "debug": debug_files(root),
            }, indent=2, sort_keys=True))
            raise
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps({"observations": observations}, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5D configuration path differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust local-default differential for Phase 5B2c DSCP."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import ROOT
from phase5b1a import build_binaries, debug_files
from phase5b2a import exercise_config


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b2c-diff.json"


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    cases = {
        "zero": ("DSCP,0,DIRECT", "direct"),
        "nonzero-miss": ("DSCP,1,DIRECT", "reject"),
        "slash-reversed-range": ("DSCP,1/2-0,DIRECT", "direct"),
        "wildcard": ("DSCP,*,DIRECT", "direct"),
    }
    observations: dict[str, Any] = {}
    for name, (rule, expected) in cases.items():
        case = scratch / name
        case.mkdir()
        observations[name] = exercise_config(
            binary,
            case,
            rule,
            [("127.0.0.1", expected)],
            "REJECT",
        )["127.0.0.1"]

    invalid = scratch / "invalid.yaml"
    invalid.write_text("rules:\n  - DSCP,64,DIRECT\n")
    validation = subprocess.run(
        [str(binary), "-t", "-f", str(invalid)],
        cwd=scratch,
        capture_output=True,
        check=False,
    )
    observations["invalid-64-accepted"] = validation.returncode == 0
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    debug: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b2c-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5B2C_CARGO_TARGET", "phase5b2c")
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
    print("Phase 5B2c default DSCP mixed-TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

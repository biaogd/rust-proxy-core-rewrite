#!/usr/bin/env python3
"""Go/Rust live mixed-TCP differential for Phase 5B3d logic rules."""

from __future__ import annotations

import json
import pathlib
import tempfile
from typing import Any

from phase1 import ROOT
from phase5b1a import build_binaries, debug_files
from phase5b2a import exercise_config


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b3d-diff.json"


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    cases = {
        "and": (
            "AND,((DOMAIN,localhost),(IN-TYPE,HTTPS)),DIRECT",
            [("localhost", "direct"), ("127.0.0.1", "reject")],
        ),
        "or": (
            "OR,((DOMAIN,localhost),(IN-TYPE,HTTP)),DIRECT",
            [("localhost", "direct"), ("127.0.0.1", "reject")],
        ),
        "not": (
            "NOT,((DOMAIN,localhost)),DIRECT",
            [("127.0.0.1", "direct"), ("localhost", "reject")],
        ),
    }
    observations: dict[str, Any] = {}
    for name, (rule, probes) in cases.items():
        case = scratch / name
        case.mkdir()
        observations[name] = exercise_config(binary, case, rule, probes, "REJECT")
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    debug: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b3d-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5B3D_CARGO_TARGET", "phase5b3d")
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
    print("Phase 5B3d AND/OR/NOT mixed-TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

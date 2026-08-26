#!/usr/bin/env python3
"""Go/Rust mixed-TCP differential for Phase 5B2b source IP suffixes."""

from __future__ import annotations

import json
import pathlib
import tempfile
from typing import Any

from phase1 import ROOT
from phase5b1a import build_binaries, debug_files
from phase5b2a import exercise_config


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b2b-diff.json"


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    cases = {
        "explicit-source-kind": "SRC-IP-SUFFIX,0.0.0.1/8,DIRECT",
        "source-parameter": "IP-SUFFIX,0.0.0.1/8,DIRECT,src",
        "source-miss": "SRC-IP-SUFFIX,0.0.0.2/8,DIRECT",
    }
    observations: dict[str, Any] = {}
    for name, rule in cases.items():
        case = scratch / name
        case.mkdir()
        expected = "reject" if name == "source-miss" else "direct"
        observations[name] = exercise_config(
            binary,
            case,
            rule,
            [("127.0.0.1", expected)],
            "REJECT",
        )
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b2b-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5B2B_CARGO_TARGET", "phase5b2b")
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
    print("Phase 5B2b source IP suffix mixed-TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust live differential for Phase 5B3f SUB-RULE and PASS-RULE."""

from __future__ import annotations

import json
import pathlib
import tempfile
from typing import Any

from phase1 import ROOT
from phase5b1a import build_binaries, debug_files
from phase5b3e import exercise_rules


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b3f-diff.json"


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    continue_in_branch = scratch / "continue-in-branch"
    escape_branch = scratch / "escape-branch"
    continue_in_branch.mkdir()
    escape_branch.mkdir()
    return {
        "continue-in-branch": exercise_rules(
            binary,
            continue_in_branch,
            ["SUB-RULE,(NETWORK,TCP),branch", "MATCH,REJECT"],
            [("localhost", "direct"), ("127.0.0.1", "reject")],
            """sub-rules:
  branch:
    - DOMAIN,localhost,PASS-RULE
    - DOMAIN,localhost,DIRECT
    - MATCH,REJECT
""",
        ),
        "escape-branch": exercise_rules(
            binary,
            escape_branch,
            ["SUB-RULE,(NETWORK,TCP),branch", "MATCH,DIRECT"],
            [("localhost", "direct")],
            """sub-rules:
  branch:
    - DOMAIN,localhost,PASS-RULE
""",
        ),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    debug: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b3f-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5B3F_CARGO_TARGET", "phase5b3f")
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
    print("Phase 5B3f SUB-RULE/PASS-RULE mixed-TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

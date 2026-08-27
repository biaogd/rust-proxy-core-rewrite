#!/usr/bin/env python3
"""Go/Rust live differential for Phase 5B3g REMATCH mutation/rescan."""

from __future__ import annotations

import json
import pathlib
import tempfile
from typing import Any

from phase1 import ROOT
from phase5b1a import build_binaries, debug_files
from phase5b3e import exercise_rules


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b3g-diff.json"


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    rematch_name = scratch / "rematch-name"
    sub_rule = scratch / "sub-rule"
    rematch_name.mkdir()
    sub_rule.mkdir()
    return {
        "rematch-name": exercise_rules(
            binary,
            rematch_name,
            [
                "AND,((REMATCH-NAME,after),(DOMAIN,localhost)),DIRECT",
                "REMATCH-NAME,after,REJECT",
                "MATCH,SET-NAME",
            ],
            [("localhost", "direct"), ("127.0.0.1", "reject")],
            """proxies:
  - name: SET-NAME
    type: rematch
    target-rematch-name: after
""",
        ),
        "target-sub-rule": exercise_rules(
            binary,
            sub_rule,
            ["MATCH,TO-BRANCH"],
            [("localhost", "direct"), ("127.0.0.1", "reject")],
            """proxies:
  - name: TO-BRANCH
    type: rematch
    target-sub-rule: branch
sub-rules:
  branch:
    - DOMAIN,localhost,DIRECT
    - MATCH,REJECT
""",
        ),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    debug: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b3g-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5B3G_CARGO_TARGET", "phase5b3g")
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
    print("Phase 5B3g REMATCH mixed-TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

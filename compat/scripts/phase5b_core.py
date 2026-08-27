#!/usr/bin/env python3
"""Go/Rust aggregate live differential for core domain and IP rules."""

from __future__ import annotations

import json
import pathlib
import tempfile
from typing import Any

from phase1 import ROOT
from phase5b1a import build_binaries, debug_files
from phase5b2a import exercise_config
from phase5b3e import exercise_rules


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b-core-diff.json"


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    domain = scratch / "domain-family"
    destination_cidr = scratch / "destination-cidr"
    source_cidr = scratch / "source-cidr"
    suffix_hit = scratch / "suffix-partial-hit"
    suffix_miss = scratch / "suffix-partial-miss"
    mapped = scratch / "mapped-ipv4"
    for path in (
        domain,
        destination_cidr,
        source_cidr,
        suffix_hit,
        suffix_miss,
        mapped,
    ):
        path.mkdir()

    return {
        "domain-family": exercise_rules(
            binary,
            domain,
            [
                "DOMAIN,exact.rule.test,DIRECT",
                "DOMAIN-SUFFIX,suffix.rule.test,DIRECT",
                "DOMAIN-KEYWORD,needle,DIRECT",
                "MATCH,REJECT",
            ],
            [
                ("exact.rule.test", "direct"),
                ("child.suffix.rule.test", "direct"),
                ("has-needle.rule.test", "direct"),
                ("127.0.0.1", "reject"),
            ],
            """hosts:
  exact.rule.test: 127.0.0.1
  child.suffix.rule.test: 127.0.0.1
  has-needle.rule.test: 127.0.0.1
""",
        ),
        "destination-cidr": exercise_config(
            binary,
            destination_cidr,
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
            [("127.0.0.1", "direct"), ("no-resolve.invalid", "reject")],
            "REJECT",
        ),
        "source-cidr": exercise_config(
            binary,
            source_cidr,
            "SRC-IP-CIDR,127.0.0.0/8,DIRECT",
            [("127.0.0.1", "direct")],
            "REJECT",
        ),
        "suffix-partial-hit": exercise_config(
            binary,
            suffix_hit,
            "IP-SUFFIX,127.0.0.1/1,DIRECT,no-resolve",
            [("127.0.0.1", "direct")],
            "REJECT",
        ),
        "suffix-partial-miss": exercise_config(
            binary,
            suffix_miss,
            "IP-SUFFIX,127.0.0.0/1,DIRECT,no-resolve",
            [("127.0.0.1", "reject")],
            "REJECT",
        ),
        "mapped-ipv4": exercise_config(
            binary,
            mapped,
            "IP-SUFFIX,127.0.0.1/32,DIRECT,no-resolve",
            [("[::ffff:127.0.0.1]", "direct")],
            "REJECT",
        ),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    debug: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b-core-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5BCORE_CARGO_TARGET", "phase5b-core")
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
    print("Phase 5B aggregate core domain/IP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

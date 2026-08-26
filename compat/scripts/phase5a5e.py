#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A5e classical conversion rejection."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import IO_DEADLINE, ROOT
from phase5a6b import build_binaries


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a5e-diff.json"


def observe(
    binary: pathlib.Path,
    format_name: str,
    source: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    target = scratch / "target.mrs"
    result = subprocess.run(
        [
            str(binary),
            "convert-ruleset",
            "classical",
            format_name,
            str(source),
            str(target),
            "ignored",
        ],
        cwd=scratch,
        env={**os.environ, "HOME": str(scratch)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=IO_DEADLINE,
    )
    return {
        "exit-code": result.returncode,
        "stdout": result.stdout.decode(errors="replace"),
        "stderr-present": bool(result.stderr),
        "target-created": target.exists(),
        "target-size": target.stat().st_size if target.exists() else None,
        "config-created": (scratch / ".config" / "mihomo" / "config.yaml").exists(),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a5e-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5A5E_CARGO_TARGET")
        empty_text = root / "empty.txt"
        empty_text.write_text("# no rules\n// still empty\n")
        empty_yaml = root / "empty.yaml"
        empty_yaml.write_text("payload:\n")
        arbitrary_mrs = root / "arbitrary.mrs"
        arbitrary_mrs.write_bytes(b"classical-does-not-support-mrs")
        sources = {"text": empty_text, "yaml": empty_yaml, "": empty_yaml, "mrs": arbitrary_mrs}
        observations: dict[str, Any] = {
            format_name or "empty-format": {
                name: observe(
                    binary,
                    format_name,
                    source,
                    root / f"{format_name or 'empty'}-{name}",
                )
                for name, binary in binaries.items()
            }
            for format_name, source in sources.items()
        }
        expected = {
            "exit-code": 2,
            "stdout": "",
            "stderr-present": True,
            "target-created": True,
            "target-size": 0,
            "config-created": False,
        }
        mismatch = any(
            case != {"go": expected, "rust": expected} for case in observations.values()
        )
        if mismatch:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A5e mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A5e classical rejection differential passed")


if __name__ == "__main__":
    main()

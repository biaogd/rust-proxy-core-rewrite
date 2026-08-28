#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A6a UUID generation."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import uuid
from typing import Any

from phase1 import (
    IO_DEADLINE,
    ROOT,
    RUST_ROOT,
    assert_go_oracle_baseline,
    cargo_target_path,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a6a-diff.json"


def build_binaries(output: pathlib.Path) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()
    go_binary = output / "go-oracle"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_binary), "."],
        cwd=ROOT,
        check=True,
    )
    target = cargo_target_path("PHASE5A6A_CARGO_TARGET", "phase5a6a-rust")
    subprocess.run(
        ["cargo", "build", "-p", "rewrite-cli", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def run(
    binary: pathlib.Path,
    arguments: list[str],
    scratch: pathlib.Path,
) -> subprocess.CompletedProcess[bytes]:
    scratch.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [str(binary), *arguments],
        cwd=scratch,
        env={**os.environ, "HOME": str(scratch)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=IO_DEADLINE,
    )


def generated(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    result = run(binary, ["generate", "uuid", "ignored"], scratch)
    value = result.stdout.decode(errors="replace").strip()
    try:
        parsed = uuid.UUID(value)
        canonical = str(parsed) == value
        version = parsed.version
        variant = parsed.variant == uuid.RFC_4122
    except ValueError:
        canonical = False
        version = None
        variant = False
    return {
        "exit-code": result.returncode,
        "one-line": len(result.stdout.decode(errors="replace").splitlines()) == 1,
        "canonical-lowercase": canonical,
        "version": version,
        "rfc4122-variant": variant,
        "stderr-present": bool(result.stderr),
        "config-created": (scratch / ".config" / "mihomo" / "config.yaml").exists(),
    }


def lifecycle(binary: pathlib.Path, arguments: list[str], scratch: pathlib.Path) -> dict[str, Any]:
    result = run(binary, arguments, scratch)
    return {
        "exit-code": result.returncode,
        "stdout": result.stdout.decode(errors="replace"),
        "stderr-present": bool(result.stderr),
        "config-created": (scratch / ".config" / "mihomo" / "config.yaml").exists(),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a6a-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations: dict[str, Any] = {
            "uuid": {
                name: generated(binary, root / f"uuid-{name}")
                for name, binary in binaries.items()
            },
            "unknown": {
                name: lifecycle(
                    binary,
                    ["generate", "unknown", "ignored"],
                    root / f"unknown-{name}",
                )
                for name, binary in binaries.items()
            },
            "missing": {
                name: lifecycle(binary, ["generate"], root / f"missing-{name}")
                for name, binary in binaries.items()
            },
        }
        expected_uuid = {
            "exit-code": 0,
            "one-line": True,
            "canonical-lowercase": True,
            "version": 4,
            "rfc4122-variant": True,
            "stderr-present": False,
            "config-created": False,
        }
        expected_unknown = {
            "exit-code": 0,
            "stdout": "",
            "stderr-present": False,
            "config-created": False,
        }
        expected_missing = {
            "exit-code": 2,
            "stdout": "",
            "stderr-present": True,
            "config-created": False,
        }
        mismatch = (
            observations["uuid"] != {"go": expected_uuid, "rust": expected_uuid}
            or observations["unknown"]
            != {"go": expected_unknown, "rust": expected_unknown}
            or observations["missing"]
            != {"go": expected_missing, "rust": expected_missing}
        )
        if mismatch:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A6a mismatch; see {FAILURE_ARTIFACT}")

    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A6a UUID generation differential passed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A4b age convert."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import IO_DEADLINE, ROOT, RUST_ROOT, assert_go_oracle_baseline


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a4b-diff.json"


def build_binaries(output: pathlib.Path) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()
    go_binary = output / "go-oracle"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_binary), "."],
        cwd=ROOT,
        check=True,
    )
    target = pathlib.Path(
        os.environ.get(
            "PHASE5A4B_CARGO_TARGET", ROOT / "target" / "compat" / "phase5a4b-rust"
        )
    )
    subprocess.run(
        ["cargo", "build", "-p", "rewrite-cli", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def fixture_key(go_binary: pathlib.Path) -> tuple[str, str]:
    output = subprocess.check_output([str(go_binary), "age", "keygen"], text=True)
    return (
        next(line for line in output.splitlines() if line.startswith("AGE-SECRET-KEY-")),
        next(
            line.removeprefix("# public key: ")
            for line in output.splitlines()
            if line.startswith("# public key: ")
        ),
    )


def run(binary: pathlib.Path, arguments: list[str], scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True)
    result = subprocess.run(
        [str(binary), "age", *arguments],
        cwd=scratch,
        env={**os.environ, "HOME": str(scratch)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=IO_DEADLINE,
    )
    return {
        "exit-code": result.returncode,
        "stdout": result.stdout.decode(errors="replace").strip(),
        "has-error": bool(result.stderr.strip()),
    }


def observe(
    binary: pathlib.Path, scratch: pathlib.Path, secret: str, public: str
) -> dict[str, Any]:
    valid = run(binary, ["convert", secret], scratch / "valid")
    valid["stdout"] = "expected-recipient" if valid["stdout"] == public else "unexpected"
    extra = run(binary, ["convert", secret, "ignored"], scratch / "extra")
    extra["stdout"] = "expected-recipient" if extra["stdout"] == public else "unexpected"
    invalid = run(binary, ["convert", "not-an-age-key"], scratch / "invalid")
    invalid["stdout"] = "empty" if invalid["stdout"] == "" else "unexpected"
    missing = run(binary, ["convert"], scratch / "missing")
    missing["stdout"] = "empty" if missing["stdout"] == "" else "unexpected"
    return {"valid": valid, "extra-ignored": extra, "invalid": invalid, "missing": missing}


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a4b-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        secret, public = fixture_key(binaries["go"])
        observations = {
            name: observe(binary, root / name, secret, public)
            for name, binary in binaries.items()
        }
        success = {"exit-code": 0, "stdout": "expected-recipient", "has-error": False}
        failure = {"exit-code": 2, "stdout": "empty", "has-error": True}
        expected = {
            "valid": success,
            "extra-ignored": success,
            "invalid": failure,
            "missing": failure,
        }
        if observations["go"] != observations["rust"] or observations["go"] != expected:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A4b mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A4b age convert differential passed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A2a version output."""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any

from phase1 import (
    IO_DEADLINE,
    ROOT,
    RUST_ROOT,
    assert_go_oracle_baseline,
    cargo_target_path,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a2a-diff.json"
BANNER = re.compile(
    r"^Mihomo Meta (?P<version>\S+) (?P<os>\S+) (?P<arch>\S+) "
    r"with (?P<compiler>\S+) (?P<build>.+)$"
)


def build_binaries(output: pathlib.Path) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()
    go_binary = output / "go-oracle"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_binary), "."],
        cwd=ROOT,
        check=True,
    )
    target = cargo_target_path("PHASE5A2A_CARGO_TARGET", "phase5a2a-rust")
    subprocess.run(
        ["cargo", "build", "-p", "rewrite-cli", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def run_case(
    binary: pathlib.Path, scratch: pathlib.Path, arguments: list[str]
) -> dict[str, Any]:
    home = scratch / "home"
    home.mkdir(parents=True)
    missing = scratch / "must-not-be-created.yaml"
    environment = {
        **os.environ,
        "HOME": str(home),
        "CLASH_CONFIG_FILE": str(missing),
    }
    result = subprocess.run(
        [str(binary), *arguments],
        cwd=scratch,
        env=environment,
        text=True,
        capture_output=True,
        timeout=IO_DEADLINE,
    )
    lines = result.stdout.splitlines()
    if len(lines) != 1:
        raise AssertionError(f"unexpected version stdout: {result.stdout!r}")
    match = BANNER.fullmatch(lines[0])
    if match is None:
        raise AssertionError(f"unexpected version banner: {lines[0]!r}")
    compiler = match.group("compiler")
    if not (compiler.startswith("go") or compiler.startswith("rustc")):
        raise AssertionError(f"missing implementation compiler version: {compiler!r}")
    return {
        "exit-code": result.returncode,
        "stderr-empty": result.stderr == "",
        "version": match.group("version"),
        "os": match.group("os"),
        "architecture": match.group("arch"),
        # A Rust replacement must identify rustc rather than falsely claiming
        # the Go compiler. Validate both raw forms above, then normalize only
        # this intentional implementation-language difference.
        "compiler": "implementation-compiler-version",
        "build-time": match.group("build"),
        "config-created": missing.exists(),
    }


def observe(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True)
    return {
        "version-only": run_case(binary, scratch / "only", ["-v"]),
        "version-short-circuits-config": run_case(
            binary, scratch / "short-circuit", ["-v", "-f", "missing.yaml"]
        ),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a2a-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            name: observe(binary, root / name) for name, binary in binaries.items()
        }
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A2a mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A2a version differential passed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A4d age keygen."""

from __future__ import annotations

import datetime
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import IO_DEADLINE, ROOT, RUST_ROOT, assert_go_oracle_baseline


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a4d-diff.json"


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
            "PHASE5A4D_CARGO_TARGET", ROOT / "target" / "compat" / "phase5a4d-rust"
        )
    )
    subprocess.run(
        ["cargo", "build", "-p", "rewrite-cli", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def keygen(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True)
    result = subprocess.run(
        [str(binary), "age", "keygen", "ignored"],
        cwd=scratch,
        env={**os.environ, "HOME": str(scratch)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=IO_DEADLINE,
    )
    lines = result.stdout.decode(errors="replace").splitlines()
    if len(lines) != 3:
        return {
            "exit-code": result.returncode,
            "layout": "invalid",
            "stderr": bool(result.stderr),
        }
    created = lines[0].removeprefix("# created: ")
    try:
        datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
        timestamp = "rfc3339"
    except ValueError:
        timestamp = "invalid"
    return {
        "exit-code": result.returncode,
        "layout": "three-lines",
        "timestamp": timestamp,
        "public-prefix": lines[1].startswith("# public key: age1"),
        "secret-prefix": lines[2].startswith("AGE-SECRET-KEY-1"),
        "stderr": bool(result.stderr),
        "secret": lines[2],
        "public": lines[1].removeprefix("# public key: "),
        "config-created": (scratch / ".config" / "mihomo" / "config.yaml").exists(),
    }


def convert(binary: pathlib.Path, secret: str, scratch: pathlib.Path) -> str:
    scratch.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [str(binary), "age", "convert", secret],
        cwd=scratch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=IO_DEADLINE,
        check=True,
    )
    return result.stdout.decode().strip()


def normalized(observation: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in observation.items() if key not in {"secret", "public"}}


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a4d-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        generated = {
            name: keygen(binary, root / name) for name, binary in binaries.items()
        }
        observations = {name: normalized(value) for name, value in generated.items()}
        observations["interop"] = {
            "go-key-in-rust": convert(
                binaries["rust"], generated["go"]["secret"], root / "interop"
            )
            == generated["go"]["public"],
            "rust-key-in-go": convert(
                binaries["go"], generated["rust"]["secret"], root / "interop"
            )
            == generated["rust"]["public"],
        }
        expected = {
            "exit-code": 0,
            "layout": "three-lines",
            "timestamp": "rfc3339",
            "public-prefix": True,
            "secret-prefix": True,
            "stderr": False,
            "config-created": False,
        }
        mismatch = observations["go"] != observations["rust"] or observations["go"] != expected
        if mismatch or observations["interop"] != {"go-key-in-rust": True, "rust-key-in-go": True}:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A4d mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A4d age keygen differential passed")


if __name__ == "__main__":
    main()

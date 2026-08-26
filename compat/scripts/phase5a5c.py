#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A5c domain MRS decoding."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import IO_DEADLINE, ROOT, RUST_ROOT, assert_go_oracle_baseline


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a5c-diff.json"


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
            "PHASE5A5C_CARGO_TARGET", ROOT / "target" / "compat" / "phase5a5c-rust"
        )
    )
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


def decode(
    binary: pathlib.Path,
    source: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    target = scratch / "decoded.txt"
    result = run(
        binary,
        ["convert-ruleset", "domain", "mrs", str(source), str(target), "ignored"],
        scratch,
    )
    return {
        "exit-code": result.returncode,
        "stdout": result.stdout.decode(errors="replace"),
        "stderr-present": bool(result.stderr),
        "target-created": target.exists(),
        "target": target.read_text() if target.exists() else None,
        "config-created": (scratch / ".config" / "mihomo" / "config.yaml").exists(),
    }


def malformed(
    binary: pathlib.Path,
    source: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    target = scratch / "decoded.txt"
    result = run(
        binary,
        ["convert-ruleset", "domain", "mrs", str(source), str(target)],
        scratch,
    )
    return {
        "exit-code": result.returncode,
        "stdout": result.stdout.decode(errors="replace"),
        "stderr-present": bool(result.stderr),
        "target-created": target.exists(),
        "target-size": target.stat().st_size if target.exists() else None,
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a5c-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        source = root / "domains.txt"
        source.write_text(
            "# deterministic trie\n"
            "exact.example\n"
            "*.wild.example\n"
            "+.suffix.example\n"
            "EXAMPLE.ORG\n"
        )
        mrs = root / "domains.mrs"
        encoded = run(
            binaries["go"],
            ["convert-ruleset", "domain", "text", str(source), str(mrs)],
            root / "encode",
        )
        if encoded.returncode != 0:
            raise SystemExit(f"Go fixture generation failed: {encoded.stderr.decode()}")

        observations: dict[str, Any] = {
            name: decode(binary, mrs, root / name)
            for name, binary in binaries.items()
        }
        broken = root / "broken.mrs"
        broken.write_bytes(b"not-zstd")
        observations["malformed"] = {
            name: malformed(binary, broken, root / f"malformed-{name}")
            for name, binary in binaries.items()
        }
        expected = {
            "exit-code": 0,
            "stdout": "",
            "stderr-present": False,
            "target-created": True,
            "target": "*.wild.example\n+.suffix.example\nexact.example\nexample.org\n",
            "config-created": False,
        }
        expected_malformed = {
            "exit-code": 2,
            "stdout": "",
            "stderr-present": True,
            "target-created": True,
            "target-size": 0,
        }
        mismatch = (
            observations["go"] != expected
            or observations["rust"] != expected
            or observations["malformed"]
            != {"go": expected_malformed, "rust": expected_malformed}
        )
        if mismatch:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A5c mismatch; see {FAILURE_ARTIFACT}")

    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A5c domain MRS decoding differential passed")


if __name__ == "__main__":
    main()

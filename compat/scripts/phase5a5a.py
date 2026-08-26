#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A5a IP-CIDR MRS decoding."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import IO_DEADLINE, ROOT, RUST_ROOT, assert_go_oracle_baseline


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a5a-diff.json"


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
            "PHASE5A5A_CARGO_TARGET", ROOT / "target" / "compat" / "phase5a5a-rust"
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


def observe_decode(
    binary: pathlib.Path,
    source: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    target = scratch / "decoded.txt"
    result = run(
        binary,
        ["convert-ruleset", "ipcidr", "mrs", str(source), str(target), "ignored"],
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


def observe_error(
    binary: pathlib.Path,
    arguments: list[str],
    scratch: pathlib.Path,
) -> dict[str, Any]:
    result = run(binary, arguments, scratch)
    return {
        "exit-code": result.returncode,
        "stdout": result.stdout.decode(errors="replace"),
        "stderr-present": bool(result.stderr),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a5a-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)

        source = root / "source.txt"
        source.write_text(
            "# deterministic merged ranges\n"
            "192.0.2.0/25\n"
            "192.0.2.128/25\n"
            "198.51.100.4/31\n"
            "2001:db8::/127\n"
            "2001:db8::2/127\n"
        )
        mrs = root / "oracle.mrs"
        encoded = run(
            binaries["go"],
            ["convert-ruleset", "ipcidr", "text", str(source), str(mrs)],
            root / "encode",
        )
        if encoded.returncode != 0:
            raise SystemExit(f"Go fixture generation failed: {encoded.stderr.decode()}")

        observations: dict[str, Any] = {
            name: observe_decode(binary, mrs, root / name)
            for name, binary in binaries.items()
        }
        observations["missing-arguments"] = {
            name: observe_error(binary, ["convert-ruleset"], root / f"missing-{name}")
            for name, binary in binaries.items()
        }
        observations["invalid-behavior"] = {
            name: observe_error(
                binary,
                ["convert-ruleset", "unknown", "mrs", "missing", "target"],
                root / f"behavior-{name}",
            )
            for name, binary in binaries.items()
        }
        observations["invalid-format"] = {
            name: observe_error(
                binary,
                ["convert-ruleset", "ipcidr", "unknown", "missing", "target"],
                root / f"format-{name}",
            )
            for name, binary in binaries.items()
        }

        expected_decode = {
            "exit-code": 0,
            "stdout": "",
            "stderr-present": False,
            "target-created": True,
            "target": "192.0.2.0/24\n198.51.100.4/31\n2001:db8::/126\n",
            "config-created": False,
        }
        error_cases_match = all(
            case["go"] == case["rust"]
            and case["go"]["exit-code"] == 2
            and case["go"]["stderr-present"]
            for case in (
                observations["missing-arguments"],
                observations["invalid-behavior"],
                observations["invalid-format"],
            )
        )
        mismatch = (
            observations["go"] != expected_decode
            or observations["rust"] != expected_decode
            or not error_cases_match
        )
        if mismatch:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A5a mismatch; see {FAILURE_ARTIFACT}")

    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A5a IP-CIDR MRS decoding differential passed")


if __name__ == "__main__":
    main()

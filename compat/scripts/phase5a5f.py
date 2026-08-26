#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A5f streaming YAML rulesets."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import IO_DEADLINE, ROOT
from phase5a6b import build_binaries


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a5f-diff.json"


def run(binary: pathlib.Path, arguments: list[str], scratch: pathlib.Path) -> subprocess.CompletedProcess[bytes]:
    scratch.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [str(binary), *arguments],
        cwd=scratch,
        env={**os.environ, "HOME": str(scratch)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=IO_DEADLINE,
    )


def encode_and_cross_decode(
    binaries: dict[str, pathlib.Path],
    behavior: str,
    source: pathlib.Path,
    expected: str,
    root: pathlib.Path,
) -> dict[str, Any]:
    observation: dict[str, Any] = {}
    for encoder_name, encoder in binaries.items():
        encoded = root / f"{behavior}-{encoder_name}.mrs"
        encoded_result = run(
            encoder,
            ["convert-ruleset", behavior, "yaml", str(source), str(encoded)],
            root / f"encode-{behavior}-{encoder_name}",
        )
        decoded: dict[str, Any] = {}
        for decoder_name, decoder in binaries.items():
            target = root / f"{behavior}-{encoder_name}-{decoder_name}.txt"
            result = run(
                decoder,
                ["convert-ruleset", behavior, "mrs", str(encoded), str(target)],
                root / f"decode-{behavior}-{encoder_name}-{decoder_name}",
            )
            decoded[decoder_name] = {
                "exit-code": result.returncode,
                "stderr-present": bool(result.stderr),
                "target": target.read_text() if target.exists() else None,
            }
        observation[encoder_name] = {
            "encode-exit": encoded_result.returncode,
            "encode-stdout": encoded_result.stdout.decode(errors="replace"),
            "encode-stderr-present": bool(encoded_result.stderr),
            "target-nonempty": encoded.exists() and encoded.stat().st_size > 0,
            "decode": decoded,
        }
    expected_decode = {"exit-code": 0, "stderr-present": False, "target": expected}
    expected_encoder = {
        "encode-exit": 0,
        "encode-stdout": "",
        "encode-stderr-present": False,
        "target-nonempty": True,
        "decode": {"go": expected_decode, "rust": expected_decode},
    }
    observation["matches"] = observation["go"] == observation["rust"] == expected_encoder
    return observation


def one_line_error(binary: pathlib.Path, source: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    target = scratch / "target.mrs"
    result = run(
        binary,
        ["convert-ruleset", "domain", "yaml", str(source), str(target)],
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
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a5f-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5A5F_CARGO_TARGET")
        domains = root / "domains.yaml"
        domains.write_text(
            "metadata:\n  - ignored\npayload:\n  - EXACT.example\n  - [broken\n  - later.example\n"
        )
        cidrs = root / "cidrs.yaml"
        cidrs.write_text(
            "metadata:\n  owner: ignored\nrules:\n  - 192.0.2.0/25\n  - [broken\n  - 192.0.2.128/25\n"
        )
        one_line = root / "one-line.yaml"
        one_line.write_text("payload: [one.example]")
        observations: dict[str, Any] = {
            "domain": encode_and_cross_decode(
                binaries,
                "domain",
                domains,
                "exact.example\nlater.example\n",
                root,
            ),
            "ipcidr": encode_and_cross_decode(
                binaries,
                "ipcidr",
                cidrs,
                "192.0.2.0/24\n",
                root,
            ),
            "one-line": {
                name: one_line_error(binary, one_line, root / f"one-line-{name}")
                for name, binary in binaries.items()
            },
        }
        expected_error = {
            "exit-code": 2,
            "stdout": "",
            "stderr-present": True,
            "target-created": True,
            "target-size": 0,
        }
        mismatch = (
            not observations["domain"]["matches"]
            or not observations["ipcidr"]["matches"]
            or observations["one-line"] != {"go": expected_error, "rust": expected_error}
        )
        if mismatch:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A5f mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A5f streaming YAML ruleset differential passed")


if __name__ == "__main__":
    main()

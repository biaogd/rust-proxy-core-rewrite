#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A6d VLESS X25519 generation."""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import IO_DEADLINE, ROOT
from phase5a6b import build_binaries, decode_raw_url, x25519_public


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a6d-diff.json"


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


def normalized_success(result: subprocess.CompletedProcess[bytes], scratch: pathlib.Path) -> dict[str, Any]:
    lines = result.stdout.decode(errors="replace").splitlines()
    try:
        private_text = lines[0].removeprefix("PrivateKey: ")
        password_text = lines[1].removeprefix("Password: ")
        hash_text = lines[2].removeprefix("Hash32: ")
        private = decode_raw_url(private_text)
        password = decode_raw_url(password_text)
        hash32 = decode_raw_url(hash_text)
        related = x25519_public(private) == password
        layout = (
            len(lines) == 8
            and lines[3:6] == ["-----------------------", "      Lazy-Config      ", "-----------------------"]
            and lines[6] == f'[Server] decryption: "mlkem768x25519plus.native.600s.{private_text}"'
            and lines[7] == f'[Client] encryption: "mlkem768x25519plus.native.0rtt.{password_text}"'
            and len(private) == len(password) == len(hash32) == 32
        )
    except (IndexError, ValueError):
        related = layout = False
    return {
        "exit-code": result.returncode,
        "layout": layout,
        "public-related": related,
        "stderr-present": bool(result.stderr),
        "config-created": (scratch / ".config" / "mihomo" / "config.yaml").exists(),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a6d-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5A6D_CARGO_TARGET")
        fixed = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
        successes = {
            name: run(
                binary,
                ["generate", "vless-x25519", fixed, "ignored"],
                root / f"fixed-{name}",
            )
            for name, binary in binaries.items()
        }
        invalid = {
            name: run(
                binary,
                ["generate", "vless-x25519", "too-short"],
                root / f"invalid-{name}",
            )
            for name, binary in binaries.items()
        }
        observations: dict[str, Any] = {
            "fixed": {
                name: normalized_success(result, root / f"fixed-{name}")
                for name, result in successes.items()
            },
            "fixed-output-identical": successes["go"].stdout == successes["rust"].stdout,
            "invalid": {
                name: {
                    "exit-code": result.returncode,
                    "stdout": result.stdout.decode(errors="replace"),
                    "stderr-present": bool(result.stderr),
                }
                for name, result in invalid.items()
            },
        }
        expected_success = {
            "exit-code": 0,
            "layout": True,
            "public-related": True,
            "stderr-present": False,
            "config-created": False,
        }
        expected_invalid = {"exit-code": 2, "stdout": "", "stderr-present": True}
        mismatch = (
            observations["fixed"] != {"go": expected_success, "rust": expected_success}
            or not observations["fixed-output-identical"]
            or observations["invalid"] != {"go": expected_invalid, "rust": expected_invalid}
        )
        if mismatch:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A6d mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A6d VLESS X25519 generation differential passed")


if __name__ == "__main__":
    main()

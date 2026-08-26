#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A6c WireGuard X25519 keypairs."""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import IO_DEADLINE, ROOT
from phase5a6b import build_binaries, x25519_public


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a6c-diff.json"


def observe(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [str(binary), "generate", "wg-keypair", "ignored"],
        cwd=scratch,
        env={**os.environ, "HOME": str(scratch)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=IO_DEADLINE,
    )
    lines = result.stdout.decode(errors="replace").splitlines()
    try:
        private_text = lines[0].removeprefix("PrivateKey: ")
        public_text = lines[1].removeprefix("PublicKey: ")
        private = base64.b64decode(private_text, validate=True)
        public = base64.b64decode(public_text, validate=True)
        valid = (
            len(lines) == 2
            and lines[0].startswith("PrivateKey: ")
            and lines[1].startswith("PublicKey: ")
            and len(private_text) == len(public_text) == 44
            and private_text.endswith("=")
            and public_text.endswith("=")
            and len(private) == len(public) == 32
        )
        clamped = private[0] & 7 == 0 and private[31] & 0x80 == 0 and private[31] & 0x40 != 0
        related = x25519_public(private) == public
    except (IndexError, ValueError):
        valid = clamped = related = False
    return {
        "exit-code": result.returncode,
        "two-labeled-standard-base64-lines": valid,
        "private-clamped": clamped,
        "public-related": related,
        "stderr-present": bool(result.stderr),
        "config-created": (scratch / ".config" / "mihomo" / "config.yaml").exists(),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a6c-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5A6C_CARGO_TARGET")
        observations = {
            name: observe(binary, root / name) for name, binary in binaries.items()
        }
        expected = {
            "exit-code": 0,
            "two-labeled-standard-base64-lines": True,
            "private-clamped": True,
            "public-related": True,
            "stderr-present": False,
            "config-created": False,
        }
        if observations != {"go": expected, "rust": expected}:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A6c mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A6c WireGuard X25519 keypair differential passed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Go/Rust differential for shared extra SIP004 AEAD ciphers."""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
from typing import Any

from phase1 import ROOT, cargo_target_path
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks_legacy import exercise_cipher


FAILURE_ARTIFACT = (
    ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-extra-aead-diff.json"
)
CIPHERS = (
    "xchacha20-ietf-poly1305",
    "aes-128-ccm",
    "aes-256-ccm",
    "aes-128-gcm-siv",
    "aes-256-gcm-siv",
)


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSSEXTRAAEAD_CARGO_TARGET", "phase6c-shadowsocks-extra-aead"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def exercise(
    binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    observations = {}
    for cipher in CIPHERS:
        cipher_scratch = scratch / cipher
        cipher_scratch.mkdir()
        observations[cipher] = exercise_cipher(
            binary, authority, cipher_scratch, cipher
        )
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(
        prefix="phase6c-shadowsocks-extra-aead-"
    ) as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE6CSSEXTRAAEAD_CARGO_TARGET",
            "phase6c-shadowsocks-extra-aead",
        )
        authority = authority_binary()
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, authority, scratch)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "error": f"{type(error).__name__}: {error}",
                        "observations": observations,
                        "debug": debug_files(root),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            raise
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6C-H extra Shadowsocks AEAD TCP/UDP differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

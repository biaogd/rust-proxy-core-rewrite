#!/usr/bin/env python3
"""Go/Rust differential for single-hop Shadowsocks 2022 EIH over TCP."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import ROOT, cargo_target_path
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks_2022 import exercise_tcp_cipher, validation_config


FAILURE_ARTIFACT = (
    ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-2022-eih-diff.json"
)
KEY_128 = "AAECAwQFBgcICQoLDA0ODw=="
USER_KEY_128 = "EBESExQVFhcYGRobHB0eHw=="
KEY_256 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
USER_KEY_256 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
CASES = (
    ("2022-blake3-aes-128-gcm", KEY_128, USER_KEY_128),
    ("2022-blake3-aes-256-gcm", KEY_256, USER_KEY_256),
)


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSS2022EIH_CARGO_TARGET", "phase6c-shadowsocks-2022-eih"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def validate_eih(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    cases = (
        (
            "valid-aes128-single-hop",
            "2022-blake3-aes-128-gcm",
            f"{KEY_128}:{USER_KEY_128}",
        ),
        (
            "valid-aes256-single-hop",
            "2022-blake3-aes-256-gcm",
            f"{KEY_256}:{USER_KEY_256}",
        ),
        (
            "invalid-aes128-user-length",
            "2022-blake3-aes-128-gcm",
            f"{KEY_128}:{USER_KEY_256}",
        ),
        (
            "invalid-aes128-user-base64",
            "2022-blake3-aes-128-gcm",
            f"{KEY_128}:not-base64",
        ),
        (
            "unsupported-chacha-eih",
            "2022-blake3-chacha20-poly1305",
            f"{KEY_256}:{USER_KEY_256}",
        ),
    )
    observations = {}
    for label, cipher, password in cases:
        config = scratch / f"{label}.yaml"
        config.write_text(validation_config(cipher, password))
        result = subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        observations[label] = result.returncode == 0
    return observations


def exercise(
    binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    validation = scratch / "validation"
    validation.mkdir()
    observations: dict[str, Any] = {"eih-validation": validate_eih(binary, validation)}
    for cipher, server_key, user_key in CASES:
        cipher_scratch = scratch / cipher
        cipher_scratch.mkdir()
        observations[cipher] = exercise_tcp_cipher(
            binary,
            authority,
            cipher_scratch,
            cipher,
            f"{server_key}:{user_key}",
            authority_password=server_key,
            authority_user_key=user_key,
        )
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-2022-eih-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE6CSS2022EIH_CARGO_TARGET",
            "phase6c-shadowsocks-2022-eih",
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
    print("Phase 6C-J Shadowsocks 2022 single-hop EIH differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

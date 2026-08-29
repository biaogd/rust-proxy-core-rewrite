#!/usr/bin/env python3
"""Go/Rust differential for Shadowsocks 2022 ChaCha8 TCP."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import ROOT, cargo_target_path
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks_2022 import KEY_128, KEY_256, exercise_tcp_cipher, validation_config


FAILURE_ARTIFACT = (
    ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-2022-chacha8-diff.json"
)
CIPHER = "2022-blake3-chacha8-poly1305"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSS2022CHACHA8_CARGO_TARGET",
        "phase6c-shadowsocks-2022-chacha8",
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def validate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    cases = (
        ("valid", KEY_256),
        ("invalid-base64", "not-base64"),
        ("invalid-length", KEY_128),
        ("unsupported-eih", f"{KEY_256}:{KEY_256}"),
    )
    observations = {}
    for label, password in cases:
        config = scratch / f"{label}.yaml"
        config.write_text(validation_config(CIPHER, password))
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
    wire = scratch / "wire"
    wire.mkdir()
    return {
        "key-validation": validate(binary, validation),
        "tcp": exercise_tcp_cipher(binary, authority, wire, CIPHER, KEY_256),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(
        prefix="phase6c-shadowsocks-2022-chacha8-"
    ) as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE6CSS2022CHACHA8_CARGO_TARGET",
            "phase6c-shadowsocks-2022-chacha8",
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
    print("Phase 6C-K Shadowsocks 2022 ChaCha8 TCP differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

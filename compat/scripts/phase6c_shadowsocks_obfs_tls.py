#!/usr/bin/env python3
"""Go/Rust differential for Shadowsocks simple-obfs TLS TCP."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import ROOT, cargo_target_path
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks import CIPHER, PASSWORD
from phase6c_shadowsocks_2022 import exercise_tcp_cipher
from phase6c_shadowsocks_obfs_http import config_text


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-obfs-tls-diff.json"
HOST = "phase6c-tls.example"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSSOBFSTLS_CARGO_TARGET", "phase6c-shadowsocks-obfs-tls"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def validate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    cases = (
        (
            "valid-custom-host",
            "    plugin: obfs\n    plugin-opts:\n      mode: tls\n      host: phase6c-tls.example\n",
        ),
        ("valid-default-host", "    plugin: obfs\n    plugin-opts:\n      mode: tls\n"),
        ("invalid-mode", "    plugin: obfs\n    plugin-opts:\n      mode: quic\n"),
    )
    observations = {}
    for label, plugin in cases:
        config = scratch / f"{label}.yaml"
        config.write_text(config_text(plugin))
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
        "config": validate(binary, validation),
        "wire": exercise_tcp_cipher(
            binary,
            authority,
            wire,
            CIPHER,
            PASSWORD,
            plugin_mode="tls",
            plugin_host=HOST,
        ),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-obfs-tls-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE6CSSOBFSTLS_CARGO_TARGET", "phase6c-shadowsocks-obfs-tls"
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
    print("Phase 6C-M2 Shadowsocks simple-obfs TLS differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

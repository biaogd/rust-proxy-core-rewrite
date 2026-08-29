#!/usr/bin/env python3
"""Go/Rust differential for Shadowsocks simple-obfs HTTP TCP."""

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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-obfs-http-diff.json"
HOST = "phase6c.example"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSSOBFSHTTP_CARGO_TARGET", "phase6c-shadowsocks-obfs-http"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def config_text(plugin: str, *, udp: bool = False) -> str:
    udp_line = "    udp: true\n" if udp else ""
    return f"""mixed-port: 17890
mode: rule
log-level: info
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: {CIPHER}
    password: {PASSWORD}
{plugin}{udp_line}rules:
  - MATCH,local-ss
"""


def validate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    cases = (
        (
            "valid-custom-host",
            "    plugin: obfs\n    plugin-opts:\n      mode: http\n      host: phase6c.example\n",
            False,
        ),
        (
            "valid-default-host",
            "    plugin: obfs\n    plugin-opts:\n      mode: http\n",
            False,
        ),
        (
            "valid-native-udp",
            "    plugin: obfs\n    plugin-opts:\n      mode: http\n",
            True,
        ),
        ("invalid-missing-options", "    plugin: obfs\n", False),
        (
            "invalid-mode",
            "    plugin: obfs\n    plugin-opts:\n      mode: websocket\n",
            False,
        ),
    )
    observations = {}
    for label, plugin, udp in cases:
        config = scratch / f"{label}.yaml"
        config.write_text(config_text(plugin, udp=udp))
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
            plugin_mode="http",
            plugin_host=HOST,
        ),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-obfs-http-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE6CSSOBFSHTTP_CARGO_TARGET", "phase6c-shadowsocks-obfs-http"
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
    print("Phase 6C-M1 Shadowsocks simple-obfs HTTP differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

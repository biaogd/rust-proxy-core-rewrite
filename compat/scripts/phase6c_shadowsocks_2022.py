#!/usr/bin/env python3
"""Go/Rust differential for standard Shadowsocks 2022 methods."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import (
    EchoHandler,
    HalfCloseHandler,
    ROOT,
    cargo_target_path,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks import start_authority
from phase6c_shadowsocks_ciphers import LARGE_PAYLOAD, echo, half_close, wait_route


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-2022-diff.json"
KEY_128 = "AAECAwQFBgcICQoLDA0ODw=="
KEY_256 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
CIPHERS = (
    ("2022-blake3-aes-128-gcm", KEY_128),
    ("2022-blake3-aes-256-gcm", KEY_256),
    ("2022-blake3-chacha20-poly1305", KEY_256),
)


def authority_binary() -> pathlib.Path:
    target = cargo_target_path("PHASE6CSS2022_CARGO_TARGET", "phase6c-shadowsocks-2022")
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def validation_config(cipher: str, password: str) -> str:
    return f"""mixed-port: 17890
mode: rule
log-level: info
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: {cipher}
    password: {password}
rules:
  - MATCH,local-ss
"""


def validate_keys(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    cases = (
        ("valid-aes128", "2022-blake3-aes-128-gcm", KEY_128),
        ("valid-aes256", "2022-blake3-aes-256-gcm", KEY_256),
        ("valid-chacha", "2022-blake3-chacha20-poly1305", KEY_256),
        ("invalid-base64", "2022-blake3-aes-128-gcm", "not-base64"),
        ("invalid-aes128-length", "2022-blake3-aes-128-gcm", KEY_256),
        ("invalid-aes256-length", "2022-blake3-aes-256-gcm", KEY_128),
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


def exercise_tcp_cipher(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    cipher: str,
    password: str,
    *,
    authority_password: str | None = None,
    authority_user_key: str | None = None,
    plugin_mode: str | None = None,
    plugin_host: str | None = None,
) -> dict[str, bool]:
    tcp_echo = start_server(EchoHandler)
    half_close_server = start_server(HalfCloseHandler)
    mixed_port = reserve_port()
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority,
        scratch,
        authority_port,
        cipher,
        authority_password or password,
        authority_user_key,
        plugin_mode,
        f"{plugin_host or 'bing.com'}:{authority_port}"
        if plugin_mode == "http"
        else plugin_host,
    )
    config = scratch / "config.yaml"
    plugin = ""
    if plugin_mode is not None:
        plugin = f"    plugin: obfs\n    plugin-opts:\n      mode: {plugin_mode}\n      host: {plugin_host or 'bing.com'}\n"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {cipher}
    password: {password}
{plugin}rules:
  - MATCH,local-ss
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_route(process, mixed_port, tcp_echo.port)
        try:
            half_close_result = half_close(mixed_port, half_close_server.port)
        except (EOFError, OSError):
            half_close_result = False
        return {
            "tcp-domain": echo(mixed_port, "localhost", tcp_echo.port, b"domain"),
            "tcp-ipv4-large": echo(
                mixed_port, "127.0.0.1", tcp_echo.port, LARGE_PAYLOAD
            ),
            "tcp-half-close": half_close_result,
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        tcp_echo.close()
        half_close_server.close()


def exercise(
    binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    validation = scratch / "validation"
    validation.mkdir()
    observations: dict[str, Any] = {"key-validation": validate_keys(binary, validation)}
    for cipher, password in CIPHERS:
        cipher_scratch = scratch / cipher
        cipher_scratch.mkdir()
        observations[cipher] = exercise_tcp_cipher(
            binary, authority, cipher_scratch, cipher, password
        )
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-2022-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE6CSS2022_CARGO_TARGET", "phase6c-shadowsocks-2022"
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
    print("Phase 6C-I Shadowsocks 2022 TCP differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

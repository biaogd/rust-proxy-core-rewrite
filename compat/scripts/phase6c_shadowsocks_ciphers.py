#!/usr/bin/env python3
"""Go/Rust differential for the Phase 6C-B SIP004 AEAD TCP matrix."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
from typing import Any

from phase1 import (
    EchoHandler,
    HalfCloseHandler,
    IO_DEADLINE,
    ROOT,
    cargo_target_path,
    recv_exact,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files
from phase6c_shadowsocks import PASSWORD, start_authority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-ciphers-diff.json"
CIPHERS = ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305")
LARGE_PAYLOAD = bytes(range(256)) * 512
HALF_CLOSE_PAYLOAD = b"phase6c-half-close"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSSCIPHERS_CARGO_TARGET", "phase6c-shadowsocks-ciphers"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def echo(mixed_port: int, host: str, port: int, payload: bytes) -> bool:
    with connect_domain(mixed_port, host, port) as stream:
        stream.sendall(payload)
        return recv_exact(stream, len(payload)) == payload


def half_close(mixed_port: int, port: int) -> bool:
    with connect_domain(mixed_port, "localhost", port) as stream:
        stream.sendall(HALF_CLOSE_PAYLOAD)
        stream.shutdown(socket.SHUT_WR)
        expected = b"after:" + HALF_CLOSE_PAYLOAD
        return recv_exact(stream, len(expected)) == expected


def wait_route(
    process: subprocess.Popen[bytes], mixed_port: int, echo_port: int
) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during readiness with {process.returncode}")
        try:
            if echo(mixed_port, "localhost", echo_port, b"ready"):
                return
        except (AssertionError, OSError, EOFError):
            pass
        time.sleep(0.02)
    raise TimeoutError("Shadowsocks cipher route did not become ready")


def exercise_cipher(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    cipher: str,
) -> dict[str, bool]:
    echo_server = start_server(EchoHandler)
    half_close_server = start_server(HalfCloseHandler)
    mixed_port = reserve_port()
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority, scratch, authority_port, cipher
    )
    config = scratch / "config.yaml"
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
    password: {PASSWORD}
rules:
  - MATCH,local-ss
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_route(process, mixed_port, echo_server.port)
        return {
            "domain": echo(mixed_port, "localhost", echo_server.port, b"domain"),
            "ipv4-large": echo(
                mixed_port, "127.0.0.1", echo_server.port, LARGE_PAYLOAD
            ),
            "half-close": half_close(mixed_port, half_close_server.port),
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        echo_server.close()
        half_close_server.close()


def exercise(
    binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path
) -> dict[str, dict[str, bool]]:
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
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-ciphers-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE6CSSCIPHERS_CARGO_TARGET",
            "phase6c-shadowsocks-ciphers",
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
    print("Phase 6C-B Shadowsocks SIP004 AEAD TCP matrix passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

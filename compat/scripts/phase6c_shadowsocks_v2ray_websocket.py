#!/usr/bin/env python3
"""Go/Rust differential for Shadowsocks v2ray-plugin plaintext WebSocket."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
from typing import Any

from phase1 import EchoHandler, HalfCloseHandler, IO_DEADLINE, ROOT, cargo_target_path, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks import CIPHER, PASSWORD
from phase6c_shadowsocks_ciphers import LARGE_PAYLOAD, echo, half_close, wait_route


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-v2ray-websocket-diff.json"
HOST = "phase6c-ws.example"
PATH = "/shadowsocks"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSSV2RAYWS_CARGO_TARGET", "phase6c-shadowsocks-v2ray-websocket"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-websocket-authority{suffix}"


def start_authority(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    port: int,
    *,
    host: str = HOST,
    path: str = PATH,
    certificate: pathlib.Path | None = None,
    private_key: pathlib.Path | None = None,
    options: pathlib.Path | None = None,
):
    stdout = (scratch / "authority-stdout.log").open("wb")
    stderr = (scratch / "authority-stderr.log").open("wb")
    command = [str(binary), f"127.0.0.1:{port}", PASSWORD, CIPHER, host, path]
    if certificate is not None and private_key is not None:
        command.extend((str(certificate), str(private_key)))
    if options is not None:
        command.append(str(options))
    process = subprocess.Popen(
        command,
        cwd=scratch,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"WebSocket authority exited with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return process, stdout, stderr
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("WebSocket authority did not become ready")


def config_text(port: int, authority_port: int, plugin_options: str) -> str:
    return f"""mixed-port: {port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {CIPHER}
    password: {PASSWORD}
    plugin: v2ray-plugin
    plugin-opts:
{plugin_options}rules:
  - MATCH,local-ss
"""


def validate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    cases = (
        ("valid", "      mode: websocket\n      host: phase6c-ws.example\n      path: /shadowsocks\n      mux: false\n"),
    )
    observations = {}
    for label, options in cases:
        config = scratch / f"{label}.yaml"
        config.write_text(config_text(17890, 8388, options))
        result = subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        observations[label] = result.returncode == 0
    return observations


def exercise(binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    validation = scratch / "validation"
    validation.mkdir()
    echo_server = start_server(EchoHandler)
    half_close_server = start_server(HalfCloseHandler)
    mixed_port = reserve_port()
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority, scratch, authority_port
    )
    config = scratch / "config.yaml"
    config.write_text(
        config_text(
            mixed_port,
            authority_port,
            f"      mode: websocket\n      host: {HOST}\n      path: {PATH}\n      mux: false\n",
        )
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_route(process, mixed_port, echo_server.port)
        try:
            half_close_result = half_close(mixed_port, half_close_server.port)
        except (EOFError, OSError):
            half_close_result = False
        return {
            "config": validate(binary, validation),
            "wire": {
                "domain": echo(mixed_port, "localhost", echo_server.port, b"websocket"),
                "ipv4-large": echo(mixed_port, "127.0.0.1", echo_server.port, LARGE_PAYLOAD),
                "half-close": half_close_result,
                "process-alive": process.poll() is None,
            },
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


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-v2ray-ws-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE6CSSV2RAYWS_CARGO_TARGET", "phase6c-shadowsocks-v2ray-websocket"
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
                    {"error": f"{type(error).__name__}: {error}", "observations": observations, "debug": debug_files(root)},
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
    print("Phase 6C-M3 Shadowsocks v2ray-plugin WebSocket differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

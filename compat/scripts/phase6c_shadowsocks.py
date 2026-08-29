#!/usr/bin/env python3
"""Go/Rust differential for the Phase 6C-A Shadowsocks AEAD TCP slice."""

from __future__ import annotations

import http.client
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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-diff.json"
SECRET = "phase6c-shadowsocks-secret"
PASSWORD = "phase6c-password"
CIPHER = "aes-128-gcm"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path("PHASE6CSS_CARGO_TARGET", "phase6c-shadowsocks")
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def start_authority(
    binary: pathlib.Path, scratch: pathlib.Path, port: int, cipher: str = CIPHER
):
    stdout = (scratch / "authority-stdout.log").open("wb")
    stderr = (scratch / "authority-stderr.log").open("wb")
    process = subprocess.Popen(
        [str(binary), f"127.0.0.1:{port}", PASSWORD, cipher],
        cwd=scratch,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Shadowsocks authority exited with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return process, stdout, stderr
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("Shadowsocks authority did not become ready")


def proxied_echo(mixed_port: int, echo_port: int) -> bool:
    with connect_domain(mixed_port, "localhost", echo_port) as stream:
        stream.sendall(b"shadowsocks-aead-tcp")
        return recv_exact(stream, 20) == b"shadowsocks-aead-tcp"


def rejected(mixed_port: int, echo_port: int) -> bool:
    try:
        with connect_domain(mixed_port, "127.0.0.1", echo_port) as stream:
            stream.sendall(b"reject")
            return stream.recv(1) == b""
    except (AssertionError, BrokenPipeError, ConnectionResetError, EOFError):
        return True


def wait_route(process: subprocess.Popen[bytes], mixed_port: int, echo_port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during readiness with {process.returncode}")
        try:
            if proxied_echo(mixed_port, echo_port):
                return
        except (AssertionError, OSError, EOFError):
            pass
        time.sleep(0.02)
    raise TimeoutError("Shadowsocks route did not become ready")


def proxy_snapshot(controller_port: int) -> dict[str, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", controller_port, timeout=5)
    connection.request(
        "GET",
        "/proxies/local-ss",
        headers={"Authorization": f"Bearer {SECRET}"},
    )
    response = connection.getresponse()
    body = response.read()
    connection.close()
    if response.status != 200:
        raise AssertionError((response.status, body))
    payload = json.loads(body)
    return {
        "name": payload["name"],
        "type": payload["type"],
        "udp": payload["udp"],
        "uot": payload["uot"],
    }


def exercise(binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    mixed_port = reserve_port()
    controller_port = reserve_port()
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority, scratch, authority_port
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
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
rules:
  - DOMAIN,localhost,local-ss
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_route(process, mixed_port, echo.port)
        return {
            "domain-aead-tcp": proxied_echo(mixed_port, echo.port),
            "match-reject": rejected(mixed_port, echo.port),
            "controller": proxy_snapshot(controller_port),
        }
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6CSS_CARGO_TARGET", "phase6c-shadowsocks")
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
    print("Phase 6C-A Shadowsocks AEAD TCP differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

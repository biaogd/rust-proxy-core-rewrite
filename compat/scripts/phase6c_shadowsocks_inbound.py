#!/usr/bin/env python3
"""Go/Rust differential for legacy Shadowsocks ss-config inbound TCP."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import time
from typing import Any

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    cargo_target_path,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-inbound-diff.json"
PASSWORD = "phase6c-inbound-password"
CIPHER = "aes-128-gcm"
PAYLOAD = "phase6c-ss-inbound-tcp"


def client_binary() -> pathlib.Path:
    target = cargo_target_path("PHASE6CSSINBOUND_CARGO_TARGET", "phase6c-shadowsocks-inbound")
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-client{suffix}"


def proxied_echo(client: pathlib.Path, ss_port: int, echo_port: int) -> bool:
    command = [
        str(client),
        f"127.0.0.1:{ss_port}",
        PASSWORD,
        CIPHER,
        "127.0.0.1",
        str(echo_port),
        PAYLOAD,
    ]
    completed = subprocess.run(command, check=False, capture_output=True)
    return completed.returncode == 0


def wait_ss_route(process: subprocess.Popen[bytes], client: pathlib.Path, ss_port: int, echo_port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during readiness with {process.returncode}")
        try:
            if proxied_echo(client, ss_port, echo_port):
                return
        except (AssertionError, OSError, subprocess.SubprocessError):
            pass
        time.sleep(0.02)
    raise TimeoutError("Shadowsocks inbound route did not become ready")


def exercise(binary: pathlib.Path, client: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    echo = start_server(EchoHandler)
    ss_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""ss-config: ss://{CIPHER}:{PASSWORD}@127.0.0.1:{ss_port}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ss_route(process, client, ss_port, echo.port)
        return {
            "domain-aead-tcp": proxied_echo(client, ss_port, echo.port),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-inbound-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6CSSINBOUND_CARGO_TARGET", "phase6c-shadowsocks-inbound")
        client = client_binary()
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, client, scratch)
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
    print("Phase 6C-N Shadowsocks ss-config inbound TCP differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for Shadowsocks AEAD TCP outbound."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, recv_exact, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files
from phase5d_proxies import normalize, request
from phase5d_streams import wait_controller
from phase6c_fixtures import ShadowsocksAeadServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-diff.json"
PASSWORD = "phase6c-ss-pass"
ROUTE_DEADLINE = 15.0
ATTEMPT_TIMEOUT = 2.0


def proxied_route(mixed_port: int, echo_port: int) -> bool:
    with connect_domain(mixed_port, "localhost", echo_port) as stream:
        stream.settimeout(ATTEMPT_TIMEOUT)
        stream.sendall(b"ss-outbound")
        try:
            return recv_exact(stream, 12) == b"ss-outbound"
        except (EOFError, ConnectionResetError, TimeoutError, OSError):
            return False


def wait_proxy_route(process, mixed_port: int, echo_port: int) -> None:
    deadline = time.monotonic() + ROUTE_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during readiness with {process.returncode}")
        try:
            if proxied_route(mixed_port, echo_port):
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError("Shadowsocks outbound did not become ready")


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    upstream = ShadowsocksAeadServer(PASSWORD)
    time.sleep(0.2)
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: {upstream.port}
    cipher: aes-256-gcm
    password: {PASSWORD}
rules:
  - DOMAIN,localhost,local-ss
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        adapter = request(controller_port, "GET", "/proxies/local-ss")
        wait_proxy_route(process, mixed_port, echo.port)
        upstream.observations.clear()
        echoed = proxied_route(mixed_port, echo.port)
        return {
            "adapter": (adapter[0], normalize(json.loads(adapter[1]))),
            "echo": echoed,
            "upstream": upstream.observations,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        upstream.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(root, "PHASE6CSS_CARGO_TARGET", "phase6c-shadowsocks")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
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
    print("Phase 6C Shadowsocks AEAD TCP outbound differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

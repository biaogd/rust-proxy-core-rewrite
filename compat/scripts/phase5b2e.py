#!/usr/bin/env python3
"""Go/Rust live differential for Phase 5B2e TCP source-port metadata."""

from __future__ import annotations

import json
import pathlib
import socket
import tempfile
import threading
from typing import Any

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    RunningServer,
    ThreadingServer,
    recv_exact,
    recv_until,
    reserve_port,
    wait_ready,
)
from phase3 import launch, status, stop
from phase5b1a import build_binaries, debug_files
from phase5b2a import wait_route


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b2e-diff.json"


def bound_client() -> socket.socket:
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    stream.settimeout(IO_DEADLINE)
    stream.bind(("127.0.0.1", 0))
    return stream


def bound_route(
    stream: socket.socket,
    proxy_port: int,
    destination_port: int,
) -> str:
    try:
        stream.connect(("127.0.0.1", proxy_port))
        stream.sendall(
            (
                f"CONNECT 127.0.0.1:{destination_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{destination_port}\r\n\r\n"
            ).encode()
        )
        response = recv_until(stream, b"\r\n\r\n")
        if " 200 " not in status(response):
            return "reject"
        payload = b"source-port"
        stream.sendall(payload)
        return "direct" if recv_exact(stream, len(payload)) == payload else "unexpected"
    except (EOFError, ConnectionResetError, BrokenPipeError, OSError):
        return "reject"


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    server = ThreadingServer(("0.0.0.0", 0), EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    echo = RunningServer(server, thread)
    hit = bound_client()
    miss = bound_client()
    hit_port = hit.getsockname()[1]
    proxy_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {proxy_port}
mode: rule
log-level: info
ipv6: false
rules:
  - DOMAIN,localhost,DIRECT
  - SRC-PORT,{hit_port},DIRECT
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, proxy_port)
        wait_route(process, proxy_port, "localhost", echo.port, "direct")
        return {
            "source-hit": bound_route(hit, proxy_port, echo.port),
            "source-miss": bound_route(miss, proxy_port, echo.port),
        }
    finally:
        hit.close()
        miss.close()
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    debug: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b2e-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5B2E_CARGO_TARGET", "phase5b2e")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
            debug = debug_files(root)
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
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {"observations": observations, "debug": debug},
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5B2e SRC-PORT mixed-TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

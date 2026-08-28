#!/usr/bin/env python3
"""Go/Rust mixed-TCP differential for Phase 5B1a DOMAIN-REGEX."""

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
    IO_DEADLINE,
    ROOT,
    RUST_ROOT,
    assert_go_oracle_baseline,
    cargo_target_path,
    connect_proxy,
    recv_exact,
    recv_until,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, status, stop


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b1a-diff.json"


def build_binaries(
    output: pathlib.Path,
    cargo_target_variable: str = "PHASE5B1A_CARGO_TARGET",
    default_target_name: str = "phase5b1a",
) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()
    executable_suffix = ".exe" if os.name == "nt" else ""
    go_binary = output / f"go-oracle{executable_suffix}"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_binary), "."],
        cwd=ROOT,
        check=True,
    )
    target = cargo_target_path(cargo_target_variable, default_target_name)
    subprocess.run(
        ["cargo", "build", "--workspace", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {
        "go": go_binary,
        "rust": target / "debug" / f"rewrite-core{executable_suffix}",
    }


def connect_domain(proxy_port: int, host: str, destination_port: int) -> socket.socket:
    stream = connect_proxy(proxy_port)
    stream.sendall(
        (
            f"CONNECT {host}:{destination_port} HTTP/1.1\r\n"
            f"Host: {host}:{destination_port}\r\n\r\n"
        ).encode()
    )
    response = recv_until(stream, b"\r\n\r\n")
    if " 200 " not in status(response):
        stream.close()
        raise AssertionError(response)
    return stream


def route(proxy_port: int, host: str, destination_port: int) -> str:
    with connect_domain(proxy_port, host, destination_port) as stream:
        try:
            stream.sendall(b"rule-route")
            return "direct" if recv_exact(stream, 10) == b"rule-route" else "unexpected"
        except (EOFError, ConnectionResetError, BrokenPipeError):
            return "reject"


def wait_route(process: subprocess.Popen[bytes], proxy_port: int, host: str, destination_port: int, expected: str) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during readiness with {process.returncode}")
        try:
            if route(proxy_port, host, destination_port) == expected:
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError(f"DOMAIN-REGEX route did not become {expected}")


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    proxy_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {proxy_port}
mode: rule
log-level: info
ipv6: false
rules:
  - DOMAIN-REGEX,^(?=LOCAL)local{{1,2}}host$,DIRECT
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, proxy_port)
        wait_route(process, proxy_port, "localhost", echo.port, "direct")
        return {
            "case-insensitive-lookahead-and-comma": route(
                proxy_port, "LOCALHOST", echo.port
            ),
            "fallback": route(proxy_port, "127.0.0.1", echo.port),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def debug_files(root: pathlib.Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): path.read_text(errors="replace")
        for path in root.rglob("*.log")
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b1a-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
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
    print("Phase 5B1a DOMAIN-REGEX mixed-TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

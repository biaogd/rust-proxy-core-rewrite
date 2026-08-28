#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A7b process shutdown."""

from __future__ import annotations

import http.client
import json
import os
import pathlib
import signal
import socket
import subprocess
import tempfile
import time
from typing import Any

from phase1 import (
    IO_DEADLINE,
    ROOT,
    RUST_ROOT,
    assert_go_oracle_baseline,
    cargo_target_path,
    connect_tunnel,
    reserve_port,
    wait_for_linux_signal_handlers,
    wait_ready,
)
from phase3 import EchoHandler, start_server


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a7b-diff.json"


def build_binaries(output: pathlib.Path) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()
    go_binary = output / "go-oracle"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_binary), "."],
        cwd=ROOT,
        check=True,
    )
    target = cargo_target_path("PHASE5A7B_CARGO_TARGET", "phase5a7b-rust")
    subprocess.run(
        ["cargo", "build", "-p", "rewrite-cli", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def wait_controller(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("candidate exited before controller readiness")
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
            connection.request("GET", "/version")
            response = connection.getresponse()
            response.read()
            connection.close()
            if response.status == 200:
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("controller did not become ready")


def wait_dns_tcp(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("candidate exited before DNS readiness")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("DNS TCP listener did not become ready")


def bind_tcp(port: int) -> None:
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen()


def bind_udp(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))


def run_case(
    binary: pathlib.Path, scratch: pathlib.Path, shutdown_signal: signal.Signals
) -> dict[str, Any]:
    scratch.mkdir(parents=True)
    echo = start_server(EchoHandler)
    mixed_port, controller_port, dns_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:{controller_port}
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  nameserver:
    - udp://127.0.0.1:9
rules:
  - MATCH,DIRECT
"""
    )
    stdout = (scratch / "stdout.log").open("wb")
    stderr = (scratch / "stderr.log").open("wb")
    process = subprocess.Popen(
        [str(binary), "-d", str(scratch), "-f", str(config)],
        cwd=scratch,
        env={**os.environ, "HOME": str(scratch)},
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    idle: socket.socket | None = None
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_dns_tcp(process, dns_port)
        idle = connect_tunnel(mixed_port, "127.0.0.1", echo.port)
        if not wait_for_linux_signal_handlers(process):
            time.sleep(0.05)

        started = time.monotonic()
        os.kill(process.pid, shutdown_signal)
        exit_code = process.wait(timeout=IO_DEADLINE)
        duration = time.monotonic() - started
        try:
            idle_closed = idle.recv(1) == b""
        except (ConnectionResetError, BrokenPipeError):
            idle_closed = True
        idle.close()
        idle = None

        bind_tcp(mixed_port)
        bind_tcp(controller_port)
        bind_tcp(dns_port)
        bind_udp(dns_port)
        return {
            "exit-code": exit_code,
            "duration": "bounded" if duration < IO_DEADLINE else "timeout",
            "idle-stream": "closed" if idle_closed else "open",
            "mixed-tcp": "released",
            "controller-tcp": "released",
            "dns-tcp": "released",
            "dns-udp": "released",
        }
    finally:
        if idle is not None:
            idle.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=IO_DEADLINE)
        stdout.close()
        stderr.close()
        echo.close()


def observe(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    return {
        "sigint": run_case(binary, scratch / "sigint", signal.SIGINT),
        "sigterm": run_case(binary, scratch / "sigterm", signal.SIGTERM),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a7b-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            name: observe(binary, root / name) for name, binary in binaries.items()
        }
        expected_case = {
            "exit-code": 0,
            "duration": "bounded",
            "idle-stream": "closed",
            "mixed-tcp": "released",
            "controller-tcp": "released",
            "dns-tcp": "released",
            "dns-udp": "released",
        }
        expected = {"sigint": expected_case, "sigterm": expected_case}
        if observations["go"] != observations["rust"] or observations["go"] != expected:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A7b mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A7b shutdown differential passed")


if __name__ == "__main__":
    main()

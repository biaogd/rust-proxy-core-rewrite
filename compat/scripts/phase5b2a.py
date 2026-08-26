#!/usr/bin/env python3
"""Go/Rust mixed-TCP differential for Phase 5B2a destination IP-SUFFIX."""

from __future__ import annotations

import json
import pathlib
import threading
import subprocess
import tempfile
import time
from typing import Any

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    RunningServer,
    ThreadingServer,
    reserve_port,
    wait_ready,
)
from phase3 import launch, stop
from phase4b import local_interface_ip
from phase5b1a import build_binaries, debug_files, route


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b2a-diff.json"


def wait_route(
    process: subprocess.Popen[bytes],
    proxy_port: int,
    host: str,
    destination_port: int,
    expected: str,
) -> None:
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
    raise TimeoutError(f"IP-SUFFIX route did not become {expected}")


def exercise_config(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    rule: str,
    probes: list[tuple[str, str]],
    fallback: str,
) -> dict[str, str]:
    server = ThreadingServer(("0.0.0.0", 0), EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    echo = RunningServer(server, thread)
    proxy_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {proxy_port}
mode: rule
log-level: info
ipv6: false
rules:
  - {rule}
  - MATCH,{fallback}
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, proxy_port)
        for host, expected in probes:
            wait_route(process, proxy_port, host, echo.port, expected)
        return {host: route(proxy_port, host, echo.port) for host, _ in probes}
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    interface_ip = local_interface_ip()
    if interface_ip is None:
        return {"skipped": "no-nonloopback-ipv4-interface"}
    interface_octets = bytes(int(part) for part in interface_ip.split("."))
    loopback_octets = bytes((127, 0, 0, 1))
    suffix_bits = next(
        width * 8
        for width in range(1, 5)
        if interface_octets[-width:] != loopback_octets[-width:]
    )
    literal = scratch / "literal"
    literal.mkdir()
    invalid = scratch / "invalid.yaml"
    invalid.write_text("rules:\n  - IP-SUFFIX,127.0.0.1/33,DIRECT\n")
    validation = subprocess.run(
        [str(binary), "-t", "-f", str(invalid)],
        cwd=scratch,
        capture_output=True,
        check=False,
    )
    return {
        "literal": exercise_config(
            binary,
            literal,
            f"IP-SUFFIX,{interface_ip}/{suffix_bits},DIRECT,no-resolve",
            [(interface_ip, "direct"), ("127.0.0.1", "reject")],
            "REJECT",
        ),
        "invalid-width-accepted": validation.returncode == 0,
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b2a-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5B2A_CARGO_TARGET", "phase5b2a")
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
    print("Phase 5B2a destination IP-SUFFIX mixed-TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

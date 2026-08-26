#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A7a invalid-reload recovery."""

from __future__ import annotations

import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time
from typing import Any

from phase1 import (
    IO_DEADLINE,
    ROOT,
    RUST_ROOT,
    assert_go_oracle_baseline,
    reserve_port,
    wait_for_linux_signal_handlers,
)
from phase3 import EchoHandler, route_behavior, start_server, wait_ready, wait_route
from phase4 import stop


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a7a-diff.json"


def build_binaries(output: pathlib.Path) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()
    go_binary = output / "go-oracle"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_binary), "."],
        cwd=ROOT,
        check=True,
    )
    target = pathlib.Path(
        os.environ.get(
            "PHASE5A7A_CARGO_TARGET", ROOT / "target" / "compat" / "phase5a7a-rust"
        )
    )
    subprocess.run(
        ["cargo", "build", "-p", "rewrite-cli", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def write_config(path: pathlib.Path, port: int, target: str) -> None:
    path.write_text(
        f"""mixed-port: {port}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,{target}
"""
    )


def observe(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True)
    echo = start_server(EchoHandler)
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    write_config(config, mixed_port, "DIRECT")
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
    try:
        wait_ready(process, mixed_port)
        wait_route(process, mixed_port, echo.port, "direct")
        wait_for_linux_signal_handlers(process)

        config.write_text("mixed-port: [")
        os.kill(process.pid, signal.SIGHUP)
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError("candidate exited after an invalid reload")
            if route_behavior(mixed_port, echo.port) != "direct":
                raise AssertionError("invalid reload changed the active generation")
            time.sleep(0.02)

        write_config(config, mixed_port, "REJECT")
        os.kill(process.pid, signal.SIGHUP)
        wait_route(process, mixed_port, echo.port, "reject")
        return {
            "invalid-reload": "old-generation-active",
            "following-valid-reload": "reject",
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=IO_DEADLINE)
        stdout.close()
        stderr.close()
        echo.close()


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a7a-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            name: observe(binary, root / name) for name, binary in binaries.items()
        }
        expected = {
            "invalid-reload": "old-generation-active",
            "following-valid-reload": "reject",
            "exit-code": 0,
        }
        if observations["go"] != observations["rust"] or observations["go"] != expected:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A7a mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A7a invalid-reload recovery differential passed")


if __name__ == "__main__":
    main()

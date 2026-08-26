#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A2b geodata-mode CLI default."""

from __future__ import annotations

import json
import http.client
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
from phase4 import stop


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a2b-diff.json"


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
            "PHASE5A2B_CARGO_TARGET", ROOT / "target" / "compat" / "phase5a2b-rust"
        )
    )
    subprocess.run(
        ["cargo", "build", "-p", "rewrite-cli", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def config_text(mixed_port: int, controller_port: int, explicit: bool | None) -> str:
    geodata = "" if explicit is None else f"geodata-mode: {str(explicit).lower()}\n"
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
{geodata}external-controller: 127.0.0.1:{controller_port}
rules:
  - MATCH,DIRECT
"""


def read_geodata_mode(process: subprocess.Popen[bytes], port: int) -> bool:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("candidate exited before controller became ready")
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
            connection.request("GET", "/configs")
            response = connection.getresponse()
            body = response.read()
            connection.close()
            if response.status == 200:
                value = json.loads(body)["geodata-mode"]
                if not isinstance(value, bool):
                    raise AssertionError(f"invalid geodata-mode value: {value!r}")
                return value
        except (OSError, TimeoutError):
            time.sleep(0.02)
    raise TimeoutError("controller did not become ready")


def run_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    cli_mode: bool,
    explicit: bool | None,
) -> dict[str, Any]:
    scratch.mkdir(parents=True)
    controller_port = reserve_port()
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(config_text(mixed_port, controller_port, explicit))
    arguments = [str(binary), "-d", str(scratch), "-f", str(config)]
    if cli_mode:
        arguments.insert(1, "-m")
    stdout = (scratch / "stdout.log").open("wb")
    stderr = (scratch / "stderr.log").open("wb")
    process = subprocess.Popen(
        arguments,
        cwd=scratch,
        env={**os.environ, "HOME": str(scratch)},
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    try:
        mode = read_geodata_mode(process, controller_port)
        wait_for_linux_signal_handlers(process)
        return {"geodata-mode": mode, "exit-code": stop(process)}
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=IO_DEADLINE)
        stdout.close()
        stderr.close()


def observe(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    return {
        "default-disabled": run_case(
            binary, scratch / "default-disabled", cli_mode=False, explicit=None
        ),
        "cli-enables-default": run_case(
            binary, scratch / "cli-enabled", cli_mode=True, explicit=None
        ),
        "explicit-false-beats-cli": run_case(
            binary, scratch / "explicit-false", cli_mode=True, explicit=False
        ),
        "explicit-true-without-cli": run_case(
            binary, scratch / "explicit-true", cli_mode=False, explicit=True
        ),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a2b-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            name: observe(binary, root / name) for name, binary in binaries.items()
        }
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A2b mismatch; see {FAILURE_ARTIFACT}")
        expected = {
            "default-disabled": {"geodata-mode": False, "exit-code": 0},
            "cli-enables-default": {"geodata-mode": True, "exit-code": 0},
            "explicit-false-beats-cli": {"geodata-mode": False, "exit-code": 0},
            "explicit-true-without-cli": {"geodata-mode": True, "exit-code": 0},
        }
        if observations["go"] != expected:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A2b contract failed; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A2b geodata-mode differential passed")


if __name__ == "__main__":
    main()

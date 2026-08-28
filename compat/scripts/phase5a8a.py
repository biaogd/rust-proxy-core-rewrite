#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A8a lifecycle shell hooks."""

from __future__ import annotations

import json
import os
import pathlib
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

from phase1 import (
    IO_DEADLINE,
    ROOT,
    RUST_ROOT,
    assert_go_oracle_baseline,
    cargo_target_path,
    reserve_port,
    wait_for_linux_signal_handlers,
    wait_ready,
)


HELPER = ROOT / "compat" / "fixtures" / "hooks" / "lifecycle.py"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a8a-diff.json"
HOOK_ENV = {"CLASH_POST_UP", "CLASH_POST_DOWN"}


def build_binaries(output: pathlib.Path) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()
    go_binary = output / "go-oracle"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_binary), "."],
        cwd=ROOT,
        check=True,
    )
    target = cargo_target_path("PHASE5A8A_CARGO_TARGET", "phase5a8a-rust")
    subprocess.run(
        ["cargo", "build", "-p", "rewrite-cli", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def hook_command(
    action: str, record: pathlib.Path, ports: tuple[int, int, int]
) -> str:
    command = [sys.executable, str(HELPER), action, str(record), *map(str, ports)]
    probe = " ".join(shlex.quote(value) for value in command)
    append = f"printf '{action}:shell\\n' >> {shlex.quote(str(record))}"
    return f"{probe} && {append}"


def write_config(path: pathlib.Path, ports: tuple[int, int, int]) -> None:
    mixed, controller, dns = ports
    path.write_text(
        f"""mixed-port: {mixed}
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:{controller}
dns:
  enable: true
  listen: 127.0.0.1:{dns}
  nameserver:
    - udp://127.0.0.1:9
rules:
  - MATCH,DIRECT
"""
    )


def launch(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    arguments: list[str],
    environment_hooks: dict[str, str],
) -> tuple[
    subprocess.Popen[bytes],
    Any,
    Any,
    pathlib.Path,
    tuple[int, int, int],
]:
    scratch.mkdir(parents=True)
    ports = (reserve_port(), reserve_port(), reserve_port())
    config = scratch / "config.yaml"
    record = scratch / "hooks.log"
    write_config(config, ports)
    environment = {key: value for key, value in os.environ.items() if key not in HOOK_ENV}
    environment.update(environment_hooks)
    environment["HOME"] = str(scratch)
    stdout = (scratch / "stdout.log").open("wb")
    stderr = (scratch / "stderr.log").open("wb")
    process = subprocess.Popen(
        [str(binary), *arguments, "-d", str(scratch), "-f", str(config)],
        cwd=scratch,
        env=environment,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    return process, stdout, stderr, record, ports


def finish(
    process: subprocess.Popen[bytes], stdout: Any, stderr: Any, scratch: pathlib.Path
) -> tuple[int, str]:
    exit_code = process.wait(timeout=IO_DEADLINE)
    stdout.close()
    stderr.close()
    combined = (scratch / "stdout.log").read_text(errors="replace") + (
        scratch / "stderr.log"
    ).read_text(errors="replace")
    return exit_code, combined


def wait_record(
    process: subprocess.Popen[bytes], record: pathlib.Path, marker: str
) -> None:
    # The post-up helper probes three listeners sequentially and gives each
    # one its own bounded readiness window. The outer barrier must cover that
    # complete sequence on loaded CI runners.
    deadline = time.monotonic() + (3 * IO_DEADLINE)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"candidate exited before hook record {marker!r}")
        if record.exists() and marker in record.read_text():
            return
        time.sleep(0.02)
    raise TimeoutError(f"hook record {marker!r} did not become observable")


def run_success(
    binary: pathlib.Path, scratch: pathlib.Path, source: str
) -> dict[str, Any]:
    scratch.mkdir(parents=True)
    ports = (reserve_port(), reserve_port(), reserve_port())
    config = scratch / "config.yaml"
    record = scratch / "hooks.log"
    write_config(config, ports)
    up, down = hook_command("up", record, ports), hook_command("down", record, ports)
    arguments = ["-post-up", up, "-post-down", down] if source == "cli" else []
    hooks = {"CLASH_POST_UP": up, "CLASH_POST_DOWN": down} if source == "env" else {}
    environment = {key: value for key, value in os.environ.items() if key not in HOOK_ENV}
    environment.update(hooks)
    environment["HOME"] = str(scratch)
    stdout = (scratch / "stdout.log").open("wb")
    stderr = (scratch / "stderr.log").open("wb")
    process = subprocess.Popen(
        [str(binary), *arguments, "-d", str(scratch), "-f", str(config)],
        cwd=scratch,
        env=environment,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    try:
        wait_record(process, record, "up:shell")
        if not wait_for_linux_signal_handlers(process):
            time.sleep(0.05)
        os.kill(process.pid, signal.SIGTERM)
        exit_code, output = finish(process, stdout, stderr, scratch)
        return {
            "exit-code": exit_code,
            "events": record.read_text().splitlines(),
            "hook-error": "script error" in output,
        }
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=IO_DEADLINE)


def run_empty_override(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    process, stdout, stderr, record, ports = launch(
        binary,
        scratch,
        ["-post-up=", "-post-down="],
        {"CLASH_POST_UP": "exit 31", "CLASH_POST_DOWN": "exit 32"},
    )
    try:
        wait_ready(process, ports[0])
        if not wait_for_linux_signal_handlers(process):
            time.sleep(0.05)
        os.kill(process.pid, signal.SIGTERM)
        exit_code, output = finish(process, stdout, stderr, scratch)
        return {
            "exit-code": exit_code,
            "events": record.read_text().splitlines() if record.exists() else [],
            "hook-error": "script error" in output,
        }
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=IO_DEADLINE)


def run_up_failure(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    record = scratch / "hooks.log"
    up = f"printf 'up:failed\\n' >> {shlex.quote(str(record))}; exit 7"
    down = f"printf 'down:unexpected\\n' >> {shlex.quote(str(record))}"
    process, stdout, stderr, launched_record, _ = launch(
        binary, scratch, ["-post-up", up, "-post-down", down], {}
    )
    exit_code, output = finish(process, stdout, stderr, scratch)
    return {
        "exit-code": exit_code,
        "events": launched_record.read_text().splitlines(),
        "post-up-error": "post-up script error" in output,
    }


def run_down_failure(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    record = scratch / "hooks.log"
    up = f"printf 'up:ok\\n' >> {shlex.quote(str(record))}"
    down = f"printf 'down:failed\\n' >> {shlex.quote(str(record))}; exit 9"
    process, stdout, stderr, launched_record, ports = launch(
        binary, scratch, ["-post-up", up, "-post-down", down], {}
    )
    try:
        wait_ready(process, ports[0])
        wait_record(process, launched_record, "up:ok")
        if not wait_for_linux_signal_handlers(process):
            time.sleep(0.05)
        os.kill(process.pid, signal.SIGTERM)
        exit_code, output = finish(process, stdout, stderr, scratch)
        return {
            "exit-code": exit_code,
            "events": launched_record.read_text().splitlines(),
            "post-down-error": "post-down script error" in output,
        }
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=IO_DEADLINE)


def observe(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    return {
        "cli-success": run_success(binary, scratch / "cli-success", "cli"),
        "env-success": run_success(binary, scratch / "env-success", "env"),
        "explicit-empty": run_empty_override(binary, scratch / "explicit-empty"),
        "post-up-failure": run_up_failure(binary, scratch / "post-up-failure"),
        "post-down-failure": run_down_failure(binary, scratch / "post-down-failure"),
    }


def stable_contract(observation: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(observation)
    for name in ("cli-success", "env-success"):
        result = observation[name]
        events = result["events"]
        normalized[name] = {
            "exit-code": result["exit-code"],
            "post-up-resources-ready": "up:resources-ready" in events,
            "post-up-shell-complete": "up:shell" in events,
            "post-down-called": "down:started" in events,
            "post-down-shell-complete": "down:shell" in events,
            "hook-error": result["hook-error"],
        }
    empty = observation["explicit-empty"]
    normalized["explicit-empty"] = {
        "termination": (
            "accepted"
            if empty["exit-code"] in (0, -signal.SIGTERM)
            else empty["exit-code"]
        ),
        "events": empty["events"],
        "hook-error": empty["hook-error"],
    }
    return normalized


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a8a-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            name: observe(binary, root / name) for name, binary in binaries.items()
        }
        contracts = {
            name: stable_contract(observation)
            for name, observation in observations.items()
        }
        success = {
            "exit-code": 0,
            "post-up-resources-ready": True,
            "post-up-shell-complete": True,
            "post-down-called": True,
            "post-down-shell-complete": True,
            "hook-error": False,
        }
        expected = {
            "cli-success": success,
            "env-success": success,
            "explicit-empty": {
                "termination": "accepted",
                "events": [],
                "hook-error": False,
            },
            "post-up-failure": {
                "exit-code": 1,
                "events": ["up:failed"],
                "post-up-error": True,
            },
            "post-down-failure": {
                "exit-code": 0,
                "events": ["up:ok", "down:failed"],
                "post-down-error": True,
            },
        }
        if contracts["go"] != contracts["rust"] or contracts["go"] != expected:
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {"contracts": contracts, "resource-diagnostics": observations},
                    indent=2,
                    sort_keys=True,
                )
            )
            raise SystemExit(f"Phase 5A8a mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A8a lifecycle hook differential passed")


if __name__ == "__main__":
    main()

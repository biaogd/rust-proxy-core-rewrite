#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A3a controller CLI overrides."""

from __future__ import annotations

import http.client
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
    cargo_target_path,
    reserve_port,
    wait_for_linux_signal_handlers,
)
from phase4 import stop


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a3a-diff.json"
OVERRIDE_ENV = {
    "CLASH_OVERRIDE_EXTERNAL_CONTROLLER",
    "CLASH_OVERRIDE_SECRET",
}


def build_binaries(output: pathlib.Path) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()
    go_binary = output / "go-oracle"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_binary), "."],
        cwd=ROOT,
        check=True,
    )
    target = cargo_target_path("PHASE5A3A_CARGO_TARGET", "phase5a3a-rust")
    subprocess.run(
        ["cargo", "build", "-p", "rewrite-cli", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def request(port: int, secret: str) -> int | str:
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
        headers = {"Authorization": f"Bearer {secret}"} if secret else {}
        connection.request("GET", "/version", headers=headers)
        response = connection.getresponse()
        response.read()
        connection.close()
        return response.status
    except OSError:
        return "unreachable"


def wait_selected(process: subprocess.Popen[bytes], port: int, secret: str) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("candidate exited before overridden controller became ready")
        if request(port, secret) == 200:
            return
        time.sleep(0.02)
    raise TimeoutError("overridden controller did not become ready")


def config_mode(port: int, secret: str) -> bool | None:
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
        connection.request(
            "GET", "/configs", headers={"Authorization": f"Bearer {secret}"}
        )
        response = connection.getresponse()
        body = response.read()
        connection.close()
        if response.status != 200:
            return None
        value = json.loads(body)["geodata-mode"]
        return value if isinstance(value, bool) else None
    except OSError:
        return None


def wait_reloaded(
    process: subprocess.Popen[bytes], port: int, secret: str
) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("candidate exited during overridden reload")
        if config_mode(port, secret) is True:
            return
        time.sleep(0.02)
    raise TimeoutError("overridden reload did not become observable")


def run_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    arguments: list[str],
    environment_overrides: dict[str, str],
    selected_port: int,
    selected_secret: str,
    yaml_port: int,
    cli_port: int,
    env_port: int,
    reload_selected_secret: str,
) -> dict[str, Any]:
    scratch.mkdir(parents=True)
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    def write_config(*, geodata_mode: bool, yaml_secret: str) -> None:
        config.write_text(
            f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
geodata-mode: {str(geodata_mode).lower()}
external-controller: 127.0.0.1:{yaml_port}
secret: {yaml_secret}
rules:
  - MATCH,DIRECT
"""
        )

    write_config(geodata_mode=False, yaml_secret="yaml-secret")
    environment = {
        key: value for key, value in os.environ.items() if key not in OVERRIDE_ENV
    }
    environment.update(environment_overrides)
    environment["HOME"] = str(scratch)
    stdout = (scratch / "stdout.log").open("wb")
    stderr = (scratch / "stderr.log").open("wb")
    process = subprocess.Popen(
        [str(binary), *arguments, "-f", str(config)],
        cwd=scratch,
        env=environment,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    try:
        wait_selected(process, selected_port, selected_secret)
        observations = {
            "yaml/yaml": request(yaml_port, "yaml-secret"),
            "cli/cli": request(cli_port, "cli-secret"),
            "cli/env": request(cli_port, "env-secret"),
            "env/env": request(env_port, "env-secret"),
            "selected/empty": request(selected_port, ""),
        }
        wait_for_linux_signal_handlers(process)
        write_config(geodata_mode=True, yaml_secret="reloaded-yaml-secret")
        os.kill(process.pid, signal.SIGHUP)
        wait_reloaded(process, selected_port, reload_selected_secret)
        observations.update(
            {
                "reload/selected": request(selected_port, reload_selected_secret),
                "reload/yaml-old": request(selected_port, "yaml-secret"),
                "reload/yaml-new": request(selected_port, "reloaded-yaml-secret"),
                "reload/geodata-mode": config_mode(
                    selected_port, reload_selected_secret
                ),
            }
        )
        observations["exit-code"] = stop(process)
        return observations
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=IO_DEADLINE)
        stdout.close()
        stderr.close()


def observe(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    def ports() -> tuple[int, int, int]:
        return reserve_port(), reserve_port(), reserve_port()

    yaml_port, cli_port, env_port = ports()
    cli = run_case(
        binary,
        scratch / "cli",
        arguments=["-ext-ctl", f"127.0.0.1:{cli_port}", "-secret", "cli-secret"],
        environment_overrides={},
        selected_port=cli_port,
        selected_secret="cli-secret",
        yaml_port=yaml_port,
        cli_port=cli_port,
        env_port=env_port,
        reload_selected_secret="cli-secret",
    )

    yaml_port, cli_port, env_port = ports()
    environment = {
        "CLASH_OVERRIDE_EXTERNAL_CONTROLLER": f"127.0.0.1:{env_port}",
        "CLASH_OVERRIDE_SECRET": "env-secret",
    }
    env = run_case(
        binary,
        scratch / "env",
        arguments=[],
        environment_overrides=environment,
        selected_port=env_port,
        selected_secret="env-secret",
        yaml_port=yaml_port,
        cli_port=cli_port,
        env_port=env_port,
        reload_selected_secret="env-secret",
    )

    yaml_port, cli_port, env_port = ports()
    environment = {
        "CLASH_OVERRIDE_EXTERNAL_CONTROLLER": f"127.0.0.1:{env_port}",
        "CLASH_OVERRIDE_SECRET": "env-secret",
    }
    precedence = run_case(
        binary,
        scratch / "precedence",
        arguments=["-ext-ctl", f"127.0.0.1:{cli_port}", "-secret", "cli-secret"],
        environment_overrides=environment,
        selected_port=cli_port,
        selected_secret="cli-secret",
        yaml_port=yaml_port,
        cli_port=cli_port,
        env_port=env_port,
        reload_selected_secret="cli-secret",
    )

    yaml_port, cli_port, env_port = ports()
    environment = {
        "CLASH_OVERRIDE_EXTERNAL_CONTROLLER": f"127.0.0.1:{env_port}",
        "CLASH_OVERRIDE_SECRET": "env-secret",
    }
    empty = run_case(
        binary,
        scratch / "empty",
        arguments=["-ext-ctl", "", "-secret", ""],
        environment_overrides=environment,
        selected_port=yaml_port,
        selected_secret="yaml-secret",
        yaml_port=yaml_port,
        cli_port=cli_port,
        env_port=env_port,
        reload_selected_secret="reloaded-yaml-secret",
    )
    return {"cli": cli, "env": env, "cli-over-env": precedence, "empty": empty}


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a3a-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            name: observe(binary, root / name) for name, binary in binaries.items()
        }
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A3a mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A3a controller override differential passed")


if __name__ == "__main__":
    main()

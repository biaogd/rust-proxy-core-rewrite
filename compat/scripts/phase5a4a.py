#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A4a age-encrypted configuration."""

from __future__ import annotations

import base64
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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a4a-diff.json"
AGE_ENV = {"CLASH_AGE_SECRET_KEY", "CLASH_CONFIG_STRING"}


def build_binaries(output: pathlib.Path) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()
    go_binary = output / "go-oracle"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_binary), "."],
        cwd=ROOT,
        check=True,
    )
    target = cargo_target_path("PHASE5A4A_CARGO_TARGET", "phase5a4a-rust")
    subprocess.run(
        ["cargo", "build", "-p", "rewrite-cli", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def key_pair(go_binary: pathlib.Path) -> tuple[str, str]:
    output = subprocess.check_output([str(go_binary), "age", "keygen"], text=True)
    secret = next(line for line in output.splitlines() if line.startswith("AGE-SECRET-KEY-"))
    public = next(
        line.removeprefix("# public key: ")
        for line in output.splitlines()
        if line.startswith("# public key: ")
    )
    return secret, public


def encrypt(go_binary: pathlib.Path, public: str, plaintext: str) -> str:
    result = subprocess.run(
        [str(go_binary), "age", "encrypt", public, "-", "-"],
        input=plaintext.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return result.stdout.decode()


def config_text(mixed_port: int, controller_port: int) -> str:
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:{controller_port}
rules:
  - MATCH,DIRECT
"""


def wait_snapshot(process: subprocess.Popen[bytes], port: int) -> dict[str, Any]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("candidate exited before decrypted config became ready")
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
            connection.request("GET", "/configs")
            response = connection.getresponse()
            body = response.read()
            connection.close()
            if response.status == 200:
                return json.loads(body)
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("decrypted controller did not become ready")


def run_live(
    binary: pathlib.Path,
    go_binary: pathlib.Path,
    scratch: pathlib.Path,
    secret: str,
    public: str,
    *,
    source: str,
    environment_secret: str = "",
) -> dict[str, Any]:
    scratch.mkdir(parents=True)
    mixed_port, controller_port = reserve_port(), reserve_port()
    armor = encrypt(go_binary, public, config_text(mixed_port, controller_port))
    config = scratch / "config.yaml.age"
    arguments: list[str] = []
    environment = {key: value for key, value in os.environ.items() if key not in AGE_ENV}
    if source == "file":
        config.write_text(armor)
        arguments = ["-age-secret-key", secret, "-f", str(config)]
    elif source == "env-inline":
        environment["CLASH_AGE_SECRET_KEY"] = secret
        environment["CLASH_CONFIG_STRING"] = base64.b64encode(armor.encode()).decode()
    elif source == "cli-over-env":
        environment["CLASH_AGE_SECRET_KEY"] = environment_secret
        arguments = [
            "-age-secret-key",
            secret,
            "-config",
            base64.b64encode(armor.encode()).decode(),
        ]
    else:
        raise ValueError(source)
    environment["HOME"] = str(scratch)
    stdout = (scratch / "stdout.log").open("wb")
    stderr = (scratch / "stderr.log").open("wb")
    process = subprocess.Popen(
        [str(binary), *arguments],
        cwd=scratch,
        env=environment,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    try:
        snapshot = wait_snapshot(process, controller_port)
        if not wait_for_linux_signal_handlers(process):
            time.sleep(0.05)
        return {
            "mixed-port-applied": snapshot.get("mixed-port") == mixed_port,
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=IO_DEADLINE)
        stdout.close()
        stderr.close()


def run_encrypted_failure(
    binary: pathlib.Path,
    go_binary: pathlib.Path,
    scratch: pathlib.Path,
    correct_public: str,
    cli_secret: str,
    environment_secret: str,
) -> dict[str, Any]:
    scratch.mkdir(parents=True)
    armor = encrypt(go_binary, correct_public, config_text(reserve_port(), reserve_port()))
    environment = {key: value for key, value in os.environ.items() if key not in AGE_ENV}
    environment["HOME"] = str(scratch)
    environment["CLASH_AGE_SECRET_KEY"] = environment_secret
    result = subprocess.run(
        [
            str(binary),
            f"-age-secret-key={cli_secret}",
            "-config",
            base64.b64encode(armor.encode()).decode(),
        ],
        cwd=scratch,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=IO_DEADLINE,
    )
    output = (result.stdout + result.stderr).decode(errors="replace").lower()
    return {"exit-code": result.returncode, "decrypt-error": "decrypt config" in output}


def run_plain_invalid_key(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True)
    config = scratch / "config.yaml"
    config.write_text(config_text(reserve_port(), reserve_port()))
    result = subprocess.run(
        [str(binary), "-age-secret-key", "not-an-age-key", "-t", "-f", str(config)],
        cwd=scratch,
        env={**os.environ, "HOME": str(scratch)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=IO_DEADLINE,
    )
    output = (result.stdout + result.stderr).decode(errors="replace").lower()
    return {
        "exit-code": result.returncode,
        "validation-warning": "age-secret-key" in output,
        "config-success": "test is successful" in output,
    }


def observe(
    binary: pathlib.Path,
    go_binary: pathlib.Path,
    scratch: pathlib.Path,
    correct: tuple[str, str],
    wrong: tuple[str, str],
) -> dict[str, Any]:
    secret, public = correct
    wrong_secret, _ = wrong
    return {
        "cli-file": run_live(
            binary, go_binary, scratch / "cli-file", secret, public, source="file"
        ),
        "env-inline": run_live(
            binary,
            go_binary,
            scratch / "env-inline",
            secret,
            public,
            source="env-inline",
        ),
        "cli-over-env": run_live(
            binary,
            go_binary,
            scratch / "cli-over-env",
            secret,
            public,
            source="cli-over-env",
            environment_secret=wrong_secret,
        ),
        "wrong-key": run_encrypted_failure(
            binary,
            go_binary,
            scratch / "wrong-key",
            public,
            wrong_secret,
            "",
        ),
        "explicit-empty": run_encrypted_failure(
            binary,
            go_binary,
            scratch / "explicit-empty",
            public,
            "",
            secret,
        ),
        "plain-invalid-key": run_plain_invalid_key(binary, scratch / "plain-invalid-key"),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a4a-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        correct, wrong = key_pair(binaries["go"]), key_pair(binaries["go"])
        observations = {
            name: observe(binary, binaries["go"], root / name, correct, wrong)
            for name, binary in binaries.items()
        }
        live = {"mixed-port-applied": True, "exit-code": 0}
        expected = {
            "cli-file": live,
            "env-inline": live,
            "cli-over-env": live,
            "wrong-key": {"exit-code": 1, "decrypt-error": True},
            "explicit-empty": {"exit-code": 1, "decrypt-error": True},
            "plain-invalid-key": {
                "exit-code": 0,
                "validation-warning": True,
                "config-success": True,
            },
        }
        if observations["go"] != observations["rust"] or observations["go"] != expected:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A4a mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A4a age-encrypted configuration differential passed")


if __name__ == "__main__":
    main()

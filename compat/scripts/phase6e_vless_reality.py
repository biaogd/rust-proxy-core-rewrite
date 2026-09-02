#!/usr/bin/env python3
"""Go/Rust differential for Phase 6E-H VLESS REALITY over native TCP."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_tcp import (
    LARGE_PAYLOAD,
    STANDARD_UUID,
    config_validation,
    exchange,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-reality-diff.json"

REALITY_PUBLIC_KEY = "Cu7X8PtrU22DHCW46oyZfgEEFLoWMxJYWhHOpBIokhc"
REALITY_SHORT_ID = "10f897e26c4b9478"
REALITY_SERVER_NAME = "itunes.apple.com"


def build_authority(output: pathlib.Path) -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    binary = output / f"vless-reality-authority{suffix}"
    subprocess.run(
        [
            "go",
            "build",
            "-trimpath",
            "-o",
            str(binary),
            "./compat/helpers/vless_reality_authority",
        ],
        cwd=ROOT,
        check=True,
    )
    return binary


def start_authority(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    port: int,
    *,
    log_name: str,
) -> tuple[Any, Any, Any, pathlib.Path]:
    stdout_path = scratch / f"{log_name}-stdout.log"
    stdout = stdout_path.open("wb")
    stderr = (scratch / f"{log_name}-stderr.log").open("wb")
    command = [
        str(binary),
        "-listen",
        f"127.0.0.1:{port}",
        "-uuid",
        STANDARD_UUID,
    ]
    process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
    output = scratch / f"{log_name}-output.log"
    return process, stdout, stderr, output


def reality_record(name: str, authority_port: int) -> str:
    return f"""  - name: {name}
    type: vless
    server: 127.0.0.1
    port: {authority_port}
    uuid: {STANDARD_UUID}
    encryption: none
    network: tcp
    tls: true
    client-fingerprint: chrome
    servername: {REALITY_SERVER_NAME}
    reality-opts:
      public-key: {REALITY_PUBLIC_KEY}
      short-id: {REALITY_SHORT_ID}
"""


def wait_observations(output: pathlib.Path, expected: set[str]) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed = {
            line.strip()
            for line in output.read_text(errors="replace").splitlines()
            if line.startswith("CONNECT ")
        }
        if expected <= observed:
            return sorted(expected)
        time.sleep(0.05)
    raise TimeoutError(f"missing VLESS REALITY observations: {sorted(expected - observed)}")


def exercise(binary: pathlib.Path, scratch: pathlib.Path, authority_binary: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority_port = reserve_port()
    authority_scratch = scratch / "authority"
    authority_scratch.mkdir(parents=True, exist_ok=True)
    authority_stdout_path = authority_scratch / "reality-authority-stdout.log"
    authority_stdout = authority_stdout_path.open("wb")
    authority_stderr = (authority_scratch / "reality-authority-stderr.log").open("wb")
    authority_output = authority_scratch / "reality-authority-output.log"
    authority_process = subprocess.Popen(
        [
            str(authority_binary),
            "-listen",
            f"127.0.0.1:{authority_port}",
            "-uuid",
            STANDARD_UUID,
        ],
        stdout=authority_stdout,
        stderr=authority_stderr,
        start_new_session=True,
    )
    try:
        ready_deadline = time.monotonic() + IO_DEADLINE
        while time.monotonic() < ready_deadline:
            text = authority_stdout_path.read_text(errors="replace")
            if "READY " in text:
                break
            if authority_process.poll() is not None:
                raise RuntimeError(
                    f"reality authority exited early: {authority_stderr.read().decode(errors='replace')}"
                )
            time.sleep(0.05)
        else:
            raise TimeoutError("reality authority did not become ready")

        mixed_port, controller_port = reserve_port(), reserve_port()
        config = scratch / "config.yaml"
        config.write_text(
            f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
proxies:
{reality_record("vless-reality", authority_port)}rules:
  - DST-PORT,26022,vless-reality
  - MATCH,REJECT
"""
        )
        process, stdout, stderr = launch(binary, config, scratch)
        try:
            wait_ready(process, mixed_port)
            wait_controller(process, controller_port)
            small = exchange(mixed_port, "reality.phase6e", 26022, b"vless-reality")
            large = exchange(mixed_port, "reality-large.phase6e", 26022, LARGE_PAYLOAD)
            half_close = exchange(
                mixed_port,
                "reality-half.phase6e",
                26022,
                b"vless-reality-half",
                half_close=True,
            )
            reality_without_tls = (
                config_validation(
                    binary,
                    scratch,
                    "proxies:\n"
                    "  - name: bad\n    type: vless\n    server: 127.0.0.1\n    port: 1\n"
                    f"    uuid: {STANDARD_UUID}\n    encryption: none\n    network: tcp\n"
                    "    client-fingerprint: chrome\n    reality-opts:\n"
                    f"      public-key: {REALITY_PUBLIC_KEY}\n      short-id: {REALITY_SHORT_ID}\n",
                )
                is False
            )
            reality_without_fingerprint = (
                config_validation(
                    binary,
                    scratch,
                    "proxies:\n"
                    "  - name: bad\n    type: vless\n    server: 127.0.0.1\n    port: 1\n"
                    f"    uuid: {STANDARD_UUID}\n    encryption: none\n    network: tcp\n    tls: true\n"
                    "    servername: itunes.apple.com\n    reality-opts:\n"
                    f"      public-key: {REALITY_PUBLIC_KEY}\n      short-id: {REALITY_SHORT_ID}\n",
                )
                is False
            )
            expected = {
                "CONNECT reality.phase6e:26022",
                "CONNECT reality-large.phase6e:26022",
                "CONNECT reality-half.phase6e:26022",
            }
            authority_stdout_path.read_text(errors="replace")
            # Mirror authority CONNECT lines into a dedicated observation file.
            authority_output.write_text(authority_stdout_path.read_text(errors="replace"))
            return {
                "small": small,
                "large": large,
                "half-close": half_close,
                "reality-without-tls-rejected": reality_without_tls,
                "reality-without-fingerprint-rejected": reality_without_fingerprint,
                "authority": wait_observations(authority_output, expected),
                "process-alive": process.poll() is None,
            }
        finally:
            stop(process)
            stdout.close()
            stderr.close()
    finally:
        stop(authority_process)
        authority_stdout.close()
        authority_stderr.close()


def contract_errors(name: str, observations: dict[str, Any]) -> list[str]:
    errors = []
    for field in ["small", "large", "half-close", "process-alive"]:
        if observations[field] is not True:
            errors.append(f"{name}: {field} was not true")
    if name == "rust":
        for field in ["reality-without-tls-rejected", "reality-without-fingerprint-rejected"]:
            if observations[field] is not True:
                errors.append(f"{name}: {field} was not rejected")
    return errors


def main() -> int:
    scratch = pathlib.Path(tempfile.mkdtemp(prefix="phase6e-vless-reality-"))
    authority_binary = build_authority(scratch)
    binaries = build_binaries(scratch, "PHASE6EVLESSREALITY_CARGO_TARGET", "phase6e-h-vless")
    results: dict[str, Any] = {}
    errors: list[str] = []
    for name in ("go", "rust"):
        binary = binaries[name]
        try:
            results[name] = exercise(binary, scratch / name, authority_binary)
            errors.extend(contract_errors(name, results[name]))
        except Exception as error:
            results[name] = {"error": str(error), "debug": debug_files(scratch / name)}
            errors.append(f"{name}: {error}")
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    FAILURE_ARTIFACT.write_text(json.dumps(results, indent=2) + "\n")
    if errors:
        raise SystemExit("\n".join(errors))
    print("phase6e_vless_reality: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

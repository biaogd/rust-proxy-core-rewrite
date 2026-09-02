#!/usr/bin/env python3
"""Go/Rust differential for Phase 6E-G VLESS Vision over native TCP/TLS."""

from __future__ import annotations

import json
import pathlib
import tempfile
import textwrap
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_tcp import (
    LARGE_PAYLOAD,
    STANDARD_UUID,
    config_validation,
    exchange,
    vless_record,
)
from phase6e_vless_websocket import build_authority, start_authority, trusted_roots


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-vision-diff.json"


def vision_record(name: str, authority_port: int, *, servername: str) -> str:
    return f"""  - name: {name}
    type: vless
    server: 127.0.0.1
    port: {authority_port}
    uuid: {STANDARD_UUID}
    encryption: none
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: {servername}
    skip-cert-verify: false
"""


def wait_observations(output: pathlib.Path, expected: set[str]) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed = {
            line.strip()
            for line in output.read_text(errors="replace").splitlines()
            if line.startswith(("TLS ", "CONNECT "))
        }
        if expected <= observed:
            return sorted(expected)
        time.sleep(0.02)
    raise TimeoutError(f"missing VLESS Vision observations: {sorted(expected - observed)}")


def exercise(binary: pathlib.Path, scratch: pathlib.Path, authority_binary: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority_port = reserve_port()
    authority_scratch = scratch / "authority"
    authority_scratch.mkdir(parents=True, exist_ok=True)
    authority_process, authority_stdout, authority_stderr, authority_output = start_authority(
        authority_binary,
        authority_scratch,
        authority_port,
        log_name="vision-authority",
        transport="tcp",
        certificate=SERVER_CERTIFICATE,
        private_key=SERVER_KEY,
        flow="xtls-rprx-vision",
    )
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        trusted_roots()
        + f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
proxies:
{vision_record("vless-vision", authority_port, servername="dot.phase4.test")}rules:
  - DST-PORT,26021,vless-vision
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        small = exchange(mixed_port, "vision.phase6e", 26021, b"vless-vision")
        large = exchange(mixed_port, "vision-large.phase6e", 26021, LARGE_PAYLOAD)
        half_close = exchange(
            mixed_port, "vision-half.phase6e", 26021, b"vless-vision-half", half_close=True
        )
        flow_without_tls = (
            config_validation(
                binary,
                scratch,
                "proxies:\n"
                "  - name: bad-flow\n    type: vless\n    server: 127.0.0.1\n    port: 1\n"
                f"    uuid: {STANDARD_UUID}\n    encryption: none\n    network: tcp\n"
                "    flow: xtls-rprx-vision\n",
            )
            is False
        )
        flow_with_udp = (
            config_validation(
                binary,
                scratch,
                "proxies:\n"
                + vision_record("bad-udp", authority_port, servername="dot.phase4.test").replace(
                    "    skip-cert-verify: false\n", "    skip-cert-verify: false\n    udp: true\n"
                ),
            )
            is False
        )
        expected = {
            "TLS dot.phase4.test",
            "CONNECT vision.phase6e:26021",
            "CONNECT vision-large.phase6e:26021",
            "CONNECT vision-half.phase6e:26021",
        }
        return {
            "small": small,
            "large": large,
            "half-close": half_close,
            "flow-without-tls-rejected": flow_without_tls,
            "flow-with-udp-rejected": flow_with_udp,
            "authority": wait_observations(authority_output, expected),
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop(authority_process)
        authority_stdout.close()
        authority_stderr.close()


def contract_errors(name: str, observations: dict[str, Any]) -> list[str]:
    errors = []
    for field in ["small", "large", "half-close", "process-alive"]:
        if observations[field] is not True:
            errors.append(f"{name}: {field} was not true")
    if name == "rust":
        for field in ["flow-without-tls-rejected", "flow-with-udp-rejected"]:
            if observations[field] is not True:
                errors.append(f"{name}: {field} was not rejected")
    return errors


def main() -> int:
    scratch = pathlib.Path(tempfile.mkdtemp(prefix="phase6e-vless-vision-"))
    authority_binary = build_authority(scratch)
    binaries = build_binaries(scratch, "PHASE6EVLESSVISION_CARGO_TARGET", "phase6e-g-vless")
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
    print("phase6e_vless_vision: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

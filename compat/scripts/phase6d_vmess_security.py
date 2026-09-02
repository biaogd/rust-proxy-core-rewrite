#!/usr/bin/env python3
"""Go/Rust differential for Phase 6D-C VMess native-TCP security modes."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase6d_vmess_aead import exchange, wait_exchange
from phase6d_vmess_tcp import (
    build_authority,
    config_validation,
    start_authority,
    vmess_record,
    wait_authority_destinations,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6d-vmess-security-diff.json"


def exercise(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    mixed_port = reserve_port()
    authority_port = reserve_port()
    authority, authority_stdout, authority_stderr, authority_stdout_path = (
        start_authority(authority_binary, scratch, authority_port)
    )
    cases = [
        ("NONE", "native-none.phase6d", 23001, False),
        ("ZERO", "192.0.2.61", 23002, True),
        ("AES-128-CFB", "2001:db8::61", 23003, True),
    ]
    records = []
    rules = []
    expected_destinations: set[str] = set()
    for index, (cipher, destination, port, ignored_options) in enumerate(cases, start=1):
        name = f"vmess-security-{index}"
        records.append(
            vmess_record(
                name,
                authority_port,
                cipher=cipher,
                global_padding=ignored_options,
                authenticated_length=ignored_options,
            )
        )
        rules.append(f"  - DST-PORT,{port},{name}")
        expected_destinations.add(f"{destination}:{port}")

    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: true
proxies:
{''.join(records)}rules:
{chr(10).join(rules)}
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_exchange(process, mixed_port, cases[0][1], cases[0][2])
        results: dict[str, dict[str, bool]] = {}
        large_payload = bytes(range(256)) * 512
        for cipher, destination, port, _ in cases:
            results[cipher.lower()] = {
                "small": exchange(
                    mixed_port,
                    destination,
                    port,
                    f"{cipher}-small".encode(),
                    half_close=False,
                ),
                "large_half_close": exchange(
                    mixed_port,
                    destination,
                    port,
                    large_payload,
                    half_close=True,
                ),
            }
        observed = wait_authority_destinations(
            authority, authority_stdout_path, expected_destinations
        )
        unsupported = vmess_record(
            "unsupported-security", authority_port, cipher="aes-256-cfb"
        )
        return {
            "matrix": results,
            "destinations": observed,
            "unsupported_rejected": not config_validation(
                binary, scratch, "proxies:\n" + unsupported
            ),
            "survived": process.poll() is None,
        }
    finally:
        stop(process)
        stop(authority)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6d-vmess-security-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE6DCVMESS_CARGO_TARGET", "phase6d-c-vmess"
        )
        authority = build_authority(root)
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, authority, scratch)
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
    print("Phase 6D-C VMess native-TCP security differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

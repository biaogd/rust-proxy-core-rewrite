#!/usr/bin/env python3
"""Go/Rust differential for Phase 6D-D VMess legacy AlterID native TCP."""

from __future__ import annotations

import json
import pathlib
import tempfile
from typing import Any

from phase1 import ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase6d_vmess_aead import exchange, wait_exchange
from phase6d_vmess_tcp import (
    WRONG_UUID,
    build_authority,
    rejected_exchange,
    start_authority,
    vmess_record,
    wait_authority_destinations,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6d-vmess-alterid-diff.json"


def exercise(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    mixed_port = reserve_port()
    authority_port = reserve_port()
    authority, authority_stdout, authority_stderr, authority_stdout_path = (
        start_authority(authority_binary, scratch, authority_port, alter_id=64)
    )
    cases = [
        ("auto", "legacy-auto.phase6d", 24001, 1, False),
        ("aes-128-gcm", "192.0.2.71", 24002, 64, True),
        ("chacha20-poly1305", "2001:db8::71", 24003, 2, True),
        ("none", "legacy-none.phase6d", 24004, 1, True),
        ("aes-128-cfb", "192.0.2.72", 24005, 64, True),
    ]
    records = []
    rules = []
    expected_destinations: set[str] = set()
    for index, (cipher, destination, port, alter_id, options) in enumerate(
        cases, start=1
    ):
        name = f"legacy-vmess-{index}"
        records.append(
            vmess_record(
                name,
                authority_port,
                cipher=cipher,
                global_padding=options,
                authenticated_length=options,
                alter_id=alter_id,
            )
        )
        rules.append(f"  - DST-PORT,{port},{name}")
        expected_destinations.add(f"{destination}:{port}")

    provider_destination = "provider-legacy.phase6d"
    provider_port = 24006
    provider = scratch / ".config" / "mihomo" / "legacy-provider.yaml"
    provider.parent.mkdir(parents=True)
    provider.write_text(
        "proxies:\n"
        + vmess_record(
            "provider-legacy-vmess",
            authority_port,
            cipher="aes-128-gcm",
            global_padding=True,
            authenticated_length=True,
            alter_id=64,
        )
    )
    expected_destinations.add(f"{provider_destination}:{provider_port}")

    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: true
proxies:
{''.join(records)}{vmess_record('wrong-legacy-vmess', authority_port, uuid=WRONG_UUID, alter_id=64)}proxy-providers:
  legacy-provider:
    type: file
    path: {provider}
proxy-groups:
  - name: legacy-provider-select
    type: select
    use: [legacy-provider]
rules:
{chr(10).join(rules)}
  - DST-PORT,{provider_port},legacy-provider-select
  - DST-PORT,24099,wrong-legacy-vmess
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_exchange(process, mixed_port, cases[0][1], cases[0][2])
        large_payload = bytes(range(256)) * 512
        results: dict[str, dict[str, bool]] = {}
        for cipher, destination, port, alter_id, _ in cases:
            results[f"{cipher}:{alter_id}"] = {
                "small": exchange(
                    mixed_port,
                    destination,
                    port,
                    f"legacy-{cipher}-small".encode(),
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
        provider_ok = exchange(
            mixed_port,
            provider_destination,
            provider_port,
            b"legacy-provider",
            half_close=True,
        )
        rejected = rejected_exchange(mixed_port, "wrong-legacy.phase6d", 24099)
        observed = wait_authority_destinations(
            authority, authority_stdout_path, expected_destinations
        )
        return {
            "matrix": results,
            "provider_selector": provider_ok,
            "wrong_uuid_rejected": rejected,
            "destinations": observed,
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
    with tempfile.TemporaryDirectory(prefix="phase6d-vmess-alterid-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6DDVMESS_CARGO_TARGET", "phase6d-d-vmess")
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
    print("Phase 6D-D VMess legacy AlterID native-TCP differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

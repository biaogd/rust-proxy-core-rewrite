#!/usr/bin/env python3
"""Go/Rust differential suite for Phase 4F5 synthetic and registered DNS clients."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
from typing import Any, Callable

from phase1 import ROOT, RUST_ROOT, reserve_port
from phase4 import (
    build_binaries,
    dns_query,
    launch,
    stop,
    tcp_query,
    udp_query,
    wait_dns_ready,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f5-diff.json"
RCODES = {
    "success": 0,
    "format_error": 1,
    "server_failure": 2,
    "name_error": 3,
    "not_implemented": 4,
    "refused": 5,
}


def config_text(nameserver: str, dns_port: int) -> str:
    return f"""mixed-port: {reserve_port()}
mode: rule
log-level: info
ipv6: false
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  nameserver:
    - {nameserver}
rules:
  - MATCH,DIRECT
"""


def observe_config(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    observations: dict[str, Any] = {}
    nameservers = [
        *(f"rcode://{name}" for name in RCODES),
        "tailscale://fixture",
        "ts://fixture",
        "rcode://unknown",
        "tailscale://",
        "ts://",
    ]
    for index, nameserver in enumerate(nameservers):
        config = scratch / f"config-{index}.yaml"
        config.write_text(config_text(nameserver, reserve_port()))
        result = subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            capture_output=True,
            check=False,
        )
        observations[nameserver] = {
            "accepted": result.returncode == 0,
            "exit-code": result.returncode,
        }
    return observations


def observe_response(response: bytes, query: bytes, expected_rcode: int) -> dict[str, Any]:
    return {
        "id-echoed": response[:2] == query[:2],
        "flags": response[2:4].hex(),
        "questions": int.from_bytes(response[4:6], "big"),
        "answers": int.from_bytes(response[6:8], "big"),
        "authority": int.from_bytes(response[8:10], "big"),
        "additional": int.from_bytes(response[10:12], "big"),
        "question-preserved": response[12:] == query[12:],
        "rcode": response[3] & 0x0F,
        "expected-rcode": expected_rcode,
    }


def exercise_nameserver(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    nameserver: str,
    expected_rcode: int,
    identifier: int,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(config_text(nameserver, dns_port))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        observations: dict[str, Any] = {}
        queries: tuple[tuple[str, Callable[[int, bytes], bytes]], ...] = (
            ("udp", udp_query),
            ("tcp", tcp_query),
        )
        for offset, (transport, query_fn) in enumerate(queries):
            request = dns_query(
                f"{transport}-{identifier:x}.phase4f5.test", identifier + offset
            )
            observations[transport] = observe_response(
                query_fn(dns_port, request), request, expected_rcode
            )
        return observations
    finally:
        exit_code = stop(process)
        stdout.close()
        stderr.close()
        if exit_code != 0:
            raise RuntimeError(f"{nameserver} candidate exited with {exit_code}")


def observe_runtime(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    observations: dict[str, Any] = {}
    for index, (name, rcode) in enumerate(RCODES.items()):
        observations[f"rcode://{name}"] = exercise_nameserver(
            binary,
            scratch / f"rcode-{index}",
            f"rcode://{name}",
            rcode,
            0x4500 + index * 4,
        )
    for index, nameserver in enumerate(("tailscale://missing", "ts://missing")):
        observations[nameserver] = exercise_nameserver(
            binary,
            scratch / f"tailscale-{index}",
            nameserver,
            2,
            0x4600 + index * 4,
        )
    return observations


def satisfies_contract(observation: dict[str, Any]) -> bool:
    expected_acceptance = {
        **{f"rcode://{name}": True for name in RCODES},
        "tailscale://fixture": True,
        "ts://fixture": True,
        "rcode://unknown": False,
        "tailscale://": False,
        "ts://": False,
    }
    if {
        nameserver: result["accepted"]
        for nameserver, result in observation["config"].items()
    } != expected_acceptance:
        return False

    for nameserver, transports in observation["runtime"].items():
        expected_rcode = RCODES.get(nameserver.removeprefix("rcode://"), 2)
        expected_flags = f"{0x8500 | expected_rcode:04x}"
        if nameserver.startswith(("tailscale://", "ts://")):
            expected_flags = "8102"
        for result in transports.values():
            if result != {
                "id-echoed": True,
                "flags": expected_flags,
                "questions": 1,
                "answers": 0,
                "authority": 0,
                "additional": 0,
                "question-preserved": True,
                "rcode": expected_rcode,
                "expected-rcode": expected_rcode,
            }:
                return False
    return True


def run_registry_contracts() -> None:
    subprocess.run(
        [
            "go",
            "test",
            "./dns",
            "-run",
            "^TestPhase4F5TailscaleRegistryContract$",
            "-count=1",
        ],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            "rewrite-dns",
            "tailscale_registry_replacement_guard_matches_go_contract",
        ],
        cwd=RUST_ROOT,
        check=True,
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    run_registry_contracts()
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f5-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: {
                "config": observe_config(binary, root / implementation / "config"),
                "runtime": observe_runtime(binary, root / implementation / "runtime"),
            }
            for implementation, binary in binaries.items()
        }
        if observations["go"] != observations["rust"] or not satisfies_contract(
            observations["go"]
        ):
            FAILURE_ARTIFACT.write_text(
                json.dumps(observations, indent=2, sort_keys=True)
            )
            raise SystemExit(f"Phase 4F5 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F5 RCODE/Tailscale DNS differential passed")


if __name__ == "__main__":
    main()

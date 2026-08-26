#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E8 encoded DoH paths."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase4 import build_binaries, dns_query, launch, observe_response, stop, tcp_query, wait_dns_ready
from phase4e5 import HTTPSAuthority, encrypted_udp_query
from phase4e7 import render_custom_config


ENCODED_PATH = "/custom/dns%2Dquery"
WIRE_PATH = "/custom/dns-query"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e8-diff.json"


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    valid_paths = {
        "valid-hyphen-escape": "/custom/dns%2Dquery",
        "valid-tilde-escape": "/resolver/%7Euser",
        "valid-alpha-escape": "/v1/%41",
    }
    configs: dict[str, pathlib.Path] = {}
    for name, doh_path in valid_paths.items():
        config = scratch / f"{name}.yaml"
        render_custom_config(
            config,
            mixed_port=reserve_port(),
            dns_port=reserve_port(),
            upstream_port=reserve_port(),
            doh_path=doh_path,
        )
        configs[name] = config
    wrong_scheme = scratch / "wrong-scheme.yaml"
    wrong_scheme.write_text(
        configs["valid-hyphen-escape"].read_text().replace("https://", "bogus://")
    )
    configs["wrong-scheme"] = wrong_scheme
    return {
        name: subprocess.run(
            [str(binary), "-t", "-f", str(path)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        for name, path in configs.items()
    }


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = HTTPSAuthority(None)
    authority_thread = threading.Thread(target=authority.serve_forever, daemon=True)
    authority_thread.start()
    mixed_port, dns_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    render_custom_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        upstream_port=authority.server_address[1],
        doh_path=ENCODED_PATH,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        name = "encoded.path.doh.phase4.test"
        first = encrypted_udp_query(dns_port, dns_query(name, 0x8510))
        cached = tcp_query(dns_port, dns_query(name, 0x8520))
        return {
            "first": observe_response(first, 0x8510),
            "cached": observe_response(cached, 0x8520),
            "https-authority": authority.snapshot(),
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.shutdown()
        authority.server_close()
        authority_thread.join(timeout=IO_DEADLINE)


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    config = validation(binary, scratch)
    required = ("valid-hyphen-escape", "valid-tilde-escape", "valid-alpha-escape")
    if any(config[name] != 0 for name in required):
        return {"config": config, "runtime": "not-run"}
    return {"config": config, "runtime": exercise(binary, scratch / "runtime")}


def satisfies_phase_contract(observation: dict[str, Any]) -> bool:
    runtime = observation["runtime"]
    authority = runtime["https-authority"]
    return (
        observation["config"]
        == {
            "valid-hyphen-escape": 0,
            "valid-tilde-escape": 0,
            "valid-alpha-escape": 0,
            "wrong-scheme": 1,
        }
        and runtime["first"].get("address") == "192.0.2.42"
        and runtime["first"].get("id-echoed") is True
        and runtime["cached"].get("address") == "192.0.2.42"
        and runtime["cached"].get("id-echoed") is True
        and authority["connections"] == 1
        and authority["queries"] == {"https": 1}
        and len(authority["requests"]) == 1
        and authority["requests"][0]["path"] == WIRE_PATH
        and authority["requests"][0]["valid"] is True
        and runtime["exit-code"] == 0
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e8-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if (
            observations["go"] != observations["rust"]
            or not satisfies_phase_contract(observations["go"])
        ):
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4E8 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E8 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

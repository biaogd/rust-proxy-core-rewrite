#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 4F4 DHCP DNS contracts."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import ROOT, RUST_ROOT, cargo_target_path, reserve_port
from phase4 import build_binaries


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f4-diff.json"


def config_text(nameserver: str) -> str:
    return f"""mixed-port: {reserve_port()}
mode: rule
log-level: info
ipv6: false
dns:
  enable: true
  listen: 127.0.0.1:{reserve_port()}
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
    for name, nameserver in {
        "named-interface": "dhcp://fixture0",
        "system-alias": "dhcp://system",
    }.items():
        config = scratch / f"{name}.yaml"
        config.write_text(config_text(nameserver))
        result = subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            capture_output=True,
            check=False,
        )
        observations[name] = {
            "exit-code": result.returncode,
            "accepted": result.returncode == 0,
        }
    return observations


def wire_observation(scratch: pathlib.Path) -> dict[str, Any]:
    go_contract = scratch / "go-dhcp-contract"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_contract), "./compat/oracle/phase4f4"],
        cwd=ROOT,
        check=True,
    )
    go = json.loads(subprocess.check_output([str(go_contract)], text=True))
    target = cargo_target_path("PHASE4_CARGO_TARGET", "phase4-rust")
    subprocess.run(
        [
            "cargo",
            "build",
            "-p",
            "rewrite-platform",
            "--bin",
            "dhcp-contract",
            "--target-dir",
            str(target),
        ],
        cwd=RUST_ROOT,
        check=True,
    )
    rust_contract = target / "debug" / "dhcp-contract"
    rust_discover = subprocess.check_output(
        [str(rust_contract), "discover"], text=True
    ).strip()
    offers = []
    for case in go["offers"]:
        rust_classification = subprocess.check_output(
            [str(rust_contract), "parse", case["wire"]], text=True
        ).strip()
        offers.append(
            {
                "name": case["name"],
                "go": case["classification"],
                "rust": rust_classification,
            }
        )
    return {
        "discover-identical": go["discover"] == rust_discover,
        "discover-length": len(bytes.fromhex(go["discover"])),
        "offers": offers,
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f4-") as temporary:
        scratch = pathlib.Path(temporary)
        binaries = build_binaries(scratch)
        observations = {
            "config": {
                implementation: observe_config(binary, scratch / implementation)
                for implementation, binary in binaries.items()
            },
            "wire": wire_observation(scratch),
        }
        expected_config = {
            "named-interface": {"exit-code": 0, "accepted": True},
            "system-alias": {"exit-code": 0, "accepted": True},
        }
        valid = (
            observations["config"]["go"] == observations["config"]["rust"]
            == expected_config
            and observations["wire"]["discover-identical"]
            and observations["wire"]["discover-length"] == 300
            and all(
                case["go"] == case["rust"]
                for case in observations["wire"]["offers"]
            )
        )
        if not valid:
            FAILURE_ARTIFACT.write_text(
                json.dumps(observations, indent=2, sort_keys=True)
            )
            raise SystemExit(f"Phase 4F4 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F4 DHCP config and wire differential passed")


if __name__ == "__main__":
    main()

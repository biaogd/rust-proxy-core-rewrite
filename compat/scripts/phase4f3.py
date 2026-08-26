#!/usr/bin/env python3
"""Phase 4F3 system-resolver config differential and platform contracts."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import reserve_port
from phase4 import build_binaries


ROOT = pathlib.Path(__file__).resolve().parents[2]
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f3-diff.json"


def config_text(nameservers: list[str]) -> str:
    rendered = "\n".join(f"    - {server}" for server in nameservers)
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
{rendered}
rules:
  - MATCH,DIRECT
"""


def observe(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    observations: dict[str, Any] = {}
    for name, nameservers in {
        "legacy-system": ["system"],
        "url-system": ["system://"],
    }.items():
        config = scratch / f"{name}.yaml"
        config.write_text(config_text(nameservers))
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


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f3-") as temporary:
        scratch = pathlib.Path(temporary)
        binaries = build_binaries(scratch)
        observations = {
            implementation: observe(binary, scratch / implementation)
            for implementation, binary in binaries.items()
        }
        expected = {
            "legacy-system": {"exit-code": 0, "accepted": True},
            "url-system": {"exit-code": 0, "accepted": True},
        }
        if observations["go"] != observations["rust"] or observations["go"] != expected:
            FAILURE_ARTIFACT.write_text(
                json.dumps(observations, indent=2, sort_keys=True)
            )
            raise SystemExit(f"Phase 4F3 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F3 system-resolver config differential passed")


if __name__ == "__main__":
    main()

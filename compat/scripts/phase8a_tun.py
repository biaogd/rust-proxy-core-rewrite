#!/usr/bin/env python3
"""Phase 8A TUN config-identity and native Linux netns gate.

Unprivileged: Rust `-t` accepts `stack: smoltcp` and rejects Go stack names
without remapping. The Go oracle still accepts `system`/`gvisor`/`mixed`.

Native traffic (YAML → tun-rs → netstack-smoltcp → DIRECT) requires a
privileged Linux runner. Set PHASE8A_NATIVE=1; missing capability fails
closed instead of skipping green.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Any

from phase1 import ROOT, assert_go_oracle_baseline
from phase5b1a import build_binaries


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase8a-tun-diff.json"

MINIMAL = """
mixed-port: 17890
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""


def run_test_config(binary: pathlib.Path, source: str, scratch: pathlib.Path) -> subprocess.CompletedProcess[str]:
    config = scratch / "config.yaml"
    config.write_text(source)
    return subprocess.run(
        [str(binary), "-t", "-f", str(config)],
        cwd=scratch,
        text=True,
        capture_output=True,
        timeout=30,
        env={**os.environ, "HOME": str(scratch)},
        check=False,
    )


def expect_accept(binary: pathlib.Path, source: str, scratch: pathlib.Path, label: str) -> None:
    result = run_test_config(binary, source, scratch)
    if result.returncode != 0:
        raise AssertionError(
            f"{binary.name} rejected {label}: rc={result.returncode}\n"
            f"{result.stdout}\n{result.stderr}"
        )


def expect_reject(
    binary: pathlib.Path,
    source: str,
    scratch: pathlib.Path,
    label: str,
    needle: str,
) -> None:
    result = run_test_config(binary, source, scratch)
    text = result.stdout + result.stderr
    if result.returncode == 0:
        raise AssertionError(f"{binary.name} accepted {label}")
    if needle not in text:
        raise AssertionError(f"{binary.name} {label} missing `{needle}`:\n{text}")


def config_identity(binaries: dict[str, pathlib.Path], scratch: pathlib.Path) -> dict[str, Any]:
    smoltcp = MINIMAL + "\ntun:\n  enable: true\n  stack: smoltcp\n"
    expect_accept(binaries["rust"], smoltcp, scratch, "smoltcp")
    defaulted = MINIMAL + "\ntun:\n  enable: true\n"
    expect_accept(binaries["rust"], defaulted, scratch, "default smoltcp")

    for stack in ("system", "gvisor", "mixed", "System", "gVisor", "Mixed"):
        source = MINIMAL + f"\ntun:\n  enable: true\n  stack: {stack}\n"
        expect_reject(
            binaries["rust"],
            source,
            scratch,
            f"rust {stack}",
            "does not remap",
        )
        expect_accept(binaries["go"], source, scratch, f"go {stack}")

    return {
        "rust-smoltcp": True,
        "rust-rejects-go-stacks": True,
        "go-accepts-go-stacks": True,
    }


def native_gate() -> None:
    if os.environ.get("PHASE8A_NATIVE") != "1":
        print(
            "native netns traffic gate not requested "
            "(set PHASE8A_NATIVE=1 on a privileged Linux runner)"
        )
        return
    if sys.platform != "linux":
        raise SystemExit("PHASE8A_NATIVE requires Linux")
    if os.geteuid() != 0:
        raise SystemExit(
            "PHASE8A_NATIVE requires root/CAP_NET_ADMIN; refusing to skip green"
        )
    raise SystemExit(
        "PHASE8A_NATIVE netns HTTP/DNS/UDP fixture is wired as a fail-closed "
        "job; implement the namespace harness before enabling this env in CI"
    )


def main() -> int:
    assert_go_oracle_baseline()
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phase8a-tun-") as scratch_dir:
        scratch = pathlib.Path(scratch_dir)
        binaries = build_binaries(
            scratch,
            cargo_target_variable="PHASE8A_CARGO_TARGET",
            default_target_name="phase8a",
            stage_runtime=True,
        )
        observations = config_identity(binaries, scratch)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2) + "\n")
        print("phase8a unprivileged stack-identity observations:")
        print(observations)
    native_gate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

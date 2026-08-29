#!/usr/bin/env python3
"""Go/Rust differential for Shadowsocks config acceptance."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from phase1 import ROOT, reserve_port
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-contract-diff.json"


def render_config(name: str, mixed_port: int, upstream_port: int) -> str:
    if name == "ss-valid":
        return f"""mixed-port: {mixed_port}
mode: rule
proxies:
  - name: ss
    type: ss
    server: 127.0.0.1
    port: {upstream_port}
    cipher: aes-256-gcm
    password: secret
rules:
  - MATCH,ss
"""
    if name == "ss-plugin-rejected":
        return f"""mixed-port: {mixed_port}
mode: rule
proxies:
  - name: ss
    type: ss
    server: 127.0.0.1
    port: {upstream_port}
    cipher: aes-256-gcm
    password: secret
    plugin: obfs-local
rules:
  - MATCH,ss
"""
    raise KeyError(name)


def exercise_case(binary: Path, scratch: Path, case: str) -> dict[str, Any]:
    mixed_port = reserve_port()
    upstream_port = reserve_port()
    scratch.mkdir(parents=True, exist_ok=True)
    config = scratch / "config.yaml"
    config.write_text(render_config(case, mixed_port, upstream_port))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        stop(process)
        return {"exit": 0, "timed-out": True}
    stdout.close()
    stderr.close()
    return {"exit": process.returncode, "timed-out": False}


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    cases = ("ss-valid",)
    return {case: exercise_case(binary, scratch / case, case) for case in cases}


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-contract-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(root, "PHASE6CSSCONTRACT_CARGO_TARGET", "phase6c-shadowsocks-contract")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
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
    print("Phase 6C Shadowsocks config contract differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Deterministic Go/Rust differential suite for Phase 2 pure policy."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import random
import subprocess
import sys
from typing import Any

from phase1 import assert_go_oracle_baseline


ROOT = pathlib.Path(__file__).resolve().parents[2]
RUST_ROOT = ROOT / "rust"
FIXED_CASES = ROOT / "compat" / "fixtures" / "phase2" / "cases.json"
BASELINE = "c0e43ebecf3be9b223f1015c1fc38689bb073467"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase2-diff.json"
DEFAULT_SEED = 0xC0E43EBE


def build_binaries() -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()

    build_root = ROOT / "target" / "compat" / "phase2"
    build_root.mkdir(parents=True, exist_ok=True)
    go_override = os.environ.get("PHASE2_GO_ORACLE")
    rust_override = os.environ.get("PHASE2_RUST_ORACLE")
    go_binary = pathlib.Path(go_override) if go_override else build_root / "go-oracle"
    rust_target = pathlib.Path(
        os.environ.get("PHASE2_CARGO_TARGET", build_root / "rust-target")
    )
    rust_binary = (
        pathlib.Path(rust_override)
        if rust_override
        else rust_target / "debug" / "rewrite-phase2-oracle"
    )
    if not go_override:
        subprocess.run(
            [
                "go",
                "build",
                "-trimpath",
                "-o",
                str(go_binary),
                "./compat/oracle/phase2",
            ],
            cwd=ROOT,
            check=True,
        )
    if not rust_override:
        subprocess.run(
            [
                "cargo",
                "build",
                "-p",
                "rewrite-test-support",
                "--target-dir",
                str(rust_target),
            ],
            cwd=RUST_ROOT,
            check=True,
        )
    return {"go": go_binary, "rust": rust_binary}


def generated_config_cases(rng: random.Random, count: int) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    modes = ["rule", "global", "direct", "RULE", "Global"]
    levels = ["debug", "info", "warning", "error", "silent", "INFO"]
    for _ in range(count):
        values: dict[str, Any] = {}
        candidates: dict[str, Any] = {
            "port": rng.randint(-1, 70000),
            "socks-port": rng.randint(0, 70000),
            "redir-port": rng.randint(0, 70000),
            "tproxy-port": rng.randint(0, 70000),
            "mixed-port": rng.randint(-1, 70000),
            "allow-lan": rng.choice([True, False]),
            "bind-address": rng.choice(["*", "127.0.0.1", "0.0.0.0"]),
            "mode": rng.choice(modes),
            "unified-delay": rng.choice([True, False]),
            "log-level": rng.choice(levels),
            "ipv6": rng.choice([True, False]),
            "interface-name": rng.choice(["", "en0", "eth0"]),
            "routing-mark": rng.randint(0, 1000),
            "tcp-concurrent": rng.choice([True, False]),
            "keep-alive-idle": rng.randint(0, 60),
            "keep-alive-interval": rng.randint(0, 60),
            "disable-keep-alive": rng.choice([True, False]),
            "etag-support": rng.choice([True, False]),
        }
        for key, value in candidates.items():
            if rng.random() < 0.55:
                values[key] = value
        cases.append({"op": "config", "yaml": json.dumps(values, sort_keys=True)})
    return cases


def condition_case(rng: random.Random) -> tuple[str, dict[str, Any]]:
    family = rng.choice(
        ["domain", "suffix", "keyword", "ip", "src-ip", "port", "network"]
    )
    should_match = rng.choice([True, False])
    metadata: dict[str, Any] = {"network": rng.choice(["TCP", "UDP"])}
    if family == "domain":
        payload = rng.choice(["one.example", "two.example", "api.local"])
        metadata["host"] = payload if should_match else "miss.example"
        return f"DOMAIN,{payload}", metadata
    if family == "suffix":
        payload = rng.choice(["example.com", "internal.local"])
        metadata["host"] = f"www.{payload}" if should_match else "example.net"
        return f"DOMAIN-SUFFIX,{payload}", metadata
    if family == "keyword":
        payload = rng.choice(["api", "needle", "cdn"])
        metadata["host"] = f"x-{payload}-y" if should_match else "plain.example"
        return f"DOMAIN-KEYWORD,{payload}", metadata
    if family == "ip":
        metadata["destination-ip"] = "10.2.3.4" if should_match else "11.2.3.4"
        return "IP-CIDR,10.0.0.0/8", metadata
    if family == "src-ip":
        metadata["source-ip"] = "192.168.2.3" if should_match else "172.16.2.3"
        return "SRC-IP-CIDR,192.168.0.0/16", metadata
    if family == "port":
        metadata["destination-port"] = rng.randint(8000, 9000) if should_match else 7000
        return "DST-PORT,8000-9000", metadata
    wanted = rng.choice(["TCP", "UDP"])
    metadata["network"] = wanted if should_match else ("UDP" if wanted == "TCP" else "TCP")
    return f"NETWORK,{wanted}", metadata


def generated_rule_cases(rng: random.Random, count: int) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for _ in range(count):
        first, metadata = condition_case(rng)
        shape = rng.choice(["simple", "and", "or", "not"])
        if shape == "simple":
            rule = f"{first},REJECT"
        else:
            second, _ = condition_case(rng)
            if shape == "and":
                rule = f"AND,(({first}),({second})),REJECT"
            elif shape == "or":
                rule = f"OR,(({first}),({second})),REJECT"
            else:
                rule = f"NOT,(({first})),REJECT"
        cases.append(
            {
                "op": "rules",
                "rules": [rule, "MATCH,DIRECT"],
                "metadata": metadata,
            }
        )
    return cases


def run_oracle(binary: pathlib.Path, requests: list[dict[str, Any]]) -> tuple[Any, str]:
    process = subprocess.run(
        [str(binary)],
        input=json.dumps(requests, separators=(",", ":")).encode(),
        capture_output=True,
        timeout=60,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"{binary.name} exited {process.returncode}: "
            f"{process.stderr.decode(errors='replace')}"
        )
    return json.loads(process.stdout), process.stderr.decode(errors="replace")


def write_failure(payload: dict[str, Any]) -> pathlib.Path:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    FAILURE_ARTIFACT.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return FAILURE_ARTIFACT


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=DEFAULT_SEED)
    parser.add_argument("--generated-configs", type=int, default=96)
    parser.add_argument("--generated-rules", type=int, default=256)
    arguments = parser.parse_args()

    fixed = json.loads(FIXED_CASES.read_text())
    rng = random.Random(arguments.seed)
    requests = fixed + generated_config_cases(
        rng, arguments.generated_configs
    ) + generated_rule_cases(rng, arguments.generated_rules)
    binaries = build_binaries()
    try:
        go, go_stderr = run_oracle(binaries["go"], requests)
        rust, rust_stderr = run_oracle(binaries["rust"], requests)
    except Exception as error:
        artifact = write_failure(
            {"error": f"{type(error).__name__}: {error}", "seed": arguments.seed}
        )
        print(f"Phase 2 differential run failed: {artifact}", file=sys.stderr)
        raise

    if go != rust:
        mismatch = next(
            (
                index
                for index, (go_result, rust_result) in enumerate(zip(go, rust))
                if go_result != rust_result
            ),
            min(len(go), len(rust)),
        )
        artifact = write_failure(
            {
                "seed": arguments.seed,
                "case-index": mismatch,
                "request": requests[mismatch] if mismatch < len(requests) else None,
                "go": go[mismatch] if mismatch < len(go) else None,
                "rust": rust[mismatch] if mismatch < len(rust) else None,
                "go-stderr": go_stderr,
                "rust-stderr": rust_stderr,
                "request-count": len(requests),
            }
        )
        print(f"Phase 2 differential mismatch: {artifact}", file=sys.stderr)
        return 1

    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print(
        "Phase 2 Go/Rust differential suite passed: "
        f"{len(fixed)} fixed + {arguments.generated_configs} config + "
        f"{arguments.generated_rules} rule cases (seed={arguments.seed:#x})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

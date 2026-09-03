#!/usr/bin/env python3
"""Go/Rust differential suite for Phase 4F8 DNS resolver policies."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import time
from typing import Any

from phase1 import ROOT, cargo_target_path, reserve_port
from phase4 import build_binaries
from phase4f2 import LocalAuthority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f8-diff.json"


def varint(value: int) -> bytes:
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def field_bytes(number: int, value: bytes) -> bytes:
    return varint((number << 3) | 2) + varint(len(value)) + value


def domain(kind: int, value: str) -> bytes:
    return varint(8) + varint(kind) + field_bytes(2, value.encode())


def geosite(name: str, domains: list[tuple[int, str]]) -> bytes:
    payload = field_bytes(1, name.encode())
    for kind, value in domains:
        payload += field_bytes(2, domain(kind, value))
    return field_bytes(1, payload)


def write_geosite(path: pathlib.Path) -> None:
    path.write_bytes(
        geosite("CN", [(2, "example.cn")])
        + geosite(
            "PHASE4F8",
            [
                (3, "early.phase4f8.test"),
                (3, "ordered.phase4f8.test"),
                (0, "plain-token"),
                (1, r"^regex\.[a-z]+\.phase4f8\.test$"),
                (2, "geo-suffix.phase4f8.test"),
            ],
        )
    )


def endpoint(authority: LocalAuthority, transport: str = "udp") -> str:
    return f"{transport}://127.0.0.1:{authority.port}"


def render_config(path: pathlib.Path, authorities: dict[str, LocalAuthority]) -> None:
    mixed_port = reserve_port()
    dns_port = reserve_port()
    while dns_port == mixed_port:
        dns_port = reserve_port()
    path.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
rule-providers:
  domains:
    type: inline
    behavior: domain
    payload:
      - '+.rules.phase4f8.test'
  classical:
    type: inline
    behavior: classical
    payload:
      - 'DOMAIN-KEYWORD,classic-token'
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  default-nameserver:
    - {endpoint(authorities['main'])}
  nameserver:
    - {endpoint(authorities['main'])}
  nameserver-policy:
    'early.phase4f8.test':
      - {endpoint(authorities['early-slow'])}
      - {endpoint(authorities['early-fast'], 'tcp')}
    'geosite:PHASE4F8': {endpoint(authorities['geosite'])}
    'ordered.phase4f8.test': {endpoint(authorities['ordered-late'])}
    '+.overwrite.phase4f8.test': {endpoint(authorities['overwrite-old'])}
    'overwrite.phase4f8.test': {endpoint(authorities['overwrite-new'])}
    'rule-set:domains': {endpoint(authorities['ruleset'])}
    'rule-set:classical': {endpoint(authorities['classical'])}
    'comma-a.phase4f8.test,comma-b.phase4f8.test': {endpoint(authorities['comma'])}
    'all-transports.phase4f8.test':
      - {endpoint(authorities['main'])}
      - {endpoint(authorities['main'], 'tcp')}
      - tls://127.0.0.1:{authorities['main'].port}#skip-cert-verify=true&disable-reuse=true
      - http://127.0.0.1:{authorities['main'].port}/dns-query
      - https://127.0.0.1:{authorities['main'].port}/dns-query#skip-cert-verify=true
      - quic://127.0.0.1:{authorities['main'].port}#name-cert-verify=phase4f8.test
      - system://
      - rcode://name_error
      - tailscale://fixture
  proxy-server-nameserver:
    - {endpoint(authorities['proxy-main'])}
  proxy-server-nameserver-policy:
    '+.proxy.phase4f8.test':
      - {endpoint(authorities['proxy-slow'])}
      - {endpoint(authorities['proxy-fast'], 'tcp')}
rules:
  - MATCH,DIRECT
"""
    )


def build_helpers(root: pathlib.Path) -> dict[str, pathlib.Path]:
    products = build_binaries(root)
    go_helper = root / "go-resolver-policy"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_helper), "./compat/oracle/phase4f8"],
        cwd=ROOT,
        check=True,
    )
    target = cargo_target_path("PHASE4_CARGO_TARGET", "phase4-rust")
    return {
        "go-product": products["go"],
        "rust-product": products["rust"],
        "go": go_helper,
        "rust": target / "debug" / "rewrite-resolver-set",
    }


def run_helper(
    binary: pathlib.Path, config: pathlib.Path, resolver_set: str, host: str
) -> dict[str, Any]:
    result = subprocess.run(
        [str(binary), str(config), resolver_set, host],
        cwd=config.parent,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    lines = [line for line in result.stdout.splitlines() if line]
    return {
        "exit-code": result.returncode,
        "address": lines[-1] if result.returncode == 0 and lines else None,
    }


def validate_products(
    binaries: dict[str, pathlib.Path], config: pathlib.Path
) -> dict[str, int]:
    commands = {
        "go": [
            str(binaries["go-product"]),
            "-d",
            str(config.parent),
            "-t",
            "-f",
            str(config),
        ],
        "rust": [
            str(binaries["rust-product"]),
            "-d",
            str(config.parent),
            "-t",
            "-f",
            str(config),
        ],
    }
    return {
        name: subprocess.run(
            command,
            cwd=config.parent,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        for name, command in commands.items()
    }


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    addresses = {
        "main": "192.0.2.80",
        "early-slow": "192.0.2.81",
        "early-fast": "192.0.2.82",
        "geosite": "192.0.2.83",
        "ordered-late": "192.0.2.84",
        "overwrite-old": "192.0.2.85",
        "overwrite-new": "192.0.2.86",
        "ruleset": "192.0.2.87",
        "classical": "192.0.2.88",
        "comma": "192.0.2.89",
        "proxy-main": "192.0.2.90",
        "proxy-slow": "192.0.2.91",
        "proxy-fast": "192.0.2.92",
    }
    authorities = {
        name: LocalAuthority(
            "answer",
            address=address,
            delay=0.25 if name.endswith("slow") else 0.03 if name.endswith("fast") else 0,
        )
        for name, address in addresses.items()
    }
    try:
        write_geosite(scratch / "GeoSite.dat")
        config = scratch / "policy.yaml"
        render_config(config, authorities)
        cases = [
            ("early-domain-before-matcher", "main", "early.phase4f8.test", "early-fast"),
            ("matcher-before-late-domain", "main", "ordered.phase4f8.test", "geosite"),
            ("same-node-overwrite", "main", "overwrite.phase4f8.test", "overwrite-new"),
            ("ruleset-domain", "main", "deep.rules.phase4f8.test", "ruleset"),
            ("ruleset-classical", "main", "a.classic-token.test", "classical"),
            ("comma-expansion", "main", "comma-b.phase4f8.test", "comma"),
            ("geosite-plain", "main", "x.plain-token.test", "geosite"),
            ("geosite-regex", "main", "regex.name.phase4f8.test", "geosite"),
            ("geosite-domain", "main", "deep.geo-suffix.phase4f8.test", "geosite"),
            ("proxy-policy", "proxy", "deep.proxy.phase4f8.test", "proxy-fast"),
        ]
        observations: dict[str, Any] = {}
        for label, resolver_set, host, expected_authority in cases:
            result = run_helper(binary, config, resolver_set, host)
            result["expected"] = addresses[expected_authority]
            observations[label] = result
        time.sleep(0.3)
        observations["contacts"] = {
            name: authority.state.snapshot() for name, authority in authorities.items()
        }
        observations["multi-main-both"] = (
            observations["contacts"]["early-slow"]["udp"] > 0
            and observations["contacts"]["early-fast"]["tcp"] > 0
        )
        observations["multi-proxy-both"] = (
            observations["contacts"]["proxy-slow"]["udp"] > 0
            and observations["contacts"]["proxy-fast"]["tcp"] > 0
        )
        observations["shadowed-not-contacted"] = (
            observations["contacts"]["ordered-late"]["udp"] == 0
            and observations["contacts"]["overwrite-old"]["udp"] == 0
        )
        return observations
    finally:
        for authority in authorities.values():
            authority.close()


def satisfies_contract(observation: dict[str, Any]) -> bool:
    results = [value for value in observation.values() if isinstance(value, dict) and "expected" in value]
    return (
        all(case["exit-code"] == 0 and case["address"] == case["expected"] for case in results)
        and observation["multi-main-both"] is True
        and observation["multi-proxy-both"] is True
        and observation["shadowed-not-contacted"] is True
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f8-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_helpers(root)
        validation_root = root / "validation"
        validation_root.mkdir()
        validation_authorities = {
            name: LocalAuthority("answer", address=f"192.0.2.{100 + index}")
            for index, name in enumerate(
                [
                    "main", "early-slow", "early-fast", "geosite", "ordered-late",
                    "overwrite-old", "overwrite-new", "ruleset", "classical", "comma",
                    "proxy-main", "proxy-slow", "proxy-fast",
                ]
            )
        }
        try:
            write_geosite(validation_root / "GeoSite.dat")
            validation_config = validation_root / "policy.yaml"
            render_config(validation_config, validation_authorities)
            validation = validate_products(binaries, validation_config)
        finally:
            for authority in validation_authorities.values():
                authority.close()
        runtime = {
            implementation: exercise(binaries[implementation], root / implementation)
            for implementation in ("go", "rust")
        }
        evidence = {"config": validation, "runtime": runtime}
        if (
            validation != {"go": 0, "rust": 0}
            or runtime["go"] != runtime["rust"]
            or not satisfies_contract(runtime["go"])
        ):
            FAILURE_ARTIFACT.write_text(json.dumps(evidence, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4F8 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F8 DNS resolver-policy differential passed")


if __name__ == "__main__":
    main()

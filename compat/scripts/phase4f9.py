#!/usr/bin/env python3
"""Go/Rust differential suite for Phase 4F9 DNS fallback semantics."""

from __future__ import annotations

import json
import pathlib
import socket
import subprocess
import tempfile
import time
from typing import Any

from phase1 import ROOT, cargo_target_path, reserve_port
from phase4 import build_binaries
from phase4f2 import LocalAuthority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f9-diff.json"


def varint(value: int) -> bytes:
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def field_bytes(number: int, value: bytes) -> bytes:
    return varint((number << 3) | 2) + varint(len(value)) + value


def write_geoip(path: pathlib.Path) -> None:
    network = field_bytes(1, socket.inet_pton(socket.AF_INET, "203.0.113.0"))
    network += varint(2 << 3) + varint(24)
    cn_entry = field_bytes(1, b"CN") + field_bytes(2, network)
    test_entry = field_bytes(1, b"TEST") + field_bytes(2, network)
    path.write_bytes(field_bytes(1, cn_entry) + field_bytes(1, test_entry))


def write_geosite(path: pathlib.Path) -> None:
    cn_domain = varint(8) + varint(2) + field_bytes(2, b"example.cn")
    cn_entry = field_bytes(1, b"CN") + field_bytes(2, cn_domain)
    domain = varint(8) + varint(3) + field_bytes(2, b"geosite.phase4f9.test")
    entry = field_bytes(1, b"PHASE4F9") + field_bytes(2, domain)
    path.write_bytes(field_bytes(1, cn_entry) + field_bytes(1, entry))


def endpoint(authority: LocalAuthority, transport: str = "udp") -> str:
    return f"{transport}://127.0.0.1:{authority.port}"


def render_config(
    path: pathlib.Path,
    main: LocalAuthority,
    fallback: list[LocalAuthority],
    filter_lines: list[str],
    *,
    lazy: bool = False,
) -> None:
    fallback_lines = "\n".join(f"    - {endpoint(server)}" for server in fallback)
    filters = "\n".join(f"    {line}" for line in filter_lines)
    path.write_text(
        f"""mixed-port: {reserve_port()}
mode: rule
log-level: info
ipv6: true
geodata-mode: true
dns:
  enable: true
  listen: 127.0.0.1:{reserve_port()}
  ipv6: true
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  nameserver:
    - {endpoint(main)}
  fallback:
{fallback_lines}
  fallback-lazy-query: {str(lazy).lower()}
  fallback-filter:
{filters}
rules:
  - MATCH,DIRECT
"""
    )


def build_helpers(root: pathlib.Path) -> dict[str, pathlib.Path]:
    products = build_binaries(root)
    go_helper = root / "go-fallback"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_helper), "./compat/oracle/phase4f9"],
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


def run_helper(binary: pathlib.Path, config: pathlib.Path, host: str) -> tuple[int, str | None, float]:
    command = [str(binary), str(config), host]
    if binary.name == "rewrite-resolver-set":
        command = [str(binary), str(config), "main", host]
    started = time.monotonic()
    result = subprocess.run(
        command,
        cwd=config.parent,
        capture_output=True,
        text=True,
        check=False,
        timeout=12,
    )
    elapsed = time.monotonic() - started
    lines = [line for line in result.stdout.splitlines() if line]
    address = lines[-1] if result.returncode == 0 and lines else None
    return result.returncode, address, elapsed


def classify_gap(main: LocalAuthority, fallback: list[LocalAuthority]) -> str:
    main_received = main.state.first_received
    fallback_received = [
        server.state.first_received
        for server in fallback
        if server.state.first_received is not None
    ]
    if main_received is None:
        return "main-not-contacted"
    if not fallback_received:
        return "fallback-not-contacted"
    gap = min(fallback_received) - main_received
    if abs(gap) <= 0.15:
        return "parallel"
    if 0.20 <= gap <= 1.5:
        return "after-failure"
    if gap >= 4.0:
        return "after-timeout"
    return "unexpected"


def run_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    label: str,
    *,
    main_mode: str = "answer",
    main_address: str = "192.0.2.10",
    main_delay: float = 0.0,
    fallback_specs: list[tuple[str, str, float]] | None = None,
    filter_lines: list[str],
    lazy: bool = False,
    expected: str | None,
) -> dict[str, Any]:
    main = LocalAuthority(main_mode, address=main_address, delay=main_delay)
    specs = fallback_specs or [("answer", "192.0.2.20", 0.0)]
    fallback = [
        LocalAuthority(mode, address=address, delay=delay)
        for mode, address, delay in specs
    ]
    try:
        config = scratch / f"{label}.yaml"
        render_config(config, main, fallback, filter_lines, lazy=lazy)
        exit_code, address, elapsed = run_helper(
            binary, config, f"{label}.phase4f9.test"
        )
        time.sleep(0.05)
        return {
            "exit-code": exit_code,
            "address": address,
            "expected": expected,
            "duration": "timeout" if 4.5 <= elapsed <= 7.0 else "prompt",
            "start-order": classify_gap(main, fallback),
            "main-contacted": main.state.first_received is not None,
            "fallback-contacted": [
                server.state.first_received is not None for server in fallback
            ],
        }
    finally:
        main.close()
        for server in fallback:
            server.close()


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    write_geoip(scratch / "GeoIP.dat")
    write_geosite(scratch / "GeoSite.dat")
    cases = {
        "domain": dict(
            filter_lines=["geoip: false", "domain: ['+.domain.phase4f9.test']"],
            expected="192.0.2.20",
        ),
        "geosite": dict(
            filter_lines=["geoip: false", "geosite: [PHASE4F9]"],
            expected="192.0.2.20",
        ),
        "ipv4-cidr": dict(
            main_address="198.51.100.10",
            filter_lines=["geoip: false", "ipcidr: [198.51.100.0/24]"],
            expected="192.0.2.20",
        ),
        "ipv6-cidr": dict(
            main_address="2001:db8:1::10",
            filter_lines=["geoip: false", "ipcidr: ['2001:db8:1::/48']"],
            expected="192.0.2.20",
        ),
        "geoip-contained": dict(
            main_address="203.0.113.7",
            filter_lines=["geoip: true", "geoip-code: TEST"],
            expected="203.0.113.7",
        ),
        "geoip-outside": dict(
            main_address="198.51.100.7",
            filter_lines=["geoip: true", "geoip-code: TEST"],
            expected="192.0.2.20",
        ),
        "geoip-private-exception": dict(
            main_address="10.0.0.7",
            filter_lines=["geoip: true", "geoip-code: TEST"],
            expected="10.0.0.7",
        ),
        "geoip-lan-code": dict(
            main_address="198.51.100.9",
            filter_lines=["geoip: true", "geoip-code: LAN"],
            expected="192.0.2.20",
        ),
        "geoip-inverted": dict(
            main_address="203.0.113.8",
            filter_lines=["geoip: true", "geoip-code: '!TEST'"],
            expected="192.0.2.20",
        ),
        "multiple-fallback": dict(
            main_address="198.51.100.11",
            fallback_specs=[
                ("blackhole", "192.0.2.21", 0.0),
                ("answer", "192.0.2.22", 0.03),
            ],
            filter_lines=["geoip: false", "ipcidr: [198.51.100.0/24]"],
            expected="192.0.2.22",
        ),
        "eager-failure": dict(
            main_mode="servfail",
            main_delay=0.35,
            filter_lines=["geoip: false"],
            expected="192.0.2.20",
        ),
        "lazy-failure": dict(
            main_mode="servfail",
            main_delay=0.35,
            filter_lines=["geoip: false"],
            lazy=True,
            expected="192.0.2.20",
        ),
        "eager-timeout": dict(
            main_mode="blackhole",
            filter_lines=["geoip: false"],
            expected="192.0.2.20",
        ),
        "lazy-timeout": dict(
            main_mode="blackhole",
            filter_lines=["geoip: false"],
            lazy=True,
            expected=None,
        ),
    }
    return {
        label: run_case(binary, scratch, label, **parameters)
        for label, parameters in cases.items()
    }


def validate_products(
    binaries: dict[str, pathlib.Path], scratch: pathlib.Path
) -> dict[str, dict[str, bool]]:
    scratch.mkdir(parents=True, exist_ok=True)
    main = LocalAuthority("answer")
    fallback = LocalAuthority("answer")
    try:
        write_geoip(scratch / "GeoIP.dat")
        write_geosite(scratch / "GeoSite.dat")
        valid = scratch / "valid.yaml"
        render_config(
            valid,
            main,
            [fallback],
            ["geoip: true", "geoip-code: TEST", "geosite: [PHASE4F9]"],
        )
        unknown = scratch / "unknown.yaml"
        render_config(
            unknown,
            main,
            [fallback],
            ["geoip: true", "geoip-code: UNKNOWN"],
        )
        commands = {
            "go": lambda path: [
                str(binaries["go-product"]), "-d", str(scratch), "-t", "-f", str(path)
            ],
            "rust": lambda path: [str(binaries["rust-product"]), "-t", "-f", str(path)],
        }
        return {
            implementation: {
                "valid": subprocess.run(
                    command(valid), cwd=scratch, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, check=False
                ).returncode == 0,
                "unknown-rejected": subprocess.run(
                    command(unknown), cwd=scratch, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, check=False
                ).returncode != 0,
            }
            for implementation, command in commands.items()
        }
    finally:
        main.close()
        fallback.close()


def satisfies_contract(observation: dict[str, Any]) -> bool:
    if not all(
        (
            case["exit-code"] != 0 and case["address"] is None
            if case["expected"] is None
            else case["exit-code"] == 0 and case["address"] == case["expected"]
        )
        for case in observation.values()
    ):
        return False
    return (
        observation["domain"]["main-contacted"] is False
        and observation["geosite"]["main-contacted"] is False
        and observation["geoip-contained"]["start-order"] == "parallel"
        and observation["geoip-contained"]["fallback-contacted"] == [True]
        and observation["multiple-fallback"]["fallback-contacted"] == [True, True]
        and observation["multiple-fallback"]["duration"] == "prompt"
        and observation["eager-failure"]["start-order"] == "parallel"
        and observation["lazy-failure"]["start-order"] == "after-failure"
        and observation["eager-timeout"]["start-order"] == "parallel"
        and observation["lazy-timeout"]["start-order"] == "fallback-not-contacted"
        and observation["eager-timeout"]["duration"] == "timeout"
        and observation["lazy-timeout"]["duration"] == "timeout"
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f9-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_helpers(root)
        validation = validate_products(binaries, root / "validation")
        runtime = {
            implementation: exercise(binaries[implementation], root / implementation)
            for implementation in ("go", "rust")
        }
        evidence = {"config": validation, "runtime": runtime}
        expected_validation = {
            "go": {"valid": True, "unknown-rejected": True},
            "rust": {"valid": True, "unknown-rejected": True},
        }
        if (
            validation != expected_validation
            or runtime["go"] != runtime["rust"]
            or not satisfies_contract(runtime["go"])
        ):
            FAILURE_ARTIFACT.write_text(json.dumps(evidence, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4F9 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F9 DNS fallback differential passed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Go/Rust differential suite for Phase 4F7 DNS resolver sets."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import time
from typing import Any

from phase1 import ROOT, reserve_port
from phase4 import build_binaries
from phase4f2 import LocalAuthority


RUST_ROOT = ROOT / "rust"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f7-diff.json"


def render_config(
    path: pathlib.Path,
    *,
    defaults: list[str],
    main: list[str],
    fallback: list[str] | None = None,
    direct: list[str] | None = None,
    proxy: list[str] | None = None,
    policy: tuple[str, str] | None = None,
    direct_follow: bool = False,
    fallback_cidr: str | None = None,
) -> None:
    def block(name: str, values: list[str] | None) -> str:
        if not values:
            return ""
        return f"  {name}:\n" + "".join(f"    - {value}\n" for value in values)

    policy_text = ""
    if policy is not None:
        policy_text = f"  nameserver-policy:\n    {policy[0]}: {policy[1]}\n"
    fallback_filter = ""
    if fallback:
        fallback_filter = "  fallback-filter:\n    geoip: false\n"
        if fallback_cidr is not None:
            fallback_filter += f"    ipcidr:\n      - {fallback_cidr}\n"
    path.write_text(
        f"""mixed-port: {reserve_port()}
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
{block("default-nameserver", defaults)}{block("nameserver", main)}{block("fallback", fallback)}{fallback_filter}{block("direct-nameserver", direct)}  direct-nameserver-follow-policy: {str(direct_follow).lower()}
{block("proxy-server-nameserver", proxy)}{policy_text}rules:
  - MATCH,DIRECT
"""
    )


def build_helpers(root: pathlib.Path) -> dict[str, pathlib.Path]:
    binaries = build_binaries(root)
    go_helper = root / "go-resolver-set"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_helper), "./compat/oracle/phase4f7"],
        cwd=ROOT,
        check=True,
    )
    target = pathlib.Path(
        __import__("os").environ.get(
            "PHASE4_CARGO_TARGET", ROOT / "target" / "compat" / "phase4-rust"
        )
    )
    return {
        "go-product": binaries["go"],
        "rust-product": binaries["rust"],
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
    output_lines = [line for line in result.stdout.splitlines() if line]
    return {
        "exit-code": result.returncode,
        "address": output_lines[-1] if result.returncode == 0 and output_lines else None,
    }


def pair(
    authorities: list[LocalAuthority],
    slow_address: str,
    fast_address: str,
) -> tuple[list[str], LocalAuthority, LocalAuthority]:
    slow = LocalAuthority("answer", address=slow_address, delay=0.25)
    fast = LocalAuthority("answer", address=fast_address, delay=0.03)
    authorities.extend([slow, fast])
    return (
        [f"udp://127.0.0.1:{slow.port}", f"tcp://127.0.0.1:{fast.port}"],
        slow,
        fast,
    )


def snapshot(slow: LocalAuthority, fast: LocalAuthority) -> dict[str, Any]:
    time.sleep(0.05)
    return {
        "slow": slow.state.snapshot(),
        "fast": fast.state.snapshot(),
        "both-contacted": slow.state.first_received is not None
        and fast.state.first_received is not None,
    }


def validation_source(path: pathlib.Path) -> None:
    port = reserve_port()
    all_transports = [
        f"udp://127.0.0.1:{port}",
        f"tcp://127.0.0.1:{port}",
        f"tls://127.0.0.1:{port}#skip-cert-verify=true&disable-reuse=true",
        f"http://127.0.0.1:{port}/dns-query",
        f"https://127.0.0.1:{port}/dns-query#skip-cert-verify=true",
        f"quic://127.0.0.1:{port}#name-cert-verify=phase4f7.test",
        "system://",
    ]
    main_transports = [*all_transports, "rcode://name_error", "tailscale://fixture"]
    render_config(
        path,
        defaults=all_transports,
        main=main_transports,
        fallback=main_transports,
        direct=main_transports,
        proxy=main_transports,
    )


def validate_products(
    go_binary: pathlib.Path, rust_binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, int]:
    config = scratch / "all-transports.yaml"
    validation_source(config)
    return {
        name: subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        for name, binary in {"go": go_binary, "rust": rust_binary}.items()
    }


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authorities: list[LocalAuthority] = []
    try:
        defaults, default_slow, default_fast = pair(
            authorities, "192.0.2.41", "192.0.2.42"
        )
        main, main_slow, main_fast = pair(authorities, "192.0.2.43", "192.0.2.44")
        direct, direct_slow, direct_fast = pair(
            authorities, "192.0.2.45", "192.0.2.46"
        )
        proxy, proxy_slow, proxy_fast = pair(
            authorities, "192.0.2.47", "192.0.2.48"
        )
        base = scratch / "sets.yaml"
        render_config(
            base,
            defaults=defaults,
            main=main,
            direct=direct,
            proxy=proxy,
        )
        observations = {}
        for resolver_set, expected, servers in (
            ("default", "192.0.2.42", (default_slow, default_fast)),
            ("main", "192.0.2.44", (main_slow, main_fast)),
            ("direct", "192.0.2.46", (direct_slow, direct_fast)),
            ("proxy", "192.0.2.48", (proxy_slow, proxy_fast)),
        ):
            result = run_helper(
                binary, base, resolver_set, f"{resolver_set}.phase4f7.test"
            )
            result["expected"] = expected
            result["authorities"] = snapshot(*servers)
            observations[resolver_set] = result

        rejected_main = LocalAuthority("answer", address="198.51.100.10")
        fallback, fallback_slow, fallback_fast = pair(
            authorities, "192.0.2.49", "192.0.2.50"
        )
        authorities.append(rejected_main)
        fallback_config = scratch / "fallback.yaml"
        render_config(
            fallback_config,
            defaults=defaults,
            main=[f"udp://127.0.0.1:{rejected_main.port}"],
            fallback=fallback,
            fallback_cidr="198.51.100.0/24",
        )
        fallback_result = run_helper(
            binary, fallback_config, "main", "fallback.phase4f7.test"
        )
        fallback_result["expected"] = "192.0.2.50"
        fallback_result["authorities"] = snapshot(fallback_slow, fallback_fast)
        fallback_result["main-contacted"] = rejected_main.state.snapshot()["udp"] > 0
        observations["fallback"] = fallback_result

        policy_authority = LocalAuthority("answer", address="192.0.2.51")
        authorities.append(policy_authority)
        follow_config = scratch / "direct-follow.yaml"
        render_config(
            follow_config,
            defaults=defaults,
            main=main,
            direct=direct,
            policy=(
                "follow.phase4f7.test",
                f"udp://127.0.0.1:{policy_authority.port}",
            ),
            direct_follow=True,
        )
        follow = run_helper(
            binary, follow_config, "direct", "follow.phase4f7.test"
        )
        follow["expected"] = "192.0.2.51"
        follow["policy-contacted"] = policy_authority.state.snapshot()["udp"] > 0
        observations["direct-follow-policy"] = follow
        return observations
    finally:
        for authority in authorities:
            authority.close()


def satisfies_contract(observation: dict[str, Any]) -> bool:
    for name in ("default", "main", "direct", "proxy", "fallback"):
        case = observation[name]
        if case["exit-code"] != 0 or case["address"] != case["expected"]:
            return False
        if not case["authorities"]["both-contacted"]:
            return False
    fallback = observation["fallback"]
    follow = observation["direct-follow-policy"]
    return (
        fallback["main-contacted"] is True
        and follow["exit-code"] == 0
        and follow["address"] == follow["expected"]
        and follow["policy-contacted"] is True
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f7-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_helpers(root)
        product_validation = validate_products(
            binaries["go-product"], binaries["rust-product"], root
        )
        observations = {
            implementation: exercise(binaries[implementation], root / implementation)
            for implementation in ("go", "rust")
        }
        evidence = {"config": product_validation, "runtime": observations}
        if (
            product_validation != {"go": 0, "rust": 0}
            or observations["go"] != observations["rust"]
            or not satisfies_contract(observations["go"])
        ):
            FAILURE_ARTIFACT.write_text(json.dumps(evidence, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4F7 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F7 DNS resolver-set differential passed")


if __name__ == "__main__":
    main()

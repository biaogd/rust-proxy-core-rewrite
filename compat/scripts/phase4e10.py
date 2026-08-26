#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E10 DoT trust options."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase4 import build_binaries, dns_query, launch, observe_response, stop, tcp_query
from phase4 import wait_dns_ready
from phase4e2 import ROOT_CERTIFICATE, rejected_query
from phase4e4 import ReuseTLSAuthority
from phase4e5 import encrypted_udp_query


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e10-diff.json"


def render_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    dns_port: int,
    upstream_port: int,
    fragment: str,
    include_root: bool,
) -> None:
    tls = ""
    if include_root:
        root_pem = "\n".join(
            f"      {line}" for line in ROOT_CERTIFICATE.read_text().splitlines()
        )
        tls = f"tls:\n  custom-certifactes:\n    - |-\n{root_pem}\n"
    path.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
{tls}dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  nameserver:
    - tls://127.0.0.1:{upstream_port}{fragment}
rules:
  - MATCH,DIRECT
"""
    )


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    configs: dict[str, pathlib.Path] = {}
    cases = {
        "default-reuse": "",
        "default-no-reuse": "#disable-reuse=true",
        "skip-reuse": "#skip-cert-verify=true",
        "skip-no-reuse": "#skip-cert-verify=true&disable-reuse=true",
        "name-reuse": "#name-cert-verify=dot.phase4.test",
        "name-no-reuse": (
            "#name-cert-verify=dot.phase4.test&disable-reuse=true"
        ),
        "name-over-skip": (
            "#skip-cert-verify=true&name-cert-verify=dot.phase4.test"
        ),
    }
    for name, fragment in cases.items():
        config = scratch / f"{name}.yaml"
        render_config(
            config,
            mixed_port=reserve_port(),
            dns_port=reserve_port(),
            upstream_port=reserve_port(),
            fragment=fragment,
            include_root=name.startswith("name"),
        )
        configs[name] = config
    invalid = scratch / "wrong-scheme.yaml"
    render_config(
        invalid,
        mixed_port=reserve_port(),
        dns_port=reserve_port(),
        upstream_port=reserve_port(),
        fragment="",
        include_root=False,
    )
    invalid.write_text(invalid.read_text().replace("tls://", "bogus://"))
    configs["wrong-scheme"] = invalid
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


def exercise(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    fragment: str,
    include_root: bool,
    accepted: bool,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = ReuseTLSAuthority(close_after_response=False)
    authority_thread = threading.Thread(target=authority.serve_forever, daemon=True)
    authority_thread.start()
    mixed_port, dns_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        upstream_port=authority.server_address[1],
        fragment=fragment,
        include_root=include_root,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        observations: dict[str, Any] = {}
        for inbound, query_fn, identifier in (
            ("udp", encrypted_udp_query, 0x8710),
            ("tcp", tcp_query, 0x8720),
        ):
            query = dns_query(f"{inbound}.{scratch.name}.phase4.test", identifier)
            if accepted:
                observations[inbound] = observe_response(
                    query_fn(dns_port, query), identifier
                )
            else:
                observations[inbound] = rejected_query(query_fn, dns_port, query)
        observations["tls-authority"] = authority.snapshot()
        observations["exit-code"] = stop(process)
        return observations
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
    if any(code != 0 for name, code in config.items() if name != "wrong-scheme"):
        return {"config": config, "runtime": "not-run"}
    return {
        "config": config,
        "runtime": {
            "system-untrusted": exercise(
                binary,
                scratch / "system-untrusted",
                fragment="#disable-reuse=true",
                include_root=False,
                accepted=False,
            ),
            "global-root-default-name-mismatch": exercise(
                binary,
                scratch / "global-root-default-name-mismatch",
                fragment="#disable-reuse=true",
                include_root=True,
                accepted=False,
            ),
            "global-root-name-override": exercise(
                binary,
                scratch / "global-root-name-override",
                fragment="#name-cert-verify=dot.phase4.test&disable-reuse=true",
                include_root=True,
                accepted=True,
            ),
            "skip-no-reuse": exercise(
                binary,
                scratch / "skip-no-reuse",
                fragment="#skip-cert-verify=true&disable-reuse=true",
                include_root=False,
                accepted=True,
            ),
            "skip-reuse": exercise(
                binary,
                scratch / "skip-reuse",
                fragment="#skip-cert-verify=true",
                include_root=False,
                accepted=True,
            ),
            "name-over-skip-untrusted": exercise(
                binary,
                scratch / "name-over-skip-untrusted",
                fragment=(
                    "#skip-cert-verify=true&name-cert-verify=dot.phase4.test"
                ),
                include_root=False,
                accepted=False,
            ),
        },
    }


def satisfies_phase_contract(observation: dict[str, Any]) -> bool:
    expected_config = {
        "default-reuse": 0,
        "default-no-reuse": 0,
        "skip-reuse": 0,
        "skip-no-reuse": 0,
        "name-reuse": 0,
        "name-no-reuse": 0,
        "name-over-skip": 0,
        "wrong-scheme": 1,
    }
    if observation["config"] != expected_config:
        return False
    runtime = observation["runtime"]
    for name in ("system-untrusted", "global-root-default-name-mismatch", "name-over-skip-untrusted"):
        case = runtime[name]
        if (
            case["udp"].get("answers") != 0
            or case["tcp"].get("answers") != 0
            or case["tls-authority"]["queries"] != {"tls": 0}
            or case["exit-code"] != 0
        ):
            return False
    for name, connections in (
        ("global-root-name-override", 2),
        ("skip-no-reuse", 2),
        ("skip-reuse", 1),
    ):
        case = runtime[name]
        if (
            case["udp"].get("address") != "192.0.2.42"
            or case["tcp"].get("address") != "192.0.2.42"
            or case["tls-authority"]
            != {"connections": connections, "queries": {"tls": 2}}
            or case["exit-code"] != 0
        ):
            return False
    return True


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e10-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if observations["go"] != observations["rust"] or not satisfies_phase_contract(
            observations["go"]
        ):
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4E10 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E10 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

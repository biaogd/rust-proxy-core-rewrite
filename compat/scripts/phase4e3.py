#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E3 multiple DoT roots."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase4 import (
    build_binaries,
    dns_query,
    launch,
    observe_response,
    stop,
    tcp_query,
    udp_query,
    wait_dns_ready,
)
from phase4e2 import ROOT_CERTIFICATE, TLSAuthority, rejected_query


FIXTURE = ROOT / "compat" / "fixtures" / "phase4" / "dot-multi-root.yaml.tmpl"
DECOY_CERTIFICATE = ROOT / "compat" / "fixtures" / "phase4" / "phase4e3-decoy-root.pem"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e3-diff.json"


def roots_yaml(certificates: list[pathlib.Path]) -> str:
    blocks = []
    for certificate in certificates:
        lines = certificate.read_text().splitlines()
        blocks.append("    - |-\n" + "\n".join(f"      {line}" for line in lines))
    return "\n".join(blocks)


def render_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    dns_port: int,
    upstream_port: int,
    certificates: list[pathlib.Path],
) -> None:
    path.write_text(
        FIXTURE.read_text()
        .replace("${MIXED_PORT}", str(mixed_port))
        .replace("${DNS_PORT}", str(dns_port))
        .replace("${UPSTREAM_PORT}", str(upstream_port))
        .replace("${ROOTS_PEM}", roots_yaml(certificates))
    )


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    valid = scratch / "valid.yaml"
    render_config(
        valid,
        mixed_port=reserve_port(),
        dns_port=reserve_port(),
        upstream_port=reserve_port(),
        certificates=[DECOY_CERTIFICATE, ROOT_CERTIFICATE],
    )
    wrong_scheme = scratch / "wrong-scheme.yaml"
    wrong_scheme.write_text(valid.read_text().replace("tls://", "bogus://"))
    return {
        name: subprocess.run(
            [str(binary), "-t", "-f", str(path)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        for name, path in {"valid-multiple": valid, "wrong-scheme": wrong_scheme}.items()
    }


def exercise(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    certificates: list[pathlib.Path],
    trusted: bool,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = TLSAuthority()
    authority_thread = threading.Thread(target=authority.serve_forever, daemon=True)
    authority_thread.start()
    mixed_port, dns_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        upstream_port=authority.server_address[1],
        certificates=certificates,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        observations: dict[str, Any] = {}
        for inbound, query_fn, identifier in (
            ("udp", udp_query, 0x8010),
            ("tcp", tcp_query, 0x8020),
        ):
            name = f"{inbound}.roots.phase4.test"
            query = dns_query(name, identifier)
            if trusted:
                first = query_fn(dns_port, query)
                cached = query_fn(dns_port, dns_query(name, identifier + 1))
                observations[inbound] = {
                    "first": observe_response(first, identifier),
                    "cached": observe_response(cached, identifier + 1),
                }
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
    return {
        "config": validation(binary, scratch),
        "issuer-second": exercise(
            binary,
            scratch / "issuer-second",
            [DECOY_CERTIFICATE, ROOT_CERTIFICATE],
            True,
        ),
        "issuer-first": exercise(
            binary,
            scratch / "issuer-first",
            [ROOT_CERTIFICATE, DECOY_CERTIFICATE],
            True,
        ),
        "decoy-only": exercise(
            binary,
            scratch / "decoy-only",
            [DECOY_CERTIFICATE],
            False,
        ),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e3-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4E3 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E3 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

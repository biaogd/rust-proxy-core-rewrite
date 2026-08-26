#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4D3A direct/lazy DNS."""

from __future__ import annotations

import json
import pathlib
import socket
import subprocess
import tempfile
import time
from typing import Any

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    recv_exact,
    reserve_port,
    socks_connect,
    start_server,
    wait_ready,
)
from phase4 import build_binaries, launch, stop, wait_dns_ready
from phase4d2 import LocalAuthority


FIXTURE = ROOT / "compat" / "fixtures" / "phase4" / "direct-lazy.yaml.tmpl"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4d3a-diff.json"

STANDARD_RULES = [
    "DOMAIN,domain-first.phase4.test,REJECT",
    "IP-CIDR,127.0.0.0/8,DIRECT",
    "MATCH,REJECT",
]
NO_RESOLVE_RULES = [
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "MATCH,REJECT",
]


def main_answer(name: str) -> str:
    if name == "miss.phase4.test":
        return "192.0.2.10"
    return "127.0.0.2"


def make_authorities() -> dict[str, LocalAuthority]:
    return {
        "main": LocalAuthority(main_answer),
        "direct": LocalAuthority("127.0.0.1"),
        "policy": LocalAuthority("127.0.0.1"),
    }


def render_config(
    path: pathlib.Path,
    mixed_port: int,
    dns_port: int,
    authorities: dict[str, LocalAuthority],
    follow_policy: bool,
    rules: list[str],
) -> None:
    rule_lines = "\n".join(f"  - {rule}" for rule in rules)
    path.write_text(
        FIXTURE.read_text()
        .replace("${MIXED_PORT}", str(mixed_port))
        .replace("${DNS_PORT}", str(dns_port))
        .replace("${MAIN_PORT}", str(authorities["main"].port))
        .replace("${DIRECT_PORT}", str(authorities["direct"].port))
        .replace("${POLICY_PORT}", str(authorities["policy"].port))
        .replace("${FOLLOW_POLICY}", str(follow_policy).lower())
        .replace("${RULES}", rule_lines)
    )


def validation(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authorities: dict[str, LocalAuthority],
) -> dict[str, int]:
    valid = scratch / "valid.yaml"
    render_config(
        valid,
        reserve_port(),
        reserve_port(),
        authorities,
        False,
        STANDARD_RULES,
    )
    wrong_scheme = scratch / "wrong-scheme.yaml"
    wrong_scheme.write_text(
        valid.read_text().replace(
            f"tcp://127.0.0.1:{authorities['direct'].port}",
            f"bogus://127.0.0.1:{authorities['direct'].port}",
        )
    )
    wrong_follow = scratch / "wrong-follow.yaml"
    wrong_follow.write_text(
        valid.read_text().replace("direct-nameserver-follow-policy: false", "direct-nameserver-follow-policy: text")
    )
    result: dict[str, int] = {}
    for name, path in {
        "valid": valid,
        "wrong-scheme": wrong_scheme,
        "wrong-follow": wrong_follow,
    }.items():
        result[name] = subprocess.run(
            [str(binary), "-t", "-f", str(path)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
    return result


def domain_stream(proxy_port: int, domain: str, destination_port: int) -> socket.socket:
    encoded = domain.encode("ascii")
    return socks_connect(
        proxy_port,
        3,
        bytes([len(encoded)]) + encoded,
        destination_port,
    )


def observe_closed(stream: socket.socket) -> str:
    try:
        return "closed" if stream.recv(1) == b"" else "open"
    except (ConnectionResetError, BrokenPipeError):
        return "closed"


def exercise(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authorities: dict[str, LocalAuthority],
    echo_port: int,
    follow_policy: bool,
    rules: list[str],
    cases: list[tuple[str, str, str]],
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    mixed_port = reserve_port()
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port,
        dns_port,
        authorities,
        follow_policy,
        rules,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    observations: dict[str, Any] = {}
    try:
        wait_ready(process, mixed_port)
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        for label, domain, expected in cases:
            with domain_stream(mixed_port, domain, echo_port) as stream:
                if expected == "echo":
                    payload = label.encode("ascii")
                    stream.sendall(payload)
                    try:
                        observations[label] = recv_exact(stream, len(payload)).decode("ascii")
                    except (EOFError, OSError) as error:
                        snapshots = {
                            name: authority.state.snapshot()
                            for name, authority in authorities.items()
                        }
                        raise AssertionError(
                            f"{label} relay failed after DNS observations {snapshots}"
                        ) from error
                else:
                    observations[label] = observe_closed(stream)
        observations["exit-code"] = stop(process)
        return observations
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def run_mode(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    echo_port: int,
    follow_policy: bool,
    rules: list[str],
    cases: list[tuple[str, str, str]],
) -> dict[str, Any]:
    authorities = make_authorities()
    try:
        return {
            "runtime": exercise(
                binary,
                scratch,
                authorities,
                echo_port,
                follow_policy,
                rules,
                cases,
            ),
            "authorities": {
                name: authority.state.snapshot()
                for name, authority in authorities.items()
            },
        }
    finally:
        for authority in authorities.values():
            authority.close()


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path, echo_port: int) -> dict[str, Any]:
    validation_authorities = make_authorities()
    try:
        config = validation(binary, scratch, validation_authorities)
    finally:
        for authority in validation_authorities.values():
            authority.close()

    return {
        "config": config,
        "ordered": run_mode(
            binary,
            scratch / "ordered",
            echo_port,
            False,
            STANDARD_RULES,
            [
                ("domain-first", "domain-first.phase4.test", "closed"),
                ("lazy-direct", "route.phase4.test", "echo"),
                ("lazy-miss", "miss.phase4.test", "closed"),
                ("direct-no-follow", "x.follow.phase4.test", "echo"),
            ],
        ),
        "no-resolve": run_mode(
            binary,
            scratch / "no-resolve",
            echo_port,
            False,
            NO_RESOLVE_RULES,
            [("no-resolve", "no-resolve.phase4.test", "closed")],
        ),
        "follow-policy": run_mode(
            binary,
            scratch / "follow-policy",
            echo_port,
            True,
            STANDARD_RULES,
            [("direct-follow", "x.follow.phase4.test", "echo")],
        ),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    echo = start_server(EchoHandler)
    try:
        with tempfile.TemporaryDirectory(prefix="mihomo-phase4d3a-") as temporary:
            root = pathlib.Path(temporary)
            binaries = build_binaries(root)
            observations: dict[str, Any] = {}
            for implementation, binary in binaries.items():
                scratch = root / implementation
                scratch.mkdir()
                observations[implementation] = run_candidate(binary, scratch, echo.port)
            if observations["go"] != observations["rust"]:
                FAILURE_ARTIFACT.write_text(
                    json.dumps(observations, indent=2, sort_keys=True)
                )
                raise SystemExit(f"Phase 4D3A mismatch; see {FAILURE_ARTIFACT}")
    finally:
        echo.close()
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4D3A Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

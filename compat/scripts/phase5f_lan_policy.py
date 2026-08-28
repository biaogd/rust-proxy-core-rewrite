#!/usr/bin/env python3
"""Go/Rust differential for Phase 5F1 fixed-listener LAN policies."""

from __future__ import annotations

import http.client
import json
import pathlib
import socket
import tempfile
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, socks_connect, start_server, reserve_port, wait_ready
from phase3 import http_request, launch, status, stop
from phase5b1a import build_binaries, debug_files
from phase5b3a import relay_result
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5f-lan-policy-diff.json"


def controller_snapshot(port: int) -> dict[str, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    connection.request(
        "GET", "/configs", headers={"Authorization": f"Bearer {SECRET}"}
    )
    response = connection.getresponse()
    try:
        if response.status != 200:
            raise AssertionError((response.status, response.read()))
        value = json.loads(response.read())
        return {
            key: value[key]
            for key in (
                "allow-lan",
                "bind-address",
                "skip-auth-prefixes",
                "lan-allowed-ips",
                "lan-disallowed-ips",
            )
        }
    finally:
        response.close()
        connection.close()


def http_route(port: int, destination_port: int) -> str:
    try:
        stream, response = http_request(port, destination_port, None)
        with stream:
            if " 200 " not in status(response):
                return status(response)
            return relay_result(stream, b"lan-http")
    except (OSError, EOFError, ConnectionResetError, BrokenPipeError):
        return "closed"


def socks_route(port: int, destination_port: int) -> str:
    try:
        stream = socks_connect(
            port, 1, socket.inet_aton("127.0.0.1"), destination_port
        )
        return relay_result(stream, b"lan-socks")
    except (OSError, EOFError, ConnectionResetError, BrokenPipeError):
        return "closed"


def exercise_skip_auth(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    http_port, socks_port, mixed_port = reserve_port(), reserve_port(), reserve_port()
    controller_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""port: {http_port}
socks-port: {socks_port}
mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
allow-lan: true
bind-address: 0.0.0.0
skip-auth-prefixes: [127.0.0.0/8]
lan-allowed-ips: [0.0.0.0/0]
lan-disallowed-ips: []
authentication: [alice:secret]
mode: rule
log-level: info
ipv6: false
rules: ['MATCH,DIRECT']
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        for port in (http_port, socks_port, mixed_port):
            wait_ready(process, port)
        wait_controller(process, controller_port)
        return {
            "http": http_route(http_port, echo.port),
            "socks": socks_route(socks_port, echo.port),
            "mixed": http_route(mixed_port, echo.port),
            "config": controller_snapshot(controller_port),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise_policy(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    extra: str,
) -> str:
    echo = start_server(EchoHandler)
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
allow-lan: true
bind-address: 0.0.0.0
{extra}
mode: rule
log-level: info
ipv6: false
rules: ['MATCH,DIRECT']
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        return http_route(mixed_port, echo.port)
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise_loopback_override(
    binary: pathlib.Path, scratch: pathlib.Path
) -> str:
    echo = start_server(EchoHandler)
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
allow-lan: false
bind-address: 192.0.2.1
mode: rule
log-level: info
ipv6: false
rules: ['MATCH,DIRECT']
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        return http_route(mixed_port, echo.port)
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    cases = {}
    for name in ("skip-auth", "allowed", "disallowed", "loopback-override"):
        case = scratch / name
        case.mkdir()
        cases[name] = case
    return {
        "skip-auth": exercise_skip_auth(binary, cases["skip-auth"]),
        "allowed-filter": exercise_policy(
            binary, cases["allowed"], "lan-allowed-ips: [192.0.2.0/24]"
        ),
        "disallowed-filter": exercise_policy(
            binary,
            cases["disallowed"],
            "lan-allowed-ips: [0.0.0.0/0]\nlan-disallowed-ips: [127.0.0.0/8]",
        ),
        "allow-lan-false-ignores-bind": exercise_loopback_override(
            binary, cases["loopback-override"]
        ),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5f-lan-policy-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE5FLANPOLICY_CARGO_TARGET", "phase5f-lan-policy"
        )
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
    print("Phase 5F1 LAN policy differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

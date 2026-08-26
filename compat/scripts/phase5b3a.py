#!/usr/bin/env python3
"""Go/Rust mixed-TCP differential for Phase 5B3a IN-TYPE."""

from __future__ import annotations

import json
import pathlib
import socket
import tempfile
import time
from typing import Any, Callable

from phase1 import (
    CaptureHttpHandler,
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    connect_proxy,
    recv_all,
    recv_exact,
    socks_connect,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, socks4_connect, stop
from phase5b1a import build_binaries, debug_files, route as http_route


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b3a-diff.json"


def relay_result(stream: socket.socket, payload: bytes) -> str:
    with stream:
        try:
            stream.sendall(payload)
            return "direct" if recv_exact(stream, len(payload)) == payload else "unexpected"
        except (EOFError, ConnectionResetError, BrokenPipeError):
            return "reject"


def socks5_route(proxy_port: int, destination_port: int) -> str:
    stream = socks_connect(
        proxy_port,
        1,
        socket.inet_aton("127.0.0.1"),
        destination_port,
    )
    return relay_result(stream, b"socks5-type")


def socks4_route(proxy_port: int, destination_port: int) -> str:
    stream, reply = socks4_connect(proxy_port, destination_port, b"phase5b3a")
    if reply[1] != 0x5A:
        stream.close()
        raise AssertionError(f"SOCKS4 CONNECT failed: {reply!r}")
    return relay_result(stream, b"socks4-type")


def http_absolute_route(proxy_port: int, destination_port: int) -> str:
    with connect_proxy(proxy_port) as stream:
        stream.sendall(
            (
                f"GET http://127.0.0.1:{destination_port}/in-type HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{destination_port}\r\nConnection: close\r\n\r\n"
            ).encode()
        )
        try:
            response = recv_all(stream)
        except (ConnectionResetError, BrokenPipeError):
            return "reject"
    return "direct" if b"phase-one-origin" in response else "reject"


def exercise_config(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    rules: list[str],
    expected: dict[str, str],
) -> dict[str, str]:
    echo = start_server(EchoHandler)
    origin = start_server(CaptureHttpHandler)
    proxy_port = reserve_port()
    rendered_rules = "\n".join(f"  - {rule}" for rule in rules)
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {proxy_port}
mode: rule
log-level: info
ipv6: false
rules:
{rendered_rules}
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    probes: dict[str, Callable[[], str]] = {
        "http-connect": lambda: http_route(proxy_port, "127.0.0.1", echo.port),
        "http-absolute": lambda: http_absolute_route(proxy_port, origin.port),
        "socks4": lambda: socks4_route(proxy_port, echo.port),
        "socks5": lambda: socks5_route(proxy_port, echo.port),
    }
    try:
        wait_ready(process, proxy_port)
        observations: dict[str, str] = {}
        order = sorted(probes, key=lambda name: expected[name] != "direct")
        for name in order:
            deadline = time.monotonic() + IO_DEADLINE
            while time.monotonic() < deadline:
                try:
                    observations[name] = probes[name]()
                    if observations[name] == expected[name]:
                        break
                except OSError:
                    pass
                time.sleep(0.02)
            else:
                raise TimeoutError(
                    f"{name} route did not become {expected[name]}: "
                    f"{observations.get(name)}"
                )
        return {name: observations[name] for name in probes}
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()
        origin.close()


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    explicit = scratch / "explicit"
    alias = scratch / "alias"
    explicit.mkdir()
    alias.mkdir()
    return {
        "explicit-list": exercise_config(
            binary,
            explicit,
            [
                "IN-TYPE,HTTP/SOCKS4,DIRECT",
                "IN-TYPE,HTTPS/SOCKS5,REJECT",
                "MATCH,REJECT",
            ],
            {
                "http-connect": "reject",
                "http-absolute": "direct",
                "socks4": "direct",
                "socks5": "reject",
            },
        ),
        "socks-alias": exercise_config(
            binary,
            alias,
            ["IN-TYPE,SOCKS,DIRECT", "MATCH,REJECT"],
            {
                "http-connect": "reject",
                "http-absolute": "reject",
                "socks4": "direct",
                "socks5": "direct",
            },
        ),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    debug: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b3a-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5B3A_CARGO_TARGET", "phase5b3a")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
            debug = debug_files(root)
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
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {"observations": observations, "debug": debug},
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5B3a IN-TYPE mixed-TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

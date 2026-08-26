#!/usr/bin/env python3
"""Go/Rust mixed-TCP differential for Phase 5B3b IN-USER."""

from __future__ import annotations

import base64
import json
import pathlib
import socket
import tempfile
import time
from typing import Any, Callable

from phase1 import EchoHandler, IO_DEADLINE, ROOT, recv_exact, reserve_port, start_server, wait_ready
from phase3 import http_request, launch, socks4_connect, socks5_authenticated, status, stop
from phase5b1a import build_binaries, debug_files


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b3b-diff.json"


def relay_result(stream: socket.socket, payload: bytes) -> str:
    with stream:
        try:
            stream.sendall(payload)
            return "direct" if recv_exact(stream, len(payload)) == payload else "unexpected"
        except (EOFError, ConnectionResetError, BrokenPipeError):
            return "reject"


def http_user_route(
    proxy_port: int,
    destination_port: int,
    username: str,
    password: str,
) -> str:
    credential = base64.b64encode(f"{username}:{password}".encode()).decode()
    stream, response = http_request(
        proxy_port,
        destination_port,
        f"Basic {credential}",
    )
    if " 200 " not in status(response):
        stream.close()
        raise AssertionError(response)
    return relay_result(stream, b"http-user")


def socks5_user_route(
    proxy_port: int,
    destination_port: int,
    username: bytes,
    password: bytes,
) -> str:
    stream, method, authentication = socks5_authenticated(
        proxy_port,
        destination_port,
        username,
        password,
    )
    if method != b"\x05\x02" or authentication != b"\x01\x00":
        stream.close()
        raise AssertionError((method, authentication))
    return relay_result(stream, b"socks5-user")


def socks4_user_route(
    proxy_port: int,
    destination_port: int,
    username: bytes,
) -> str:
    stream, reply = socks4_connect(proxy_port, destination_port, username)
    if reply[1] != 0x5A:
        stream.close()
        raise AssertionError(reply)
    return relay_result(stream, b"socks4-user")


def exercise_config(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    rules: list[str],
    expected: dict[str, str],
) -> dict[str, str]:
    echo = start_server(EchoHandler)
    proxy_port = reserve_port()
    rendered_rules = "\n".join(f"  - {rule}" for rule in rules)
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {proxy_port}
mode: rule
log-level: info
ipv6: false
authentication:
  - alice:secret
  - Alice:capital
  - "socks4:"
rules:
{rendered_rules}
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    probes: dict[str, Callable[[], str]] = {
        "http-alice": lambda: http_user_route(proxy_port, echo.port, "alice", "secret"),
        "socks5-alice": lambda: socks5_user_route(
            proxy_port, echo.port, b"alice", b"secret"
        ),
        "socks4": lambda: socks4_user_route(proxy_port, echo.port, b"socks4"),
        "http-case-miss": lambda: http_user_route(
            proxy_port, echo.port, "Alice", "capital"
        ),
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


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    exact = scratch / "exact"
    users = scratch / "list"
    exact.mkdir()
    users.mkdir()
    return {
        "exact": exercise_config(
            binary,
            exact,
            [
                "IN-USER,alice,DIRECT",
                "IN-USER,socks4,REJECT",
                "MATCH,REJECT",
            ],
            {
                "http-alice": "direct",
                "socks5-alice": "direct",
                "socks4": "reject",
                "http-case-miss": "reject",
            },
        ),
        "slash-list": exercise_config(
            binary,
            users,
            ["IN-USER,alice/socks4,DIRECT", "MATCH,REJECT"],
            {
                "http-alice": "direct",
                "socks5-alice": "direct",
                "socks4": "direct",
                "http-case-miss": "reject",
            },
        ),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    debug: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b3b-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5B3B_CARGO_TARGET", "phase5b3b")
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
    print("Phase 5B3b IN-USER mixed-TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for controller connection deletion side effects."""

from __future__ import annotations

import http.client
import json
import pathlib
import socket
import tempfile
import time
from typing import Any

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    recv_exact,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import http_request, launch, status, stop
from phase5b1a import build_binaries, debug_files
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5d-connections-diff.json"


def controller_request(
    port: int, method: str, path: str
) -> tuple[int, bytes, dict[str, str]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    connection.request(
        method, path, headers={"Authorization": f"Bearer {SECRET}"}
    )
    response = connection.getresponse()
    try:
        return response.status, response.read(), {
            name.lower(): value for name, value in response.getheaders()
        }
    finally:
        response.close()
        connection.close()


def snapshot(port: int) -> dict[str, Any]:
    code, body, _ = controller_request(port, "GET", "/connections")
    if code != 200:
        raise AssertionError((code, body))
    return json.loads(body)


def wait_connection_count(port: int, expected: int) -> dict[str, Any]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        current = snapshot(port)
        connections = current.get("connections") or []
        if len(connections) == expected:
            return current
        time.sleep(0.02)
    raise TimeoutError(f"connection count did not become {expected}")


def wait_stream_closed(stream: socket.socket) -> None:
    stream.settimeout(0.1)
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        try:
            if stream.recv(1) == b"":
                return
        except socket.timeout:
            pass
        except (ConnectionResetError, BrokenPipeError):
            return
    raise TimeoutError("deleted tracked connection remained open")


def open_tunnel(mixed_port: int, echo_port: int) -> socket.socket:
    stream, response = http_request(mixed_port, echo_port, None)
    if " 200 " not in status(response):
        stream.close()
        raise AssertionError(response)
    return stream


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    first: socket.socket | None = None
    second: socket.socket | None = None
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        first = open_tunnel(mixed_port, echo.port)
        second = open_tunnel(mixed_port, echo.port)
        # CONNECT success can precede publication in the Go tracker. A byte
        # round-trip proves both tunnels reached the observable relay state
        # before the exact controller-count assertion.
        first.sendall(b"1")
        second.sendall(b"2")
        if recv_exact(first, 1) != b"1" or recv_exact(second, 1) != b"2":
            raise AssertionError("connection tracker readiness echo mismatch")
        first_port = str(first.getsockname()[1])
        second_port = str(second.getsockname()[1])
        active = wait_connection_count(controller_port, 2)
        by_source = {
            connection["metadata"]["sourcePort"]: connection
            for connection in active["connections"]
        }
        first_id = by_source[first_port]["id"]

        one_status, one_body, _ = controller_request(
            controller_port, "DELETE", f"/connections/{first_id}"
        )
        wait_stream_closed(first)
        after_one = wait_connection_count(controller_port, 1)
        survivor = after_one["connections"][0]
        if survivor["metadata"]["sourcePort"] != second_port:
            raise AssertionError(f"wrong connection survived: {survivor}")
        second.sendall(b"survivor")
        survivor_echo = recv_exact(second, 8) == b"survivor"

        missing_status, missing_body, _ = controller_request(
            controller_port, "DELETE", "/connections/not-present"
        )
        all_status, all_body, _ = controller_request(
            controller_port, "DELETE", "/connections"
        )
        wait_stream_closed(second)
        after_all = wait_connection_count(controller_port, 0)

        return {
            "initial-count": len(active["connections"]),
            "delete-one": {
                "status": one_status,
                "empty-body": one_body == b"",
                "remaining": len(after_one["connections"]),
                "right-survivor": survivor_echo,
            },
            "delete-missing": {
                "status": missing_status,
                "empty-body": missing_body == b"",
            },
            "delete-all": {
                "status": all_status,
                "empty-body": all_body == b"",
                "connections-null": after_all["connections"] is None,
            },
        }
    finally:
        if first is not None:
            first.close()
        if second is not None:
            second.close()
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-connections-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE5DCONNECTIONS_CARGO_TARGET", "phase5d-connections"
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
        FAILURE_ARTIFACT.write_text(
            json.dumps({"observations": observations}, indent=2, sort_keys=True)
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5D complete connections controller differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

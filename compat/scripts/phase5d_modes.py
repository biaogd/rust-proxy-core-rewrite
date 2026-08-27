#!/usr/bin/env python3
"""Go/Rust differential for rule/direct/global live routing modes."""

from __future__ import annotations

import http.client
import json
import pathlib
import socketserver
import tempfile
import threading
import time
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import UdpEchoHandler, launch, stop
from phase5b1a import build_binaries, debug_files, route, wait_route
from phase5b_udp import udp_client, udp_result
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5d-modes-diff.json"


def request(
    port: int, method: str, path: str, value: dict[str, Any]
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    connection.request(
        method,
        path,
        body=json.dumps(value).encode(),
        headers={
            "Authorization": f"Bearer {SECRET}",
            "Content-Type": "application/json",
        },
    )
    response = connection.getresponse()
    try:
        return response.status, response.read()
    finally:
        response.close()
        connection.close()


def mode(port: int) -> str:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    connection.request(
        "GET", "/configs", headers={"Authorization": f"Bearer {SECRET}"}
    )
    response = connection.getresponse()
    try:
        if response.status != 200:
            raise AssertionError((response.status, response.read()))
        return json.loads(response.read())["mode"]
    finally:
        response.close()
        connection.close()


def empty(result: tuple[int, bytes]) -> dict[str, Any]:
    status, body = result
    return {"status": status, "empty-body": body == b""}


def observe(
    mixed_port: int,
    tcp_port: int,
    udp_port: int,
    controller_port: int,
) -> dict[str, str]:
    return {
        "mode": mode(controller_port),
        "tcp": route(mixed_port, "127.0.0.1", tcp_port),
        "udp": fresh_udp_result(mixed_port, udp_port, b"mode-observe"),
    }


def wait_paths(
    process: Any,
    mixed_port: int,
    tcp_port: int,
    udp_port: int,
    expected: str,
    label: str,
) -> None:
    wait_route(process, mixed_port, "127.0.0.1", tcp_port, expected)
    deadline = time.monotonic() + (2 * IO_DEADLINE) + 1
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during {label}: {process.returncode}")
        if fresh_udp_result(mixed_port, udp_port, label.encode()) == expected:
            return
        time.sleep(0.02)
    raise TimeoutError(f"{label} did not become {expected}")


def fresh_udp_result(proxy_port: int, destination_port: int, payload: bytes) -> str:
    client = udp_client()
    try:
        return udp_result(client, proxy_port, destination_port, payload)
    finally:
        client.close()


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    tcp_echo = start_server(EchoHandler)
    udp_echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    udp_thread = threading.Thread(target=udp_echo.serve_forever, daemon=True)
    udp_thread.start()
    udp_port = int(udp_echo.server_address[1])
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
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    observations: dict[str, Any] = {}
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_paths(
            process,
            mixed_port,
            tcp_echo.port,
            udp_port,
            "reject",
            "initial-rule",
        )
        observations["rule"] = observe(
            mixed_port, tcp_echo.port, udp_port, controller_port
        )

        observations["patch-direct"] = empty(
            request(controller_port, "PATCH", "/configs", {"mode": "direct"})
        )
        wait_paths(
            process,
            mixed_port,
            tcp_echo.port,
            udp_port,
            "direct",
            "patch-direct",
        )
        observations["direct"] = observe(
            mixed_port, tcp_echo.port, udp_port, controller_port
        )

        observations["patch-global"] = empty(
            request(controller_port, "PATCH", "/configs", {"mode": "global"})
        )
        wait_paths(
            process,
            mixed_port,
            tcp_echo.port,
            udp_port,
            "direct",
            "global-direct",
        )
        observations["global-direct"] = observe(
            mixed_port, tcp_echo.port, udp_port, controller_port
        )

        observations["select-reject"] = empty(
            request(
                controller_port,
                "PUT",
                "/proxies/GLOBAL",
                {"name": "REJECT"},
            )
        )
        wait_paths(
            process,
            mixed_port,
            tcp_echo.port,
            udp_port,
            "reject",
            "global-reject",
        )
        observations["global-reject"] = observe(
            mixed_port, tcp_echo.port, udp_port, controller_port
        )

        observations["select-direct"] = empty(
            request(
                controller_port,
                "PUT",
                "/proxies/GLOBAL",
                {"name": "DIRECT"},
            )
        )
        wait_paths(
            process,
            mixed_port,
            tcp_echo.port,
            udp_port,
            "direct",
            "global-restored",
        )

        observations["patch-rule"] = empty(
            request(controller_port, "PATCH", "/configs", {"mode": "rule"})
        )
        wait_paths(
            process,
            mixed_port,
            tcp_echo.port,
            udp_port,
            "reject",
            "rule-restored",
        )
        observations["rule-restored"] = observe(
            mixed_port, tcp_echo.port, udp_port, controller_port
        )

        invalid_status, invalid_body = request(
            controller_port, "PATCH", "/configs", {"mode": "invalid"}
        )
        observations["invalid-mode"] = {
            "status": invalid_status,
            "message": json.loads(invalid_body)["message"],
            "preserved": mode(controller_port),
        }

        payload = f"""mixed-port: {mixed_port}
mode: direct
log-level: info
ipv6: false
rules:
  - MATCH,REJECT
"""
        observations["put-direct"] = empty(
            request(
                controller_port,
                "PUT",
                "/configs",
                {"path": "", "payload": payload},
            )
        )
        wait_paths(
            process,
            mixed_port,
            tcp_echo.port,
            udp_port,
            "direct",
            "put-direct",
        )
        observations["put-direct-paths"] = observe(
            mixed_port, tcp_echo.port, udp_port, controller_port
        )
        return observations
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        tcp_echo.close()
        udp_echo.shutdown()
        udp_echo.server_close()
        udp_thread.join(timeout=IO_DEADLINE)


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-modes-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5DMODES_CARGO_TARGET", "phase5d-modes")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
        except Exception as exc:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "error": f"{type(exc).__name__}: {exc}",
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
    print("Phase 5D live routing mode differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

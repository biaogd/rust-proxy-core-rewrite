#!/usr/bin/env python3
"""Go/Rust differential for executable controller configuration transactions."""

from __future__ import annotations

import http.client
import json
import pathlib
import socket
import tempfile
import time
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files, route, wait_route
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5d-configs-diff.json"


def request(
    port: int,
    method: str,
    path: str,
    body: bytes | None = None,
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    headers = {"Authorization": f"Bearer {SECRET}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    try:
        return response.status, response.read()
    finally:
        response.close()
        connection.close()


def json_request(
    port: int,
    method: str,
    path: str,
    value: dict[str, Any],
) -> tuple[int, bytes]:
    return request(port, method, path, json.dumps(value).encode())


def selected_config(port: int) -> dict[str, Any]:
    code, body = request(port, "GET", "/configs")
    if code != 200:
        raise AssertionError((code, body))
    config = json.loads(body)
    return {
        name: config[name]
        for name in ("port", "socks-port", "mixed-port", "mode", "log-level", "ipv6")
    }


def normalize_config(
    config: dict[str, Any], initial_port: int, moved_port: int
) -> dict[str, Any]:
    normalized = dict(config)
    normalized["mixed-port"] = {
        initial_port: "initial",
        moved_port: "moved",
    }.get(config["mixed-port"], config["mixed-port"])
    return normalized


def wait_port_closed(process: Any, port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited while retiring listener: {process.returncode}")
        try:
            stream = socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except OSError:
            return
        stream.close()
        time.sleep(0.02)
    raise TimeoutError(f"old mixed listener {port} remained open")


def replacement(mixed_port: int, rule: str) -> str:
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: debug
ipv6: true
rules:
  - MATCH,{rule}
"""


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    initial_port, moved_port, controller_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {initial_port}
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
    try:
        wait_ready(process, initial_port)
        wait_controller(process, controller_port)
        wait_route(process, initial_port, "localhost", echo.port, "direct")

        initial = normalize_config(
            selected_config(controller_port), initial_port, moved_port
        )
        malformed_code, malformed_body = request(
            controller_port, "PATCH", "/configs", b"{"
        )
        unknown_code, unknown_body = json_request(
            controller_port, "PATCH", "/configs", {"future-field": 1}
        )
        patch_code, patch_body = json_request(
            controller_port,
            "PATCH",
            "/configs",
            {"mixed-port": moved_port, "log-level": "debug", "ipv6": True},
        )
        wait_route(process, moved_port, "localhost", echo.port, "direct")
        wait_port_closed(process, initial_port)
        after_patch = normalize_config(
            selected_config(controller_port), initial_port, moved_port
        )

        reject_code, reject_body = json_request(
            controller_port,
            "PUT",
            "/configs?force=true",
            {"payload": replacement(moved_port, "REJECT"), "path": ""},
        )
        if reject_code != 204:
            raise AssertionError(("inline reject", reject_code, reject_body))
        wait_route(process, moved_port, "localhost", echo.port, "reject")
        after_reject_raw = selected_config(controller_port)
        after_reject = normalize_config(after_reject_raw, initial_port, moved_port)

        invalid_code, invalid_body = json_request(
            controller_port,
            "PUT",
            "/configs",
            {"payload": "rules:\n  - [unterminated", "path": ""},
        )
        rollback_route = route(moved_port, "localhost", echo.port)
        rollback_config = normalize_config(
            selected_config(controller_port), initial_port, moved_port
        )

        path_code, path_body = json_request(
            controller_port,
            "PUT",
            "/configs",
            {"payload": "", "path": "relative.yaml"},
        )
        direct_code, direct_body = json_request(
            controller_port,
            "PUT",
            "/configs",
            {
                "payload": replacement(moved_port, "DIRECT"),
                "path": "relative-is-ignored-when-payload-is-present.yaml",
            },
        )
        wait_route(process, moved_port, "localhost", echo.port, "direct")

        return {
            "initial": initial,
            "malformed-patch": {
                "status": malformed_code,
                "message": json.loads(malformed_body)["message"],
            },
            "unknown-patch": {
                "status": unknown_code,
                "empty-body": unknown_body == b"",
            },
            "patch": {
                "status": patch_code,
                "empty-body": patch_body == b"",
                "old-listener-closed": True,
                "config": after_patch,
            },
            "inline-reject": {
                "status": reject_code,
                "empty-body": reject_body == b"",
                "controller-preserved": after_reject_raw["mixed-port"] == moved_port,
                "config": after_reject,
            },
            "invalid-inline-rollback": {
                "status": invalid_code,
                "has-message": bool(json.loads(invalid_body)["message"]),
                "route": rollback_route,
                "config": rollback_config,
            },
            "relative-path": {
                "status": path_code,
                "message": json.loads(path_body)["message"],
            },
            "payload-precedes-path": {
                "status": direct_code,
                "empty-body": direct_body == b"",
                "route": route(moved_port, "localhost", echo.port),
            },
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-configs-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE5DCONFIGS_CARGO_TARGET", "phase5d-configs"
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
    print("Phase 5D executable configuration differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

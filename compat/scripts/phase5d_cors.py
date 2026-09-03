#!/usr/bin/env python3
"""Go/Rust differential for dynamic external-controller CORS behavior."""

from __future__ import annotations

import http.client
import json
import os
import pathlib
import signal
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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5d-cors-diff.json"


def write_config(
    path: pathlib.Path,
    mixed_port: int,
    controller_port: int,
    cors: str = "",
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
{cors}rules:
  - MATCH,DIRECT
"""
    )


def request(
    port: int,
    method: str,
    origin: str,
    *,
    authorized: bool = True,
    requested_method: str | None = None,
    requested_headers: str | None = None,
    private_network: bool = False,
) -> dict[str, Any]:
    headers = {"Origin": origin}
    if authorized:
        headers["Authorization"] = f"Bearer {SECRET}"
    if requested_method is not None:
        headers["Access-Control-Request-Method"] = requested_method
    if requested_headers is not None:
        headers["Access-Control-Request-Headers"] = requested_headers
    if private_network:
        headers["Access-Control-Request-Private-Network"] = "true"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    connection.request(method, "/version", headers=headers)
    response = connection.getresponse()
    try:
        values: dict[str, list[str]] = {}
        for name, value in response.getheaders():
            values.setdefault(name.lower(), []).append(value)
        vary = sorted(
            token.strip().lower()
            for value in values.get("vary", [])
            for token in value.split(",")
            if token.strip()
        )
        return {
            "status": response.status,
            "allow-origin": first(values, "access-control-allow-origin"),
            "allow-methods": normalized_list(values, "access-control-allow-methods"),
            "allow-headers": normalized_list(values, "access-control-allow-headers"),
            "allow-private-network": first(
                values, "access-control-allow-private-network"
            ),
            "max-age": first(values, "access-control-max-age"),
            "vary": vary,
        }
    finally:
        response.read()
        response.close()
        connection.close()


def first(values: dict[str, list[str]], name: str) -> str | None:
    entries = values.get(name, [])
    return entries[0] if entries else None


def normalized_list(values: dict[str, list[str]], name: str) -> list[str]:
    return sorted(
        item.strip().lower()
        for value in values.get(name, [])
        for item in value.split(",")
        if item.strip()
    )


def wait_reload(
    process: Any,
    port: int,
    expected_origin: str,
    probe_origin: str,
) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    next_signal = 0.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"controller exited during CORS reload: {process.returncode}")
        now = time.monotonic()
        if now >= next_signal:
            os.kill(process.pid, signal.SIGHUP)
            next_signal = now + 0.2
        try:
            observed = request(port, "GET", probe_origin)
            if observed["allow-origin"] == expected_origin:
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError("controller CORS did not reload")


def preflight(port: int, origin: str, *, private: bool = True) -> dict[str, Any]:
    return request(
        port,
        "OPTIONS",
        origin,
        authorized=False,
        requested_method="delete",
        requested_headers="authorization, content-type",
        private_network=private,
    )


def wait_data_plane(process: Any, mixed_port: int, echo_port: int) -> None:
    """Wait for the Go listener and its published routing state as one barrier."""
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during data-plane readiness: {process.returncode}")
        try:
            barrier, response = http_request(mixed_port, echo_port, None)
            with barrier:
                if " 200 " not in status(response):
                    time.sleep(0.02)
                    continue
                barrier.sendall(b"signal-ready")
                if recv_exact(barrier, 12) == b"signal-ready":
                    return
        except (OSError, EOFError, ConnectionResetError, BrokenPipeError):
            pass
        time.sleep(0.02)
    raise TimeoutError("provider/signal readiness echo did not become observable")


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    write_config(config, mixed_port, controller_port)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_data_plane(process, mixed_port, echo.port)
        observations = {
            "default-actual": request(
                controller_port, "GET", "https://default.example.test"
            ),
            "default-unauthorized": request(
                controller_port,
                "GET",
                "https://default.example.test",
                authorized=False,
            ),
            "default-preflight": preflight(
                controller_port, "https://default.example.test"
            ),
            "invalid-method": request(
                controller_port,
                "OPTIONS",
                "https://default.example.test",
                authorized=False,
                requested_method="TRACE",
                requested_headers="Authorization",
            ),
            "invalid-header": request(
                controller_port,
                "OPTIONS",
                "https://default.example.test",
                authorized=False,
                requested_method="GET",
                requested_headers="X-Secret",
            ),
        }

        write_config(
            config,
            mixed_port,
            controller_port,
            """external-controller-cors:
  allow-origins:
    - https://allowed.example.test
    - https://*.wild.example.test
  allow-private-network: false
""",
        )
        wait_reload(
            process,
            controller_port,
            "https://allowed.example.test",
            "https://allowed.example.test",
        )
        observations.update(
            {
                "configured-exact": request(
                    controller_port, "GET", "https://allowed.example.test"
                ),
                "configured-wildcard": request(
                    controller_port, "GET", "HTTPS://APP.WILD.EXAMPLE.TEST"
                ),
                "configured-denied": request(
                    controller_port, "GET", "https://denied.example.test"
                ),
                "configured-private-disabled": preflight(
                    controller_port, "https://allowed.example.test"
                ),
            }
        )

        write_config(
            config,
            mixed_port,
            controller_port,
            """external-controller-cors:
  allow-origins: []
  allow-private-network: false
""",
        )
        wait_reload(
            process,
            controller_port,
            "*",
            "https://empty-list.example.test",
        )
        observations["empty-list-allows-all"] = request(
            controller_port, "GET", "https://empty-list.example.test"
        )
        return observations
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def main() -> int:
    if os.name == "nt":
        print("Phase 5D SIGHUP CORS reload differential is not applicable on Windows")
        return 0
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-cors-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5DCORS_CARGO_TARGET", "phase5d-cors")
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
    print("Phase 5D complete controller authentication/CORS differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

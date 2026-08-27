#!/usr/bin/env python3
"""Go/Rust differential for an initial local-file HTTP proxy provider."""

from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_selector import route
from phase5d_proxies import normalize, request
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-file-provider-diff.json"


def json_response(result: tuple[int, bytes]) -> tuple[int, Any]:
    status, body = result
    return status, normalize_provider(normalize(json.loads(body)))


def normalize_provider(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                int(datetime.fromisoformat(item).timestamp())
                if key == "updatedAt" and item != "0001-01-01T00:00:00Z"
                else normalize_provider(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [normalize_provider(item) for item in value]
    return value


def wait_provider_route(process, mixed_port: int, echo_port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during readiness with {process.returncode}")
        try:
            if route(mixed_port, echo_port) == "proxy":
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError("file-provider route did not become ready")


def wait_provider(controller_port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        try:
            status, body = request(
                controller_port, "GET", "/providers/proxies/local-file"
            )
            if status == 200 and json.loads(body).get("proxies"):
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError("file provider did not become ready")


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    upstream = ConnectProxyServer()
    mixed_port, controller_port = reserve_port(), reserve_port()
    provider_file = scratch / ".config" / "mihomo" / "provider.yaml"
    provider_file.parent.mkdir(parents=True)
    provider_file.write_text(
        f"""proxies:
  - name: provider-http
    type: http
    server: 127.0.0.1
    port: {upstream.port}
    username: proxy-user
    password: proxy-pass
"""
    )
    os.utime(provider_file, (1_700_000_000, 1_700_000_000))
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxy-providers:
  local-file:
    type: file
    path: {provider_file}
proxy-groups:
  - name: provider-group
    type: select
    proxies: [REJECT]
    use: [local-file]
    default-selected: provider-http
rules:
  - MATCH,provider-group
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_provider(controller_port)
        selected = request(
            controller_port,
            "PUT",
            "/proxies/provider-group",
            {"name": "provider-http"},
        )
        if selected[0] != 204:
            raise AssertionError(selected)
        wait_provider_route(process, mixed_port, echo.port)
        upstream.observations.clear()
        observations = {
            "provider-list": json_response(
                request(controller_port, "GET", "/providers/proxies")
            ),
            "provider-detail": json_response(
                request(controller_port, "GET", "/providers/proxies/local-file")
            ),
            "provider-member": json_response(
                request(
                    controller_port,
                    "GET",
                    "/providers/proxies/local-file/provider-http",
                )
            ),
            "group": json_response(
                request(controller_port, "GET", "/group/provider-group")
            ),
            "health": request(
                controller_port,
                "GET",
                "/providers/proxies/local-file/healthcheck",
            ),
            "route": route(mixed_port, echo.port),
        }
        observations["health"] = (
            observations["health"][0],
            observations["health"][1] == b"",
        )
        return observations
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        upstream.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-file-provider-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CFILEPROVIDER_CARGO_TARGET",
            "phase5c-file-provider",
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
    print("Phase 5C local file proxy-provider differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

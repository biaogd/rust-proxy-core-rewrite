#!/usr/bin/env python3
"""Go/Rust differential for manual file-provider refresh and rollback."""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_file_provider import wait_provider
from phase5c_selector import route
from phase5d_proxies import request
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-provider-refresh-diff.json"


def write_provider(path: Path, name: str, port: int, modified: int) -> None:
    path.write_text(
        f"""proxies:
  - name: {name}
    type: http
    server: 127.0.0.1
    port: {port}
    username: proxy-user
    password: proxy-pass
"""
    )
    os.utime(path, (modified, modified))


def provider_names(controller_port: int) -> list[str]:
    status, body = request(controller_port, "GET", "/providers/proxies/local-file")
    if status != 200:
        raise AssertionError((status, body))
    return [proxy["name"] for proxy in json.loads(body)["proxies"]]


def wait_names(controller_port: int, expected: list[str]) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        try:
            if provider_names(controller_port) == expected:
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError(f"provider members did not become {expected}")


def select(controller_port: int, name: str) -> tuple[int, bool]:
    status, body = request(
        controller_port,
        "PUT",
        "/proxies/provider-group",
        {"name": name},
    )
    return status, body == b""


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    first, second = ConnectProxyServer(), ConnectProxyServer()
    mixed_port, controller_port = reserve_port(), reserve_port()
    provider_file = scratch / ".config" / "mihomo" / "provider.yaml"
    provider_file.parent.mkdir(parents=True)
    write_provider(provider_file, "provider-one", first.port, 1_700_000_000)
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
rules:
  - MATCH,provider-group
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_provider(controller_port)
        initial_select = select(controller_port, "provider-one")
        initial_route = route(mixed_port, echo.port)

        write_provider(provider_file, "provider-two", second.port, 1_700_000_001)
        wait_names(controller_port, ["provider-two"])
        watched_names = provider_names(controller_port)
        refreshed = request(
            controller_port, "PUT", "/providers/proxies/local-file"
        )
        wait_names(controller_port, ["provider-two"])
        old_member = request(
            controller_port,
            "GET",
            "/providers/proxies/local-file/provider-one",
        )
        second_select = select(controller_port, "provider-two")
        second_route = route(mixed_port, echo.port)

        provider_file.write_text("proxies: [")
        failed = request(controller_port, "PUT", "/providers/proxies/local-file")
        failed_json = json.loads(failed[1])
        retained_names = provider_names(controller_port)
        retained_route = route(mixed_port, echo.port)
        return {
            "initial-select": initial_select,
            "initial-route": initial_route,
            "refresh": (refreshed[0], refreshed[1] == b""),
            "watched-names": watched_names,
            "old-member": (old_member[0], json.loads(old_member[1])["message"]),
            "second-select": second_select,
            "second-route": second_route,
            "failed-refresh": {
                "status": failed[0],
                "message-is-string": isinstance(failed_json.get("message"), str),
            },
            "retained-names": retained_names,
            "retained-route": retained_route,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        first.close()
        second.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-provider-refresh-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CPROVIDERREFRESH_CARGO_TARGET",
            "phase5c-provider-refresh",
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
    print("Phase 5C file-provider refresh/rollback differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

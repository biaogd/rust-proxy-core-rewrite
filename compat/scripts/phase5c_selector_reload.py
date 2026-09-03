#!/usr/bin/env python3
"""Go/Rust differential for selector state across SIGHUP generations."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reload_via_controller, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_selector import route
from phase5d_proxies import request
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-selector-reload-diff.json"


def write_config(
    path: Path,
    mixed_port: int,
    controller_port: int,
    upstream_port: int,
    members: list[str],
    default: str,
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-http
    type: http
    server: 127.0.0.1
    port: {upstream_port}
    username: proxy-user
    password: proxy-pass
proxy-groups:
  - name: route-group
    type: select
    proxies: {json.dumps(members)}
    default-selected: {default}
rules:
  - MATCH,route-group
"""
    )


def group(port: int) -> dict[str, Any]:
    status, body = request(port, "GET", "/group/route-group")
    if status != 200:
        raise AssertionError((status, body))
    return json.loads(body)


def wait_group(port: int, members: list[str], selected: str) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    snapshot: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        try:
            snapshot = group(port)
            if snapshot["all"] == members and snapshot["now"] == selected:
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError(f"selector did not become {members}/{selected}: {snapshot}")


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    upstream = ConnectProxyServer()
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    write_config(
        config,
        mixed_port,
        controller_port,
        upstream.port,
        ["REJECT", "local-http"],
        "REJECT",
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        selected = request(
            controller_port,
            "PUT",
            "/proxies/route-group",
            {"name": "local-http"},
        )
        if selected[0] != 204:
            raise AssertionError(selected)
        if route(mixed_port, echo.port) != "proxy":
            raise AssertionError("selected HTTP member was not ready")

        write_config(
            config,
            mixed_port,
            controller_port,
            upstream.port,
            ["DIRECT", "local-http", "REJECT"],
            "REJECT",
        )
        reload_via_controller(process, controller_port, config)
        wait_group(
            controller_port,
            ["DIRECT", "local-http", "REJECT"],
            "local-http",
        )
        retained_route = route(mixed_port, echo.port)

        config.write_text("mixed-port: [")
        reload_via_controller(process, controller_port, config, expected_status=400)
        time.sleep(0.1)
        invalid_snapshot = group(controller_port)

        write_config(
            config,
            mixed_port,
            controller_port,
            upstream.port,
            ["DIRECT", "REJECT"],
            "REJECT",
        )
        reload_via_controller(process, controller_port, config)
        wait_group(controller_port, ["DIRECT", "REJECT"], "DIRECT")
        return {
            "valid-retained": retained_route,
            "invalid-members": invalid_snapshot["all"],
            "invalid-selection": invalid_snapshot["now"],
            "removed-fallback": route(mixed_port, echo.port),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        upstream.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-selector-reload-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CSELECTORRELOAD_CARGO_TARGET",
            "phase5c-selector-reload",
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
    print("Phase 5C selector reload differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

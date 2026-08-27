#!/usr/bin/env python3
"""Go/Rust differential for a configured selector driving HTTP TCP routing."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, ROOT, recv_exact, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files
from phase5d_proxies import normalize, request
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-selector-diff.json"


def json_response(result: tuple[int, bytes]) -> tuple[int, Any]:
    status, body = result
    return status, normalize(json.loads(body))


def route(mixed_port: int, echo_port: int) -> str:
    with connect_domain(mixed_port, "localhost", echo_port) as stream:
        try:
            stream.sendall(b"selector-route")
            return "proxy" if recv_exact(stream, 14) == b"selector-route" else "unexpected"
        except (BrokenPipeError, ConnectionResetError, EOFError):
            return "reject"


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    upstream = ConnectProxyServer()
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-http
    type: http
    server: 127.0.0.1
    port: {upstream.port}
    username: proxy-user
    password: proxy-pass
proxy-groups:
  - name: route-group
    type: select
    proxies: [REJECT, local-http]
    default-selected: REJECT
rules:
  - MATCH,route-group
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        initial_route = route(mixed_port, echo.port)
        initial_group = json_response(
            request(controller_port, "GET", "/proxies/route-group")
        )
        adapter = json_response(
            request(controller_port, "GET", "/proxies/local-http")
        )
        provider = json_response(
            request(controller_port, "GET", "/providers/proxies/default")
        )
        provider_member = json_response(
            request(
                controller_port,
                "GET",
                "/providers/proxies/default/local-http",
            )
        )
        selected = request(
            controller_port,
            "PUT",
            "/proxies/route-group",
            {"name": "local-http"},
        )
        proxied_route = route(mixed_port, echo.port)
        selected_group = json_response(
            request(controller_port, "GET", "/group/route-group")
        )
        invalid = json_response(
            request(
                controller_port,
                "PUT",
                "/proxies/route-group",
                {"name": "missing"},
            )
        )
        reset = request(
            controller_port,
            "PUT",
            "/proxies/route-group",
            {"name": "REJECT"},
        )
        return {
            "initial-route": initial_route,
            "initial-group": initial_group,
            "adapter": adapter,
            "provider": provider,
            "provider-member": provider_member,
            "select-status": (selected[0], selected[1] == b""),
            "proxied-route": proxied_route,
            "selected-group": selected_group,
            "invalid-select": invalid,
            "reset-status": (reset[0], reset[1] == b""),
            "reset-route": route(mixed_port, echo.port),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        upstream.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-selector-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(root, "PHASE5CSELECTOR_CARGO_TARGET", "phase5c-selector")
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
    print("Phase 5C selector and configured HTTP route differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

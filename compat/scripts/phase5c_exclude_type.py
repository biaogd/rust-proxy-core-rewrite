#!/usr/bin/env python3
"""Go/Rust differential for select-group exclude-type composition."""

from __future__ import annotations

import json
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
from phase6b_socks5 import Socks5Server


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-exclude-type-diff.json"


def group_summary(controller_port: int, name: str) -> dict[str, Any]:
    status, body = request(controller_port, "GET", f"/group/{name}")
    if status != 200:
        raise AssertionError((status, body))
    value = json.loads(body)
    return {key: value[key] for key in ("all", "now", "udp", "emptyFallback")}


def compatible_members(controller_port: int, name: str) -> list[tuple[str, str]]:
    status, body = request(controller_port, "GET", f"/providers/proxies/{name}")
    if status != 200:
        raise AssertionError((status, body))
    return [(proxy["name"], proxy["type"]) for proxy in json.loads(body)["proxies"]]


def select(controller_port: int, name: str) -> tuple[int, bool]:
    status, body = request(
        controller_port,
        "PUT",
        "/proxies/typed-group",
        {"name": name},
    )
    return status, body == b""


def wait_proxy_route(process, mixed_port: int, echo_port: int) -> None:
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
    raise TimeoutError("exclude-type SOCKS5 route did not become ready")


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    http = ConnectProxyServer()
    socks = Socks5Server()
    mixed_port, controller_port = reserve_port(), reserve_port()
    provider_file = scratch / ".config" / "mihomo" / "provider.yaml"
    provider_file.parent.mkdir(parents=True)
    provider_file.write_text(
        f"""proxies:
  - name: provider-http
    type: http
    server: 127.0.0.1
    port: {http.port}
    username: proxy-user
    password: proxy-pass
"""
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: top-http
    type: http
    server: 127.0.0.1
    port: {http.port}
    username: proxy-user
    password: proxy-pass
  - name: top-socks
    type: socks5
    server: 127.0.0.1
    port: {socks.port}
    username: proxy-user
    password: proxy-pass
proxy-providers:
  local-file:
    type: file
    path: {provider_file}
proxy-groups:
  - name: typed-group
    type: select
    proxies: [REJECT, DIRECT, top-http, top-socks, inner]
    use: [local-file]
    exclude-type: 'rEjEcT|hTtP|sElEcToR'
    empty-fallback: REJECT
    default-selected: top-socks
  - name: empty-types
    type: select
    proxies: [REJECT, top-http, inner]
    use: [local-file]
    exclude-type: 'Reject|Http|Selector'
    empty-fallback: DIRECT
    default-selected: DIRECT
  - name: inner
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,typed-group
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_provider(controller_port)
        wait_proxy_route(process, mixed_port, echo.port)
        initial = {
            "typed": group_summary(controller_port, "typed-group"),
            "empty": group_summary(controller_port, "empty-types"),
            "compatible": compatible_members(controller_port, "typed-group"),
            "route": route(mixed_port, echo.port),
        }

        direct_select = select(controller_port, "DIRECT")
        socks.observations.clear()
        direct_route = route(mixed_port, echo.port)
        direct_used_socks = bool(socks.observations)

        socks_select = select(controller_port, "top-socks")
        socks.observations.clear()
        socks_route = route(mixed_port, echo.port)
        socks_used = bool(socks.observations)
        return {
            "initial": initial,
            "direct-select": direct_select,
            "direct-route": direct_route,
            "direct-used-socks": direct_used_socks,
            "socks-select": socks_select,
            "socks-route": socks_route,
            "socks-used": socks_used,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        http.close()
        socks.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-exclude-type-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CEXCLUDETYPE_CARGO_TARGET",
            "phase5c-exclude-type",
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
    print("Phase 5C exclude-type differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

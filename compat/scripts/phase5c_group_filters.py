#!/usr/bin/env python3
"""Go/Rust differential for select-group filters and include-all composition."""

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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-group-filters-diff.json"


def group_summary(controller_port: int, name: str) -> dict[str, Any]:
    status, body = request(controller_port, "GET", f"/group/{name}")
    if status != 200:
        raise AssertionError((status, body))
    value = json.loads(body)
    return {
        "all": value["all"],
        "now": value["now"],
        "emptyFallback": value["emptyFallback"],
        "udp": value["udp"],
    }


def select(controller_port: int, group: str, name: str) -> tuple[int, bool]:
    status, body = request(
        controller_port,
        "PUT",
        f"/proxies/{group}",
        {"name": name},
    )
    return status, body == b""


def wait_filtered_route(process, mixed_port: int, echo_port: int) -> None:
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
    raise TimeoutError("filtered provider route did not become ready")


def proxy_yaml(name: str, port: int) -> str:
    return f"""  - name: {name}
    type: http
    server: 127.0.0.1
    port: {port}
    username: proxy-user
    password: proxy-pass
"""


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    upstream = ConnectProxyServer()
    mixed_port, controller_port = reserve_port(), reserve_port()
    provider_file = scratch / ".config" / "mihomo" / "provider.yaml"
    provider_file.parent.mkdir(parents=True)
    provider_file.write_text(
        "proxies:\n"
        + proxy_yaml("provider-alpha", upstream.port)
        + proxy_yaml("provider-beta", upstream.port)
        + proxy_yaml("provider-omit", upstream.port)
    )
    top_level = (
        proxy_yaml("top-beta", upstream.port)
        + proxy_yaml("top-omit", upstream.port)
        + proxy_yaml("top-alpha", upstream.port)
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxies:
{top_level}proxy-providers:
  local-file:
    type: file
    path: {provider_file}
proxy-groups:
  - name: filtered-group
    type: select
    proxies: [REJECT]
    use: [local-file]
    filter: 'provider-beta`provider-alpha'
    exclude-filter: omit
    empty-fallback: DIRECT
    default-selected: provider-beta
  - name: all-proxies
    type: select
    include-all-proxies: true
    filter: '^top-'
    exclude-filter: omit
    default-selected: top-alpha
  - name: all-providers
    type: select
    include-all-providers: true
    filter: '^provider-alpha$'
    empty-fallback: REJECT
    default-selected: provider-alpha
  - name: all-combined
    type: select
    include-all: true
    filter: '(alpha|beta)$'
    exclude-filter: omit
    default-selected: top-alpha
  - name: empty-provider
    type: select
    use: [local-file]
    filter: '^missing$'
    empty-fallback: REJECT
    default-selected: REJECT
rules:
  - MATCH,filtered-group
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_provider(controller_port)
        wait_filtered_route(process, mixed_port, echo.port)
        initial_route = route(mixed_port, echo.port)
        rejected = select(controller_port, "filtered-group", "REJECT")
        rejected_route = route(mixed_port, echo.port)
        selected = select(controller_port, "filtered-group", "provider-alpha")
        selected_route = route(mixed_port, echo.port)
        return {
            "filtered": group_summary(controller_port, "filtered-group"),
            "all-proxies": group_summary(controller_port, "all-proxies"),
            "all-providers": group_summary(controller_port, "all-providers"),
            "all-combined": group_summary(controller_port, "all-combined"),
            "empty-provider": group_summary(controller_port, "empty-provider"),
            "initial-route": initial_route,
            "reject-select": rejected,
            "rejected-route": rejected_route,
            "provider-select": selected,
            "selected-route": selected_route,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        upstream.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-group-filters-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CGROUPFILTERS_CARGO_TARGET",
            "phase5c-group-filters",
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
    print("Phase 5C group filter/include-all differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for default HTTP-provider cache and restart reuse."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_http_provider import ProviderServer
from phase5c_http_provider_refresh import provider_names, select, wait_names
from phase5c_selector import route
from phase5d_proxies import request
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-http-provider-cache-diff.json"


def provider_payload(name: str, port: int) -> bytes:
    return f"""proxies:
  - name: {name}
    type: http
    server: 127.0.0.1
    port: {port}
    username: proxy-user
    password: proxy-pass
""".encode()


def write_config(
    path: Path,
    mixed_port: int,
    controller_port: int,
    provider_port: int,
) -> str:
    url = f"http://127.0.0.1:{provider_port}/provider.yaml?phase=5c2f"
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxy-providers:
  remote-http:
    type: http
    url: {url}
    interval: 600
proxy-groups:
  - name: provider-group
    type: select
    proxies: [REJECT]
    use: [remote-http]
rules:
  - DST-PORT,{provider_port},DIRECT
  - MATCH,provider-group
"""
    )
    return url


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    first, second = ConnectProxyServer(), ConnectProxyServer()
    first_payload = provider_payload("provider-one", first.port)
    second_payload = provider_payload("provider-two", second.port)
    provider = ProviderServer(first_payload)
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    url = write_config(config, mixed_port, controller_port, provider.port)
    cache = (
        scratch
        / ".config"
        / "mihomo"
        / "proxies"
        / hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()
    )

    first_process, first_stdout, first_stderr = launch(binary, config, scratch)
    try:
        wait_ready(first_process, mixed_port)
        wait_controller(first_process, controller_port)
        wait_names(first_process, controller_port, ["provider-one"])
        first_selected = select(controller_port, "provider-one")
        first_route = route(mixed_port, echo.port)
        initial_requests = len(provider.observations)
        initial_cache = cache.read_bytes() == first_payload
    finally:
        stop(first_process)
        first_stdout.close()
        first_stderr.close()

    provider.respond(b"remote unavailable", 500)
    second_process, second_stdout, second_stderr = launch(binary, config, scratch)
    try:
        wait_ready(second_process, mixed_port)
        wait_controller(second_process, controller_port)
        wait_names(second_process, controller_port, ["provider-one"])
        restart_requests = len(provider.observations)
        restart_selected = select(controller_port, "provider-one")
        restart_route = route(mixed_port, echo.port)

        provider.respond(second_payload)
        refreshed = request(controller_port, "PUT", "/providers/proxies/remote-http")
        wait_names(second_process, controller_port, ["provider-two"])
        replacement_selected = select(controller_port, "provider-two")
        replacement_route = route(mixed_port, echo.port)

        provider.respond(b"proxies: [")
        failed = request(controller_port, "PUT", "/providers/proxies/remote-http")
        failed_json = json.loads(failed[1])
        return {
            "default-cache-path": cache.parent.name == "proxies" and len(cache.name) == 32,
            "initial-cache": initial_cache,
            "initial-selected": first_selected,
            "initial-route": first_route,
            "restart-used-cache": restart_requests == initial_requests,
            "restart-selected": restart_selected,
            "restart-route": restart_route,
            "refresh": (refreshed[0], refreshed[1] == b""),
            "replacement-cache": cache.read_bytes() == second_payload,
            "replacement-selected": replacement_selected,
            "replacement-route": replacement_route,
            "used-second": bool(second.observations),
            "failed-refresh": {
                "status": failed[0],
                "message-is-string": isinstance(failed_json.get("message"), str),
            },
            "rollback": (
                provider_names(controller_port) == ["provider-two"]
                and cache.read_bytes() == second_payload
                and route(mixed_port, echo.port) == "proxy"
            ),
        }
    finally:
        stop(second_process)
        second_stdout.close()
        second_stderr.close()
        provider.close()
        first.close()
        second.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-http-provider-cache-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CHTTPPROVIDERCACHE_CARGO_TARGET",
            "phase5c-http-provider-cache",
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
    print("Phase 5C HTTP-provider cache/restart differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for HTTP proxy-provider refresh and rollback."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_http_provider import ProviderServer
from phase5c_selector import route
from phase5d_proxies import request
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-http-provider-refresh-diff.json"


def provider_payload(name: str, port: int) -> bytes:
    return f"""proxies:
  - name: {name}
    type: http
    server: 127.0.0.1
    port: {port}
    username: proxy-user
    password: proxy-pass
""".encode()


def provider_names(controller_port: int) -> list[str]:
    status, body = request(controller_port, "GET", "/providers/proxies/remote-http")
    if status != 200:
        raise AssertionError((status, body))
    return [proxy["name"] for proxy in json.loads(body)["proxies"]]


def wait_names(process: Any, controller_port: int, expected: list[str]) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during provider refresh: {process.returncode}")
        try:
            if provider_names(controller_port) == expected:
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError(f"HTTP provider members did not become {expected}")


def select(controller_port: int, name: str) -> tuple[int, bool]:
    status, body = request(
        controller_port,
        "PUT",
        "/proxies/provider-group",
        {"name": name},
    )
    return status, body == b""


def write_config(
    path: Path,
    mixed_port: int,
    controller_port: int,
    provider_port: int,
    cache: Path,
    interval: int,
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxy-providers:
  remote-http:
    type: http
    url: http://127.0.0.1:{provider_port}/provider.yaml?phase=5c2d
    path: {cache}
    interval: {interval}
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


def manual_refresh(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    first, second = ConnectProxyServer(), ConnectProxyServer()
    first_payload = provider_payload("provider-one", first.port)
    second_payload = provider_payload("provider-two", second.port)
    provider = ProviderServer(first_payload)
    mixed_port, controller_port = reserve_port(), reserve_port()
    cache = scratch / ".config" / "mihomo" / "providers" / "remote.yaml"
    config = scratch / "manual.yaml"
    write_config(config, mixed_port, controller_port, provider.port, cache, 600)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_names(process, controller_port, ["provider-one"])
        initial_select = select(controller_port, "provider-one")
        initial_route = route(mixed_port, echo.port)

        provider.respond(second_payload)
        refreshed = request(controller_port, "PUT", "/providers/proxies/remote-http")
        wait_names(process, controller_port, ["provider-two"])
        old_member = request(
            controller_port,
            "GET",
            "/providers/proxies/remote-http/provider-one",
        )
        second_select = select(controller_port, "provider-two")
        second_route = route(mixed_port, echo.port)

        provider.respond(b"proxies: [")
        malformed = request(controller_port, "PUT", "/providers/proxies/remote-http")
        malformed_json = json.loads(malformed[1])
        malformed_retained = (
            provider_names(controller_port) == ["provider-two"]
            and cache.read_bytes() == second_payload
        )

        provider.respond(b"remote unavailable", 500)
        unavailable = request(controller_port, "PUT", "/providers/proxies/remote-http")
        unavailable_json = json.loads(unavailable[1])
        retained_names = provider_names(controller_port)
        retained_route = route(mixed_port, echo.port)
        return {
            "initial-select": initial_select,
            "initial-route": initial_route,
            "initial-used-first": bool(first.observations),
            "refresh": (refreshed[0], refreshed[1] == b""),
            "cache-updated": cache.read_bytes() == second_payload,
            "old-member-status": old_member[0],
            "second-select": second_select,
            "second-route": second_route,
            "second-used-second": bool(second.observations),
            "malformed-refresh": {
                "status": malformed[0],
                "message-is-string": isinstance(malformed_json.get("message"), str),
                "retained": malformed_retained,
            },
            "unavailable-refresh": {
                "status": unavailable[0],
                "message-is-string": isinstance(unavailable_json.get("message"), str),
            },
            "retained-names": retained_names,
            "retained-cache": cache.read_bytes() == second_payload,
            "retained-route": retained_route,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        provider.close()
        first.close()
        second.close()
        echo.close()


def scheduled_refresh(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    first, second = ConnectProxyServer(), ConnectProxyServer()
    first_payload = provider_payload("provider-one", first.port)
    second_payload = provider_payload("provider-two", second.port)
    provider = ProviderServer(first_payload)
    mixed_port, controller_port = reserve_port(), reserve_port()
    cache = scratch / ".config" / "mihomo" / "providers" / "scheduled.yaml"
    config = scratch / "scheduled.yaml"
    write_config(config, mixed_port, controller_port, provider.port, cache, 1)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_names(process, controller_port, ["provider-one"])
        provider.respond(second_payload)
        wait_names(process, controller_port, ["provider-two"])
        selected = select(controller_port, "provider-two")
        routed = route(mixed_port, echo.port)
        return {
            "scheduled-refresh": True,
            "cache-updated": cache.read_bytes() == second_payload,
            "selected": selected,
            "route": routed,
            "used-second": bool(second.observations),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        provider.close()
        first.close()
        second.close()
        echo.close()


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    manual = scratch / "manual"
    scheduled = scratch / "scheduled"
    manual.mkdir()
    scheduled.mkdir()
    return {
        "manual": manual_refresh(binary, manual),
        "scheduled": scheduled_refresh(binary, scheduled),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-http-provider-refresh-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CHTTPPROVIDERREFRESH_CARGO_TARGET",
            "phase5c-http-provider-refresh",
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
    print("Phase 5C HTTP-provider refresh/rollback differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

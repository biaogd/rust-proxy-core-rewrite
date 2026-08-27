#!/usr/bin/env python3
"""Go/Rust differential for fallback fixed selection and persistence."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_selector import route
from phase5d_proxies import request, start_health_server
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-fallback-control-diff.json"


def write_config(
    path: Path,
    mixed_port: int,
    controller_port: int,
    upstream_port: int,
    health_url: str,
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
profile:
  store-selected: true
proxies:
  - name: local-http
    type: http
    server: 127.0.0.1
    port: {upstream_port}
    username: proxy-user
    password: proxy-pass
proxy-groups:
  - name: recovery
    type: fallback
    proxies: [local-http, DIRECT]
    url: {health_url}
    expected-status: '204'
rules:
  - MATCH,recovery
"""
    )


def group(controller_port: int) -> dict[str, str]:
    status, body = request(controller_port, "GET", "/group/recovery")
    if status != 200:
        raise AssertionError((status, body))
    value = json.loads(body)
    return {"now": value["now"], "fixed": value["fixed"]}


def wait_group(controller_port: int, now: str, fixed: str) -> dict[str, str]:
    deadline = time.monotonic() + IO_DEADLINE
    current: dict[str, str] | None = None
    while time.monotonic() < deadline:
        try:
            current = group(controller_port)
            if current == {"now": now, "fixed": fixed}:
                return current
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError(f"fallback did not become {now}/{fixed}: {current}")


def select(controller_port: int, member: str) -> tuple[int, bool]:
    status, body = request(
        controller_port,
        "PUT",
        "/proxies/recovery",
        {"name": member},
    )
    return status, body == b""


def route_kind(mixed_port: int, echo_port: int, upstream: ConnectProxyServer) -> str:
    upstream.observations.clear()
    if route(mixed_port, echo_port) != "proxy":
        return "failed"
    return "proxy" if upstream.observations else "direct"


def start_product(
    binary: Path,
    scratch: Path,
    config: Path,
    mixed_port: int,
    controller_port: int,
):
    process, stdout, stderr = launch(binary, config, scratch)
    wait_ready(process, mixed_port)
    wait_controller(process, controller_port)
    return process, stdout, stderr


def close_product(product) -> None:
    process, stdout, stderr = product
    stop(process)
    stdout.close()
    stderr.close()


def exercise(
    binary: Path,
    scratch: Path,
    upstream: ConnectProxyServer,
    health_url: str,
    echo_port: int,
) -> dict[str, Any]:
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    write_config(config, mixed_port, controller_port, upstream.port, health_url)
    product = start_product(binary, scratch, config, mixed_port, controller_port)
    try:
        initial = wait_group(controller_port, "local-http", "")
        direct_put = select(controller_port, "DIRECT")
        direct = wait_group(controller_port, "DIRECT", "DIRECT")
        direct_route = route_kind(mixed_port, echo_port, upstream)
        proxy_put = select(controller_port, "local-http")
        proxy = wait_group(controller_port, "local-http", "local-http")
        proxy_route = route_kind(mixed_port, echo_port, upstream)
        invalid = select(controller_port, "missing")
        after_invalid = group(controller_port)
    finally:
        close_product(product)

    restarted_product = start_product(
        binary,
        scratch,
        config,
        mixed_port,
        controller_port,
    )
    try:
        restarted = wait_group(controller_port, "local-http", "local-http")
        restarted_route = route_kind(mixed_port, echo_port, upstream)
    finally:
        close_product(restarted_product)
    return {
        "initial": initial,
        "direct-put": direct_put,
        "direct": direct,
        "direct-route": direct_route,
        "proxy-put": proxy_put,
        "proxy": proxy,
        "proxy-route": proxy_route,
        "invalid": invalid,
        "after-invalid": after_invalid,
        "restarted": restarted,
        "restarted-route": restarted_route,
    }


def interchange(
    binaries: dict[str, Path],
    scratch: Path,
    upstream: ConnectProxyServer,
    health_url: str,
) -> dict[str, Any]:
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    write_config(config, mixed_port, controller_port, upstream.port, health_url)
    observations: dict[str, Any] = {}
    for implementation, expected, chosen in (
        ("go", "", "DIRECT"),
        ("rust", "DIRECT", "local-http"),
        ("go", "local-http", None),
    ):
        product = start_product(
            binaries[implementation],
            scratch,
            config,
            mixed_port,
            controller_port,
        )
        try:
            current = wait_group(
                controller_port,
                expected or "local-http",
                expected,
            )
            mutation = None if chosen is None else select(controller_port, chosen)
            if chosen is not None:
                wait_group(controller_port, chosen, chosen)
            observations[f"{implementation}-{len(observations)}"] = {
                "loaded": current,
                "mutation": mutation,
            }
        finally:
            close_product(product)
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-fallback-control-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CFALLBACKCONTROL_CARGO_TARGET",
            "phase5c-fallback-control",
        )
        echo = start_server(EchoHandler)
        upstream = ConnectProxyServer()
        health = start_health_server()
        health_url = f"http://127.0.0.1:{health.server_port}/generate_204"
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(
                    binary,
                    scratch,
                    upstream,
                    health_url,
                    echo.port,
                )
            shared = root / "interchange"
            shared.mkdir()
            observations["interchange"] = interchange(
                binaries,
                shared,
                upstream,
                health_url,
            )
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
        finally:
            health.shutdown()
            health.server_close()
            upstream.close()
            echo.close()
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5C fallback control/persistence differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

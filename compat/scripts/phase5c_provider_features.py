#!/usr/bin/env python3
"""Go/Rust differential for inline provider transforms and provider health."""

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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-provider-features-diff.json"
MEMBER = "pre-renamed-http-suffix"


def provider_state(controller: int, health_url: str) -> dict[str, Any]:
    status, body = request(controller, "GET", "/providers/proxies/inline-set")
    if status != 200:
        raise AssertionError((status, body))
    value = json.loads(body)
    proxies = value["proxies"]
    return {
        "status": status,
        "name": value["name"],
        "vehicle": value["vehicleType"],
        "test-url": "health-url" if value["testUrl"] == health_url else value["testUrl"],
        "expected": value["expectedStatus"],
        "members": [proxy["name"] for proxy in proxies],
        "alive": [proxy["alive"] for proxy in proxies],
        "history": [bool(proxy["history"]) for proxy in proxies],
        "health-url": [health_url in proxy["extra"] for proxy in proxies],
    }


def wait_health(
    process: Any,
    controller: int,
    health_url: str,
    alive: bool,
) -> dict[str, Any]:
    deadline = time.monotonic() + IO_DEADLINE
    current: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during provider health: {process.returncode}")
        try:
            current = provider_state(controller, health_url)
            if current["alive"] == [alive] and current["history"] == [True]:
                return current
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError(f"provider health did not become {alive}: {current}")


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    health = start_health_server()
    upstream = ConnectProxyServer()
    mixed, controller = reserve_port(), reserve_port()
    health_url = f"http://127.0.0.1:{health.server_port}/generate_204"
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
mode: rule
log-level: info
ipv6: false
proxy-providers:
  inline-set:
    type: inline
    filter: 'keep|drop|socks'
    exclude-filter: drop
    exclude-type: socks5
    override:
      proxy-name:
        - pattern: '^keep-'
          target: 'renamed-'
      additional-prefix: 'pre-'
      additional-suffix: '-suffix'
    health-check:
      enable: true
      url: {health_url}
      expected-status: '204'
      interval: 1
      timeout: 1000
      lazy: false
    payload:
      - name: keep-http
        type: http
        server: 127.0.0.1
        port: {upstream.port}
        username: proxy-user
        password: proxy-pass
      - name: drop-http
        type: http
        server: 127.0.0.1
        port: {upstream.port}
        username: proxy-user
        password: proxy-pass
      - name: keep-socks
        type: socks5
        server: 127.0.0.1
        port: {upstream.port}
        username: proxy-user
        password: proxy-pass
proxy-groups:
  - name: inline-group
    type: select
    use: [inline-set]
    default-selected: {MEMBER}
rules:
  - MATCH,inline-group
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed)
        wait_controller(process, controller)
        healthy = wait_health(process, controller, health_url, True)
        routed = route(mixed, echo.port)
        manual = request(
            controller,
            "GET",
            "/providers/proxies/inline-set/healthcheck",
        )
        upstream.close()
        failed = wait_health(process, controller, health_url, False)
        missing = request(
            controller,
            "GET",
            "/providers/proxies/missing/healthcheck",
        )
        return {
            "healthy": healthy,
            "route": routed,
            "manual": (manual[0], manual[1] == b""),
            "failed": failed,
            "missing": (missing[0], isinstance(json.loads(missing[1]).get("message"), str)),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        if upstream.socket.fileno() != -1:
            upstream.close()
        health.shutdown()
        health.server_close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-provider-features-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CPROVIDERFEATURES_CARGO_TARGET",
            "phase5c-provider-features",
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
    print("Phase 5C inline provider transform/health differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

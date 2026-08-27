#!/usr/bin/env python3
"""Go/Rust differential for concurrent provider updates and removal cleanup."""

from __future__ import annotations

import concurrent.futures
import json
import os
import signal
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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-provider-concurrency-diff.json"


def payload(name: str, port: int) -> bytes:
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
    mixed: int,
    controller: int,
    provider_port: int,
    cache: Path,
) -> None:
    path.write_text(
        f"""mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
mode: rule
log-level: info
ipv6: false
proxy-providers:
  concurrent:
    type: http
    url: http://127.0.0.1:{provider_port}/provider.yaml
    path: {cache}
    interval: 600
proxy-groups:
  - name: concurrent-group
    type: select
    proxies: [REJECT]
    use: [concurrent]
rules:
  - DST-PORT,{provider_port},DIRECT
  - MATCH,concurrent-group
"""
    )


def burst(controller: int, count: int = 8) -> list[tuple[int, bool]]:
    def update(_index: int) -> tuple[int, bool]:
        status, body = request(controller, "PUT", "/providers/proxies/concurrent")
        return status, isinstance(json.loads(body).get("message"), str) if body else True

    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
        return sorted(executor.map(update, range(count)))


def provider_names(controller: int) -> list[str]:
    status, body = request(controller, "GET", "/providers/proxies/concurrent")
    if status != 200:
        raise AssertionError((status, body))
    return [proxy["name"] for proxy in json.loads(body)["proxies"]]


def wait_names(process: Any, controller: int, expected: list[str]) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during provider update: {process.returncode}")
        try:
            if provider_names(controller) == expected:
                return
        except (AssertionError, OSError):
            pass
        time.sleep(0.02)
    raise TimeoutError(f"provider members did not become {expected}")


def wait_removed(process: Any, controller: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited while removing provider: {process.returncode}")
        try:
            if request(controller, "GET", "/providers/proxies/concurrent")[0] == 404:
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError("removed provider remained visible")


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    first, second = ConnectProxyServer(), ConnectProxyServer()
    provider = ProviderServer(payload("provider-one", first.port))
    mixed, controller = reserve_port(), reserve_port()
    cache = scratch / ".config" / "mihomo" / "providers" / "concurrent.yaml"
    config = scratch / "config.yaml"
    write_config(config, mixed, controller, provider.port, cache)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed)
        wait_controller(process, controller)
        wait_names(process, controller, ["provider-one"])

        provider.respond(payload("provider-two", second.port))
        valid = burst(controller)
        wait_names(process, controller, ["provider-two"])
        valid_cache = cache.read_bytes() == payload("provider-two", second.port)

        provider.respond(b"proxies: [")
        invalid = burst(controller)
        retained = provider_names(controller)
        retained_cache = cache.read_bytes() == payload("provider-two", second.port)

        config.write_text(
            f"""mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
        )
        os.kill(process.pid, signal.SIGHUP)
        wait_removed(process, controller)
        return {
            "valid": valid,
            "valid-members": ["provider-two"],
            "valid-cache": valid_cache,
            "invalid": invalid,
            "retained-members": retained,
            "retained-cache": retained_cache,
            "removed-detail": request(controller, "GET", "/providers/proxies/concurrent")[0],
            "removed-update": request(controller, "PUT", "/providers/proxies/concurrent")[0],
            "post-removal-route": route(mixed, echo.port),
            "alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        provider.close()
        first.close()
        second.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-provider-concurrency-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CPROVIDERCONCURRENCY_CARGO_TARGET",
            "phase5c-provider-concurrency",
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
    print("Phase 5C provider concurrency/cleanup differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

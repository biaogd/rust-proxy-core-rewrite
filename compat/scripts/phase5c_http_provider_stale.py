#!/usr/bin/env python3
"""Go/Rust differential for stale and corrupt HTTP-provider caches."""

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
from phase5c_http_provider import ProviderServer
from phase5c_http_provider_cache import provider_payload
from phase5c_http_provider_refresh import provider_names, select, wait_names
from phase5c_selector import route
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-http-provider-stale-diff.json"


def write_config(path: Path, mixed: int, controller: int, provider: int) -> None:
    path.write_text(
        f"""mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
mode: rule
log-level: info
ipv6: false
proxy-providers:
  remote-http:
    type: http
    url: http://127.0.0.1:{provider}/provider.yaml?phase=5c2g
    path: providers/cache.yaml
    interval: 600
proxy-groups:
  - name: provider-group
    type: select
    proxies: [REJECT]
    use: [remote-http]
rules:
  - DST-PORT,{provider},DIRECT
  - MATCH,provider-group
"""
    )


def age_cache(cache: Path, payload: bytes) -> int:
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(payload)
    stale = int(time.time()) - 700
    os.utime(cache, (stale, stale))
    return stale


def wait_request(process: Any, provider: ProviderServer) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during provider refresh: {process.returncode}")
        if provider.observations:
            return
        time.sleep(0.02)
    raise TimeoutError("stale provider cache did not trigger a request")


def scenario(binary: Path, scratch: Path, kind: str) -> dict[str, Any]:
    scratch.mkdir()
    echo = start_server(EchoHandler)
    cached, remote = ConnectProxyServer(), ConnectProxyServer()
    cached_payload = provider_payload("provider-cached", cached.port)
    remote_payload = provider_payload("provider-remote", remote.port)
    provider = ProviderServer(remote_payload)
    if kind == "stale-failure":
        provider.respond(b"remote unavailable", 500)
    mixed, controller = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    write_config(config, mixed, controller, provider.port)
    cache = scratch / ".config" / "mihomo" / "providers" / "cache.yaml"
    stale = age_cache(cache, b"proxies: [" if kind == "corrupt" else cached_payload)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed)
        wait_controller(process, controller)
        wait_request(process, provider)
        expected = ["provider-cached"] if kind == "stale-failure" else ["provider-remote"]
        wait_names(process, controller, expected)
        selected = select(controller, expected[0])
        routed = route(mixed, echo.port)
        expected_cache = cached_payload if kind == "stale-failure" else remote_payload
        return {
            "request-observed": bool(provider.observations),
            "members": provider_names(controller),
            "cache-valid": cache.read_bytes() == expected_cache,
            "cache-mtime-advanced": int(cache.stat().st_mtime) > stale,
            "selected": selected,
            "route": routed,
            "cached-proxy-used": bool(cached.observations),
            "remote-proxy-used": bool(remote.observations),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        provider.close()
        cached.close()
        remote.close()
        echo.close()


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    return {
        kind: scenario(binary, scratch / kind, kind)
        for kind in ("stale-success", "stale-failure", "corrupt")
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-http-provider-stale-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CHTTPPROVIDERSTALE_CARGO_TARGET",
            "phase5c-http-provider-stale",
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
    print("Phase 5C HTTP-provider stale/corrupt-cache differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

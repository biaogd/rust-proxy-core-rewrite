#!/usr/bin/env python3
"""Go/Rust differential for HTTP-provider interval reload scheduling."""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reload_via_controller, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_http_provider import ProviderServer
from phase5c_http_provider_cache import provider_payload
from phase5c_http_provider_refresh import provider_names, select, wait_names
from phase5c_selector import route
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-http-provider-reload-diff.json"


def write_config(
    path: Path,
    mixed: int,
    controller: int,
    provider: int,
    interval: int,
    cache_name: str = "reload.yaml",
) -> None:
    path.write_text(
        f"""mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
mode: rule
log-level: info
ipv6: false
proxy-providers:
  remote-http:
    type: http
    url: http://127.0.0.1:{provider}/provider.yaml?phase=5c2h
    path: providers/{cache_name}
    interval: {interval}
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


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    first, second, third = ConnectProxyServer(), ConnectProxyServer(), ConnectProxyServer()
    first_payload = provider_payload("provider-one", first.port)
    second_payload = provider_payload("provider-two", second.port)
    third_payload = provider_payload("provider-three", third.port)
    provider, replacement = ProviderServer(second_payload), ProviderServer(third_payload)
    mixed, controller = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    write_config(config, mixed, controller, provider.port, 600)
    cache = scratch / ".config" / "mihomo" / "providers" / "reload.yaml"
    cache.parent.mkdir(parents=True)
    cache.write_bytes(first_payload)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed)
        wait_controller(process, controller)
        wait_names(process, controller, ["provider-one"])
        time.sleep(0.1)
        before_reload = len(provider.observations)

        write_config(config, mixed, controller, provider.port, 1)
        reload_via_controller(process, controller, config)
        wait_names(process, controller, ["provider-two"])
        selected = select(controller, "provider-two")
        routed = route(mixed, echo.port)
        first_cache_updated = cache.read_bytes() == second_payload

        next_cache = cache.with_name("reload-next.yaml")
        next_cache.write_bytes(first_payload)
        stale = int(time.time()) - 700
        os.utime(next_cache, (stale, stale))
        write_config(
            config,
            mixed,
            controller,
            replacement.port,
            600,
            "reload-next.yaml",
        )
        reload_via_controller(process, controller, config)
        wait_names(process, controller, ["provider-three"])
        replacement_selected = select(controller, "provider-three")
        replacement_route = route(mixed, echo.port)
        return {
            "fresh-cache-no-initial-request": before_reload == 0,
            "shortened-interval-refreshed": len(provider.observations) > before_reload,
            "members": provider_names(controller),
            "cache-updated": first_cache_updated,
            "selected": selected,
            "route": routed,
            "used-second": bool(second.observations),
            "changed-source-requested": bool(replacement.observations),
            "changed-source-cache": next_cache.read_bytes() == third_payload,
            "changed-source-mtime": int(next_cache.stat().st_mtime) > stale,
            "changed-source-selected": replacement_selected,
            "changed-source-route": replacement_route,
            "used-third": bool(third.observations),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        provider.close()
        replacement.close()
        first.close()
        second.close()
        third.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-http-provider-reload-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CHTTPPROVIDERRELOAD_CARGO_TARGET",
            "phase5c-http-provider-reload",
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
    print("Phase 5C HTTP-provider reload-scheduler differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for nested select groups and cycle rejection."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_selector import route
from phase5d_proxies import request
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-nested-selector-diff.json"


def group_summary(controller_port: int, name: str) -> dict[str, Any]:
    status, body = request(controller_port, "GET", f"/group/{name}")
    if status != 200:
        raise AssertionError((status, body))
    value = json.loads(body)
    return {key: value[key] for key in ("all", "now", "udp", "emptyFallback")}


def provider_summary(controller_port: int, name: str) -> list[tuple[str, str]]:
    status, body = request(controller_port, "GET", f"/providers/proxies/{name}")
    if status != 200:
        raise AssertionError((status, body))
    return [(proxy["name"], proxy["type"]) for proxy in json.loads(body)["proxies"]]


def select(controller_port: int, group: str, name: str) -> tuple[int, bool]:
    status, body = request(
        controller_port,
        "PUT",
        f"/proxies/{group}",
        {"name": name},
    )
    return status, body == b""


def wait_route(process, mixed_port: int, echo_port: int, expected: str) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during readiness with {process.returncode}")
        try:
            if route(mixed_port, echo_port) == expected:
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError(f"nested route did not become {expected}")


def cycle_exit(binary: Path, scratch: Path) -> int:
    cycle = scratch / "cycle.yaml"
    cycle.write_text(
        """mixed-port: 7890
mode: rule
log-level: info
ipv6: false
proxy-groups:
  - name: cycle-a
    type: select
    proxies: [cycle-b]
  - name: cycle-b
    type: select
    proxies: [cycle-a]
rules:
  - MATCH,cycle-a
"""
    )
    profile = scratch / "cycle-profile"
    result = subprocess.run(
        [str(binary), "-t", "-f", str(cycle)],
        cwd=scratch,
        env={
            **os.environ,
            "HOME": str(profile),
            "XDG_CONFIG_HOME": str(profile / ".config"),
            "CLASH_HOME_DIR": str(profile / ".config" / "mihomo"),
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode


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
  - name: outer
    type: select
    proxies: [inner, DIRECT]
    default-selected: inner
  - name: inner
    type: select
    proxies: [REJECT, local-http]
    default-selected: local-http
rules:
  - MATCH,outer
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_route(process, mixed_port, echo.port, "proxy")
        initial = {
            "outer": group_summary(controller_port, "outer"),
            "inner": group_summary(controller_port, "inner"),
            "outer-provider": provider_summary(controller_port, "outer"),
            "route": route(mixed_port, echo.port),
        }

        inner_reject = select(controller_port, "inner", "REJECT")
        wait_route(process, mixed_port, echo.port, "reject")
        rejected = {
            "select": inner_reject,
            "outer": group_summary(controller_port, "outer"),
            "route": route(mixed_port, echo.port),
        }

        inner_proxy = select(controller_port, "inner", "local-http")
        wait_route(process, mixed_port, echo.port, "proxy")
        outer_direct = select(controller_port, "outer", "DIRECT")
        upstream.observations.clear()
        direct_route = route(mixed_port, echo.port)
        direct_used_proxy = bool(upstream.observations)

        outer_nested = select(controller_port, "outer", "inner")
        upstream.observations.clear()
        nested_route = route(mixed_port, echo.port)
        nested_used_proxy = bool(upstream.observations)
        return {
            "initial": initial,
            "rejected": rejected,
            "inner-proxy-select": inner_proxy,
            "outer-direct-select": outer_direct,
            "direct-route": direct_route,
            "direct-used-proxy": direct_used_proxy,
            "outer-nested-select": outer_nested,
            "nested-route": nested_route,
            "nested-used-proxy": nested_used_proxy,
            "cycle-exit": cycle_exit(binary, scratch),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        upstream.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-nested-selector-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CNESTED_CARGO_TARGET",
            "phase5c-nested-selector",
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
    print("Phase 5C nested selector/cycle differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

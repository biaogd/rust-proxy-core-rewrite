#!/usr/bin/env python3
"""Go/Rust differential and cache interchange for selector persistence."""

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
from phase5d_proxies import request
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-selector-persistence-diff.json"


def write_config(
    path: Path,
    mixed_port: int,
    controller_port: int,
    upstream_port: int,
    store_selected: bool,
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
profile:
  store-selected: {str(store_selected).lower()}
proxies:
  - name: local-http
    type: http
    server: 127.0.0.1
    port: {upstream_port}
    username: proxy-user
    password: proxy-pass
proxy-groups:
  - name: route-group
    type: select
    proxies: [REJECT, local-http]
    default-selected: REJECT
rules:
  - MATCH,route-group
"""
    )


def selected(controller_port: int) -> str:
    status, body = request(controller_port, "GET", "/group/route-group")
    if status != 200:
        raise AssertionError((status, body))
    return json.loads(body)["now"]


def wait_selected(controller_port: int, expected: str) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    current: str | None = None
    while time.monotonic() < deadline:
        try:
            current = selected(controller_port)
            if current == expected:
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError(f"selector did not become {expected}: {current}")


def run_once(
    binary: Path,
    scratch: Path,
    config: Path,
    mixed_port: int,
    controller_port: int,
    echo_port: int,
    expected: str,
    choose: str | None = None,
) -> dict[str, Any]:
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_selected(controller_port, expected)
        before = route(mixed_port, echo_port)
        mutation: tuple[int, bool] | None = None
        after: str | None = None
        if choose is not None:
            status, body = request(
                controller_port,
                "PUT",
                "/proxies/route-group",
                {"name": choose},
            )
            mutation = status, body == b""
            wait_selected(controller_port, choose)
            after = route(mixed_port, echo_port)
        return {
            "selected": expected,
            "route": before,
            "mutation": mutation,
            "after": after,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def exercise(binary: Path, scratch: Path, upstream_port: int, echo_port: int) -> dict[str, Any]:
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    write_config(config, mixed_port, controller_port, upstream_port, True)
    first = run_once(
        binary,
        scratch,
        config,
        mixed_port,
        controller_port,
        echo_port,
        "REJECT",
        "local-http",
    )
    restored = run_once(
        binary,
        scratch,
        config,
        mixed_port,
        controller_port,
        echo_port,
        "local-http",
        "REJECT",
    )
    reset = run_once(
        binary,
        scratch,
        config,
        mixed_port,
        controller_port,
        echo_port,
        "REJECT",
    )

    disabled = scratch / "disabled"
    disabled.mkdir()
    disabled_config = disabled / "config.yaml"
    disabled_mixed, disabled_controller = reserve_port(), reserve_port()
    write_config(
        disabled_config,
        disabled_mixed,
        disabled_controller,
        upstream_port,
        False,
    )
    disabled_first = run_once(
        binary,
        disabled,
        disabled_config,
        disabled_mixed,
        disabled_controller,
        echo_port,
        "REJECT",
        "local-http",
    )
    disabled_restart = run_once(
        binary,
        disabled,
        disabled_config,
        disabled_mixed,
        disabled_controller,
        echo_port,
        "REJECT",
    )
    return {
        "first": first,
        "restored": restored,
        "reset": reset,
        "disabled-first": disabled_first,
        "disabled-restart": disabled_restart,
    }


def interchange(
    binaries: dict[str, Path],
    scratch: Path,
    upstream_port: int,
    echo_port: int,
) -> dict[str, Any]:
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    write_config(config, mixed_port, controller_port, upstream_port, True)
    go_write = run_once(
        binaries["go"],
        scratch,
        config,
        mixed_port,
        controller_port,
        echo_port,
        "REJECT",
        "local-http",
    )
    rust_read_write = run_once(
        binaries["rust"],
        scratch,
        config,
        mixed_port,
        controller_port,
        echo_port,
        "local-http",
        "REJECT",
    )
    go_read = run_once(
        binaries["go"],
        scratch,
        config,
        mixed_port,
        controller_port,
        echo_port,
        "REJECT",
    )
    return {
        "go-write": go_write,
        "rust-read-write": rust_read_write,
        "go-read": go_read,
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-selector-persistence-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CSELECTORPERSIST_CARGO_TARGET",
            "phase5c-selector-persistence",
        )
        echo = start_server(EchoHandler)
        upstream = ConnectProxyServer()
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch, upstream.port, echo.port)
            shared = root / "interchange"
            shared.mkdir()
            observations["interchange"] = interchange(
                binaries,
                shared,
                upstream.port,
                echo.port,
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
            upstream.close()
            echo.close()
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5C selector persistence differential/interchange passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

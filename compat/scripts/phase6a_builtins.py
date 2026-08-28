#!/usr/bin/env python3
"""Go/Rust differential for Phase 6A built-ins and GLOBAL selection."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.parse
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import http_request, launch, status, stop
from phase5b1a import build_binaries, debug_files
from phase5b3a import relay_result
from phase5d_proxies import (
    delay_response,
    group_delay_response,
    normalize,
    request,
    start_health_server,
)
from phase5d_streams import SECRET, wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6a-builtins-diff.json"


def route_result(mixed_port: int, destination_port: int, payload: bytes) -> str:
    try:
        stream, response = http_request(mixed_port, destination_port, None)
        with stream:
            if " 200 " not in status(response):
                return status(response)
            return relay_result(stream, payload)
    except (OSError, EOFError, ConnectionResetError, BrokenPipeError):
        return "closed"


def wait_route_result(
    process: Any,
    mixed_port: int,
    destination_port: int,
    payload: bytes,
    expected: str,
) -> str:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited with {process.returncode}")
        result = route_result(mixed_port, destination_port, payload)
        if result == expected:
            return result
        time.sleep(0.02)
    raise TimeoutError(f"route did not become {expected}")


def rejected_result(mixed_port: int, destination_port: int) -> dict[str, Any]:
    stream, response = http_request(mixed_port, destination_port, None)
    with stream:
        stream.settimeout(1.0)
        started = time.monotonic()
        try:
            closed = stream.recv(1) == b""
        except (ConnectionResetError, BrokenPipeError):
            closed = True
        return {
            "connect-status": status(response),
            "closed": closed,
            "immediate": time.monotonic() - started < 0.8,
        }


def reject_drop_result(mixed_port: int, destination_port: int) -> dict[str, Any]:
    stream, response = http_request(mixed_port, destination_port, None)
    with stream:
        started = time.monotonic()
        stream.settimeout(0.4)
        try:
            held = stream.recv(1) != b""
        except TimeoutError:
            held = True
        stream.settimeout(0.6)
        try:
            stream.sendall(b"release-drop")
            held_after_payload = stream.recv(1) != b""
        except TimeoutError:
            held_after_payload = True
        except (ConnectionResetError, BrokenPipeError):
            held_after_payload = False
        timeout_expiry = "not-run"
        if os.environ.get("PHASE6A_DROP_TIMEOUT_TEST") == "1":
            stream.settimeout(65.0)
            try:
                closed = stream.recv(1) == b""
            except (ConnectionResetError, BrokenPipeError):
                closed = True
            elapsed = time.monotonic() - started
            if not closed or not 55.0 <= elapsed <= 65.0:
                raise AssertionError(
                    f"REJECT-DROP expiry mismatch: closed={closed}, elapsed={elapsed:.3f}s"
                )
            timeout_expiry = "closed-around-60s"
        return {
            "connect-status": status(response),
            "held-without-payload": held,
            "held-after-payload": held_after_payload,
            "default-timeout-expiry": timeout_expiry,
        }


def builtin_views(controller_port: int) -> dict[str, Any]:
    code, body = request(controller_port, "GET", "/proxies")
    if code != 200:
        raise AssertionError((code, body))
    proxies = normalize(json.loads(body)["proxies"])
    return {
        name: {
            key: proxies[name][key]
            for key in ("name", "type", "udp", "uot")
        }
        for name in ("DIRECT", "COMPATIBLE", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE")
    }


def exercise_builtins(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    mixed_port, controller_port = reserve_port(), reserve_port()
    reject_port, drop_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
rules:
  - DST-PORT,{reject_port},REJECT
  - DST-PORT,{drop_port},REJECT-DROP
  - DST-PORT,{echo.port},PASS
  - MATCH,COMPATIBLE
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        return {
            "pass-compatible": wait_route_result(
                process, mixed_port, echo.port, b"compatible", "direct"
            ),
            "reject": rejected_result(mixed_port, reject_port),
            "reject-drop": reject_drop_result(mixed_port, drop_port),
            "views": builtin_views(controller_port),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def global_snapshot(controller_port: int) -> dict[str, Any]:
    code, body = request(controller_port, "GET", "/proxies/GLOBAL")
    if code != 200:
        raise AssertionError((code, body))
    value = normalize(json.loads(body))
    return {
        key: value[key]
        for key in ("name", "type", "all", "now", "udp", "hidden")
    }


def select_global(controller_port: int, name: str) -> dict[str, Any]:
    code, body = request(
        controller_port, "PUT", "/proxies/GLOBAL", {"name": name}
    )
    return {"status": code, "empty-body": body == b""}


def exercise_default_global(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    upstream = ConnectProxyServer()
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: global
log-level: info
ipv6: false
proxies:
  - name: local-http
    type: http
    server: 127.0.0.1
    port: {upstream.port}
    username: proxy-user
    password: proxy-pass
rules: ['MATCH,REJECT']
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        before = global_snapshot(controller_port)
        select_proxy = select_global(controller_port, "local-http")
        selected_proxy = global_snapshot(controller_port)
        upstream.observations.clear()
        proxied = wait_route_result(
            process, mixed_port, echo.port, b"global-http", "direct"
        )
        proxy_observations = len(upstream.observations)
        reject_selection = select_global(controller_port, "REJECT")
        selected_reject = global_snapshot(controller_port)
        rejected = route_result(mixed_port, echo.port, b"global-reject")
        direct_selection = select_global(controller_port, "DIRECT")
        direct = wait_route_result(
            process, mixed_port, echo.port, b"global-direct", "direct"
        )
        return {
            "before": before,
            "select-proxy": select_proxy,
            "selected-proxy": selected_proxy,
            "proxy-route": proxied,
            "proxy-observations": proxy_observations,
            "select-reject": reject_selection,
            "selected-reject": selected_reject,
            "reject-route": rejected,
            "select-direct": direct_selection,
            "direct-route": direct,
            "after": global_snapshot(controller_port),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        upstream.close()
        echo.close()


def exercise_custom_global(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    health = start_health_server()
    health_url = f"http://127.0.0.1:{health.server_port}/health"
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: global
log-level: info
ipv6: false
proxy-groups:
  - name: GLOBAL
    type: select
    proxies: [REJECT, DIRECT]
rules: ['MATCH,DIRECT']
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        before = global_snapshot(controller_port)
        rejected = route_result(mixed_port, echo.port, b"custom-reject")
        selected = select_global(controller_port, "DIRECT")
        direct = wait_route_result(
            process, mixed_port, echo.port, b"custom-direct", "direct"
        )
        delay_query = urllib.parse.urlencode(
            {"url": health_url, "timeout": "1000", "expected": "200-299"}
        )
        return {
            "before": before,
            "initial-route": rejected,
            "select-direct": selected,
            "direct-route": direct,
            "selected-delay": delay_response(
                request(
                    controller_port,
                    "GET",
                    f"/proxies/GLOBAL/delay?{delay_query}",
                )
            ),
            "group-delay": group_delay_response(
                request(
                    controller_port,
                    "GET",
                    f"/group/GLOBAL/delay?{delay_query}",
                )
            ),
            "after": global_snapshot(controller_port),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        health.shutdown()
        health.server_close()
        echo.close()


def configuration_cases(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    base = "mixed-port: 7890\nmode: rule\nrules: ['MATCH,DIRECT']\n"
    cases = {
        "duplicate-proxy": base
        + "proxies:\n  - {name: duplicate, type: http, server: 127.0.0.1, port: 1}\n"
        + "  - {name: duplicate, type: socks5, server: 127.0.0.1, port: 2}\n",
        "reserved-direct": base
        + "proxies:\n  - {name: DIRECT, type: http, server: 127.0.0.1, port: 1}\n",
        "proxy-group-collision": base
        + "proxies:\n  - {name: collision, type: http, server: 127.0.0.1, port: 1}\n"
        + "proxy-groups:\n  - {name: collision, type: select, proxies: [DIRECT]}\n",
        "custom-global": base
        + "proxy-groups:\n  - {name: GLOBAL, type: select, proxies: [DIRECT, REJECT]}\n",
    }
    results = {}
    for name, source in cases.items():
        path = scratch / f"{name}.yaml"
        path.write_text(source)
        result = subprocess.run(
            [str(binary), "-t", "-f", str(path)],
            cwd=scratch,
            capture_output=True,
            timeout=IO_DEADLINE,
        )
        results[name] = result.returncode == 0
    return results


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    cases = {}
    for name in ("builtins", "default-global", "custom-global", "configuration"):
        path = scratch / name
        path.mkdir()
        cases[name] = path
    return {
        "builtins": exercise_builtins(binary, cases["builtins"]),
        "default-global": exercise_default_global(binary, cases["default-global"]),
        "custom-global": exercise_custom_global(binary, cases["custom-global"]),
        "configuration": configuration_cases(binary, cases["configuration"]),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6a-builtins-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6ABUILTINS_CARGO_TARGET", "phase6a-builtins")
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
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {"observations": observations, "debug": debug_files(root)},
                    indent=2,
                    sort_keys=True,
                )
            )
            return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6A built-ins and GLOBAL differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

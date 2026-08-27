#!/usr/bin/env python3
"""Go/Rust differential for rule inventory, statistics and disable control."""

from __future__ import annotations

import http.client
import json
import pathlib
import tempfile
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files, route, wait_route
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5d-rules-diff.json"


def request(
    port: int, method: str, path: str, body: bytes | None = None
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    headers = {"Authorization": f"Bearer {SECRET}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    try:
        return response.status, response.read()
    finally:
        response.close()
        connection.close()


def patch(port: int, value: dict[str, bool]) -> tuple[int, bytes]:
    return request(port, "PATCH", "/rules/disable", json.dumps(value).encode())


def snapshot(port: int) -> list[dict[str, Any]]:
    code, body = request(port, "GET", "/rules")
    if code != 200:
        raise AssertionError((code, body))
    rules = json.loads(body)["rules"]
    return [
        {
            "index": rule["index"],
            "type": rule["type"],
            "payload": rule["payload"],
            "proxy": rule["proxy"],
            "size": rule["size"],
            "extra": {
                "disabled": rule["extra"]["disabled"],
                "hitCount": rule["extra"]["hitCount"],
                "hitAt": rule["extra"]["hitAt"],
                "missCount": rule["extra"]["missCount"],
                "missAt": rule["extra"]["missAt"],
            },
        }
        for rule in rules
    ]


def relative_snapshot(
    current: list[dict[str, Any]], baseline: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    normalized = json.loads(json.dumps(current))
    for rule, base in zip(normalized, baseline, strict=True):
        for prefix in ("hit", "miss"):
            count = f"{prefix}Count"
            timestamp = f"{prefix}At"
            rule["extra"][count] -= base["extra"][count]
            rule["extra"][timestamp] = (
                "advanced" if rule["extra"][count] > 0 else "unchanged"
            )
    return normalized


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
hosts:
  rules.phase.test: 127.0.0.1
rules:
  - DOMAIN-SUFFIX,RULES.PHASE.TEST,DIRECT
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_route(process, mixed_port, "rules.phase.test", echo.port, "direct")
        baseline = snapshot(controller_port)
        initial = relative_snapshot(baseline, baseline)

        direct = route(mixed_port, "rules.phase.test", echo.port)
        rejected = route(mixed_port, "127.0.0.1", echo.port)
        after_routes = relative_snapshot(snapshot(controller_port), baseline)

        disable_code, disable_body = patch(controller_port, {"0": True})
        disabled_route = route(mixed_port, "rules.phase.test", echo.port)
        after_disable_raw = snapshot(controller_port)
        after_disable = relative_snapshot(after_disable_raw, baseline)

        ignored_code, ignored_body = patch(
            controller_port, {"-1": True, "99": True}
        )
        after_ignored_raw = snapshot(controller_port)
        after_ignored = relative_snapshot(after_ignored_raw, baseline)
        malformed_code, malformed_body = request(
            controller_port, "PATCH", "/rules/disable", b"{"
        )

        enable_code, enable_body = patch(controller_port, {"0": False})
        enabled_route = route(mixed_port, "rules.phase.test", echo.port)
        after_enable = relative_snapshot(snapshot(controller_port), baseline)

        return {
            "initial": initial,
            "routes": {
                "matching": direct,
                "fallback": rejected,
                "snapshot": after_routes,
            },
            "disable": {
                "status": disable_code,
                "empty-body": disable_body == b"",
                "route": disabled_route,
                "snapshot": after_disable,
            },
            "ignored-indexes": {
                "status": ignored_code,
                "empty-body": ignored_body == b"",
                "unchanged": after_ignored_raw == after_disable_raw,
            },
            "malformed": {
                "status": malformed_code,
                "message": json.loads(malformed_body)["message"],
            },
            "enable": {
                "status": enable_code,
                "empty-body": enable_body == b"",
                "route": enabled_route,
                "snapshot": after_enable,
            },
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-rules-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5DRULES_CARGO_TARGET", "phase5d-rules")
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
            json.dumps({"observations": observations}, indent=2, sort_keys=True)
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5D rules controller differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

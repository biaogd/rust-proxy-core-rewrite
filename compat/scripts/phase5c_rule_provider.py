#!/usr/bin/env python3
"""Go/Rust differential for inline, file and HTTP rule providers."""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files, route
from phase5c_http_provider import ProviderServer, normalize_provider
from phase5d_proxies import request
from phase5d_streams import wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-rule-provider-diff.json"


def write_config(path: Path, mixed: int, controller: int, provider: int) -> None:
    path.write_text(
        f"""mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
mode: rule
log-level: info
ipv6: false
hosts:
  deep.inline.test: 127.0.0.1
  file-block.test: 127.0.0.1
  file-next.test: 127.0.0.1
  mrs-block.test: 127.0.0.1
rule-providers:
  inline-domain:
    type: inline
    behavior: domain
    payload: ['+.inline.test']
  file-classical:
    type: file
    behavior: classical
    path: rules/file.yaml
  mrs-domain:
    type: file
    behavior: domain
    format: mrs
    path: rules/domain.mrs
  remote-ip:
    type: http
    behavior: ipcidr
    format: text
    url: http://127.0.0.1:{provider}/rules.txt?phase=5c4a
    path: rules/remote.txt
    interval: 1
rules:
  - RULE-SET,inline-domain,REJECT
  - RULE-SET,file-classical,REJECT
  - RULE-SET,mrs-domain,REJECT
  - RULE-SET,remote-ip,REJECT,no-resolve
  - MATCH,DIRECT
"""
    )


def providers(controller: int) -> Any:
    status, body = request(controller, "GET", "/providers/rules")
    if status != 200:
        raise AssertionError((status, body))
    return normalize_provider(json.loads(body))


def update(controller: int, name: str) -> tuple[int, bool]:
    status, body = request(controller, "PUT", f"/providers/rules/{name}")
    return status, body == b""


def wait_route(
    process: Any,
    mixed: int,
    host: str,
    destination: int,
    expected: str,
) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during rule-provider update: {process.returncode}")
        try:
            if route(mixed, host, destination) == expected:
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError(f"{host} did not become {expected}")


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    provider = ProviderServer(b"192.0.2.0/24\n")
    mixed, controller = reserve_port(), reserve_port()
    home = scratch / ".config" / "mihomo"
    file_rules = home / "rules" / "file.yaml"
    file_rules.parent.mkdir(parents=True)
    file_rules.write_text("payload:\n  - DOMAIN,file-block.test\n")
    mrs_source = scratch / "mrs-source.txt"
    mrs_source.write_text("mrs-block.test\n")
    subprocess.run(
        [
            str(binary),
            "convert-ruleset",
            "domain",
            "text",
            str(mrs_source),
            str(home / "rules" / "domain.mrs"),
        ],
        cwd=scratch,
        check=True,
        capture_output=True,
        timeout=15,
    )
    config = scratch / "config.yaml"
    write_config(config, mixed, controller, provider.port)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed)
        wait_controller(process, controller)
        wait_route(process, mixed, "deep.inline.test", echo.port, "reject")
        wait_route(process, mixed, "file-block.test", echo.port, "reject")
        wait_route(process, mixed, "mrs-block.test", echo.port, "reject")
        wait_route(process, mixed, "127.0.0.1", echo.port, "direct")
        initial = {
            "providers": providers(controller),
            "inline": route(mixed, "deep.inline.test", echo.port),
            "file": route(mixed, "file-block.test", echo.port),
            "mrs": route(mixed, "mrs-block.test", echo.port),
            "ip": route(mixed, "127.0.0.1", echo.port),
            "miss": route(mixed, "localhost", echo.port),
            "remote-request": bool(provider.observations),
        }

        file_rules.write_text("payload:\n  - DOMAIN,file-next.test\n")
        wait_route(process, mixed, "file-block.test", echo.port, "direct")
        wait_route(process, mixed, "file-next.test", echo.port, "reject")
        file_watch = (
            route(mixed, "file-block.test", echo.port),
            route(mixed, "file-next.test", echo.port),
        )
        file_update = update(controller, "file-classical")
        wait_route(process, mixed, "file-block.test", echo.port, "direct")
        wait_route(process, mixed, "file-next.test", echo.port, "reject")

        provider.respond(b"198.51.100.0/24\n")
        remote_update = update(controller, "remote-ip")
        wait_route(process, mixed, "127.0.0.1", echo.port, "direct")
        provider.respond(b"127.0.0.0/8\n")
        wait_route(process, mixed, "127.0.0.1", echo.port, "reject")
        interval_ip = route(mixed, "127.0.0.1", echo.port)
        missing = request(controller, "PUT", "/providers/rules/missing")
        return {
            "initial": initial,
            "file-update": file_update,
            "file-watch": file_watch,
            "file-old": route(mixed, "file-block.test", echo.port),
            "file-new": route(mixed, "file-next.test", echo.port),
            "remote-update": remote_update,
            "interval-ip": interval_ip,
            "ip-after": route(mixed, "127.0.0.1", echo.port),
            "remote-cache": (home / "rules" / "remote.txt").read_bytes()
            == b"127.0.0.0/8\n",
            "providers-after": providers(controller),
            "missing-status": missing[0],
            "missing-message": isinstance(json.loads(missing[1]).get("message"), str),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        provider.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-rule-provider-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CRULEPROVIDER_CARGO_TARGET",
            "phase5c-rule-provider",
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
    print("Phase 5C rule-provider differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

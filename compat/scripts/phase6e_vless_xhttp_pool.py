#!/usr/bin/env python3
"""Go/Rust differential for basic xHTTP XMUX reuse and reconnection."""

from __future__ import annotations

import json
import pathlib
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase6d_vmess_websocket import trusted_roots
from phase6e_vless_tcp import exchange, vless_record
from phase6e_vless_websocket import build_authority, start_authority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-xhttp-pool-diff.json"


def record(name: str, port: int, *, max_connections: int) -> str:
    return vless_record(
        name,
        port,
        network="xhttp",
        extra=(
            "    tls: true\n"
            "    servername: dot.phase4.test\n"
            "    xhttp-opts:\n"
            "      mode: stream-one\n"
            f"      host: {name}.phase6e\n"
            f"      path: /{name}\n"
            "      x-padding-bytes: '16'\n"
            "      reuse-settings:\n"
            "        max-concurrency: '0'\n"
            f"        max-connections: '{max_connections}'\n"
        ),
    )


def wait_exchange(process: Any, mixed_port: int, host: str, port: int, payload: bytes) -> bool:
    deadline = time.monotonic() + max(IO_DEADLINE, 10.0)
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during xHTTP pool exchange: {process.returncode}")
        try:
            if exchange(mixed_port, host, port, payload):
                return True
        except (AssertionError, EOFError, OSError) as error:
            last_error = error
        time.sleep(0.05)
    raise TimeoutError(f"xHTTP pool exchange failed: {last_error}")


def connection_count(output: pathlib.Path, expected: int) -> int:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        connections = {
            line.strip()
            for line in output.read_text(errors="replace").splitlines()
            if line.startswith("XHTTP-CONN ")
        }
        if len(connections) >= expected:
            return len(connections)
        time.sleep(0.02)
    raise TimeoutError(f"expected {expected} xHTTP connections in {output}")


def exercise(
    binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    specs = [
        ("xmux-one", 0, False),
        ("xmux-two", 2, False),
        ("xmux-reconnect", 0, True),
    ]
    ports = {name: reserve_port() for name, _, _ in specs}
    outputs: dict[str, pathlib.Path] = {}
    handles = []
    for name, _, close_after in specs:
        process, stdout, stderr, output = start_authority(
            authority_binary,
            scratch,
            ports[name],
            log_name=f"authority-{name}",
            transport="xhttp",
            certificate=pathlib.Path(SERVER_CERTIFICATE),
            private_key=pathlib.Path(SERVER_KEY),
            expected_http_host=f"{name}.phase6e",
            expected_http_path=f"/{name}/",
            close_h2_after_stream=close_after,
        )
        outputs[name] = output
        handles.append((process, stdout, stderr))

    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        trusted_roots()
        + f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
{''.join(record(name, ports[name], max_connections=max_connections) for name, max_connections, _ in specs)}rules:
  - DST-PORT,29401,xmux-one
  - DST-PORT,29402,xmux-two
  - DST-PORT,29403,xmux-reconnect
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        one = [
            wait_exchange(process, mixed_port, f"one-{index}.phase6e", 29401, f"one-{index}".encode())
            for index in range(3)
        ]
        two = [
            wait_exchange(process, mixed_port, f"two-{index}.phase6e", 29402, f"two-{index}".encode())
            for index in range(3)
        ]
        reconnect = [
            wait_exchange(
                process,
                mixed_port,
                f"reconnect-{index}.phase6e",
                29403,
                f"reconnect-{index}".encode(),
            )
            for index in range(2)
        ]
        return {
            "single-connection": {
                "connections": connection_count(outputs["xmux-one"], 1),
                "exchanges": one,
            },
            "two-connections": {
                "connections": connection_count(outputs["xmux-two"], 2),
                "exchanges": two,
            },
            "reconnect-after-h2-close": {
                "connections": connection_count(outputs["xmux-reconnect"], 2),
                "exchanges": reconnect,
            },
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        for authority, authority_stdout, authority_stderr in handles:
            stop(authority)
            authority_stdout.close()
            authority_stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6e-vless-xhttp-pool-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6EVLESSXHTTPPOOL_CARGO_TARGET", "phase6e-xhttp-pool")
        authority = build_authority(root)
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, authority, scratch)
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
    print("Phase 6E VLESS xHTTP XMUX differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

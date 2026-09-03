#!/usr/bin/env python3
"""Go/Rust differential for VLESS xHTTP auto over authenticated REALITY."""

from __future__ import annotations

import json
import pathlib
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase6d_vmess_websocket import LARGE_PAYLOAD
from phase6e_vless_reality import (
    REALITY_PUBLIC_KEY,
    REALITY_SERVER_NAME,
    REALITY_SHORT_ID,
    build_authority,
    start_authority,
)
from phase6e_vless_tcp import STANDARD_UUID, exchange


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-xhttp-reality-diff.json"


def record(port: int) -> str:
    return f"""  - name: xhttp-reality
    type: vless
    server: 127.0.0.1
    port: {port}
    uuid: {STANDARD_UUID}
    encryption: none
    network: xhttp
    tls: true
    client-fingerprint: chrome
    servername: {REALITY_SERVER_NAME}
    reality-opts:
      public-key: {REALITY_PUBLIC_KEY}
      short-id: {REALITY_SHORT_ID}
    xhttp-opts:
      host: reality-xhttp.phase6e
      path: /reality-xhttp
      x-padding-bytes: '32'
      headers:
        X-Phase: 6e-xhttp-reality
"""


def wait_exchange(process: Any, mixed_port: int) -> bool:
    deadline = time.monotonic() + max(IO_DEADLINE, 15.0)
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during REALITY xHTTP exchange: {process.returncode}")
        try:
            if exchange(mixed_port, "xhttp-reality-target.phase6e", 29501, LARGE_PAYLOAD):
                return True
        except (AssertionError, EOFError, OSError, ValueError) as error:
            last_error = error
        time.sleep(0.05)
    raise TimeoutError(f"REALITY xHTTP exchange failed: {last_error}")


def exercise(
    binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    authority_port = reserve_port()
    authority, authority_stdout, authority_stderr, _ = start_authority(
        authority_binary,
        scratch,
        authority_port,
        log_name="reality-xhttp-authority",
        transport="xhttp",
        expected_http_host="reality-xhttp.phase6e",
        expected_http_path="/reality-xhttp/",
    )
    authority_output = scratch / "reality-xhttp-authority-stdout.log"
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if authority.poll() is not None:
            raise RuntimeError("REALITY xHTTP authority exited during startup")
        if "READY " in authority_output.read_text(errors="replace"):
            break
        time.sleep(0.02)
    else:
        raise TimeoutError("REALITY xHTTP authority did not become ready")

    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
{record(authority_port)}rules:
  - MATCH,xhttp-reality
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        relayed = wait_exchange(process, mixed_port)
        deadline = time.monotonic() + IO_DEADLINE
        expected = {
            "XHTTP POST reality-xhttp.phase6e /reality-xhttp/ application/grpc",
            "CONNECT xhttp-reality-target.phase6e:29501",
        }
        while time.monotonic() < deadline:
            observed = set(authority_output.read_text(errors="replace").splitlines())
            if expected <= observed:
                break
            time.sleep(0.02)
        else:
            raise TimeoutError(f"missing REALITY xHTTP observations: {sorted(expected - observed)}")
        return {
            "auto-selected-stream-one": relayed,
            "authority": sorted(expected),
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop(authority)
        authority_stdout.close()
        authority_stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6e-vless-xhttp-reality-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE6EVLESSXHTTPREALITY_CARGO_TARGET",
            "phase6e-xhttp-reality",
        )
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
    print("Phase 6E VLESS xHTTP REALITY differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

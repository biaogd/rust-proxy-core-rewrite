#!/usr/bin/env python3
"""Go/Rust differential for Phase 6D-F VMess TLS and WebSocket TCP."""

from __future__ import annotations

import json
import pathlib
import tempfile
import textwrap
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase6d_vmess_tcp import (
    build_authority,
    exchange,
    rejected_exchange,
    start_authority,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6d-vmess-websocket-diff.json"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
LARGE_PAYLOAD = bytes(range(256)) * 512


def record(
    name: str,
    authority_port: int,
    *,
    network: str,
    tls_fields: str = "",
    ws_fields: str = "",
    cipher: str = "aes-128-gcm",
    alter_id: int = 0,
) -> str:
    return f"""  - name: {name}
    type: vmess
    server: 127.0.0.1
    port: {authority_port}
    uuid: {UUID}
    alterId: {alter_id}
    cipher: {cipher}
    network: {network}
{tls_fields}{ws_fields}"""


def trusted_roots() -> str:
    root = pathlib.Path(ROOT_CERTIFICATE).read_text().strip()
    return "tls:\n  custom-certifactes:\n    - |-\n" + textwrap.indent(root, "      ") + "\n"


def wait_exchange(
    process: Any,
    mixed_port: int,
    host: str,
    port: int,
    payload: bytes,
) -> bool:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during VMess transport readiness: {process.returncode}")
        try:
            if exchange(mixed_port, host, port, payload):
                return True
        except (AssertionError, EOFError, OSError):
            pass
        time.sleep(0.02)
    raise TimeoutError("VMess TLS/WebSocket route did not become ready")


def wait_observations(
    authorities: list[tuple[Any, pathlib.Path]], expected: set[str]
) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed: set[str] = set()
        for process, output in authorities:
            if process.poll() is not None:
                raise RuntimeError("VMess transport authority exited")
            observed.update(
                line.strip()
                for line in output.read_text(errors="replace").splitlines()
                if line.startswith(("TLS ", "WS ", "CONNECT "))
            )
        if expected <= observed:
            return sorted(expected)
        time.sleep(0.02)
    raise TimeoutError(f"missing VMess transport observations: {sorted(expected - observed)}")


def launch_single_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authority_port: int,
    *,
    skip: bool,
    servername: str,
) -> tuple[Any, Any, Any, int]:
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    proxy_record = record(
        "wss-case",
        authority_port,
        network="ws",
        alter_id=1,
        tls_fields=(
            "    tls: true\n"
            f"    servername: {servername}\n"
            f"    skip-cert-verify: {str(skip).lower()}\n"
        ),
        ws_fields=(
            "    ws-opts:\n"
            "      path: /case\n"
            "      headers:\n"
            "        Host: case.phase6d.test\n"
        ),
    )
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
{proxy_record}rules:
  - MATCH,wss-case
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    wait_ready(process, mixed_port)
    return process, stdout, stderr, mixed_port


def exercise(binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    raw_tls_port, ws_port, wss_port = reserve_port(), reserve_port(), reserve_port()
    authorities = []
    handles = []
    for name, port, transport, tls in [
        ("raw-tls", raw_tls_port, "tcp", True),
        ("ws", ws_port, "ws", False),
        ("wss", wss_port, "ws", True),
    ]:
        process, stdout, stderr, output = start_authority(
            authority_binary,
            scratch,
            port,
            alter_id=1 if name == "wss" else 0,
            log_name=f"authority-{name}",
            transport=transport,
            certificate=pathlib.Path(SERVER_CERTIFICATE) if tls else None,
            private_key=pathlib.Path(SERVER_KEY) if tls else None,
        )
        authorities.append((process, output))
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
{record("vmess-tls", raw_tls_port, network="tcp", tls_fields="    tls: true\n    servername: dot.phase4.test\n")}{record("vmess-ws", ws_port, network="ws", cipher="chacha20-poly1305", ws_fields="    ws-opts:\n      path: /vmess?token=1\n      headers:\n        Host: phase6d-ws.example\n")}{record("vmess-wss", wss_port, network="ws", cipher="aes-128-cfb", alter_id=1, tls_fields="    tls: true\n", ws_fields="    ws-opts:\n      path: /secure-vmess\n      headers:\n        Host: dot.phase4.test\n")}{record("vmess-wss-name", wss_port, network="ws", cipher="none", alter_id=1, tls_fields="    tls: true\n    servername: explicit.phase6d.test\n    name-cert-verify: dot.phase4.test\n", ws_fields="    ws-opts:\n      path: /name-override\n      headers:\n        Host: front.phase6d.test\n") }rules:
  - DST-PORT,26001,vmess-tls
  - DST-PORT,26002,vmess-ws
  - DST-PORT,26003,vmess-wss
  - DST-PORT,26004,vmess-wss-name
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    opened = []
    try:
        wait_ready(process, mixed_port)
        matrix = {
            "tls": {
                "small": wait_exchange(process, mixed_port, "tls.phase6d", 26001, b"tls-ready"),
                "half-close": exchange(
                    mixed_port, "tls-half.phase6d", 26001, b"tls-half-close", half_close=True
                ),
            },
            "ws": {
                "large": wait_exchange(process, mixed_port, "ws.phase6d", 26002, LARGE_PAYLOAD),
            },
            "wss": {
                "legacy-large": wait_exchange(
                    process, mixed_port, "wss.phase6d", 26003, LARGE_PAYLOAD
                ),
                "name-override": wait_exchange(
                    process, mixed_port, "wss-name.phase6d", 26004, b"name-override"
                ),
            },
        }

        skip_dir = scratch / "skip"
        skip_dir.mkdir()
        skip_process, skip_stdout, skip_stderr, skip_port = launch_single_case(
            binary,
            skip_dir,
            wss_port,
            skip=True,
            servername="skip.phase6d.test",
        )
        opened.append((skip_process, skip_stdout, skip_stderr))
        skip_route = wait_exchange(skip_process, skip_port, "skip.phase6d", 443, b"skip")
        stop(skip_process)

        untrusted_dir = scratch / "untrusted"
        untrusted_dir.mkdir()
        untrusted_process, untrusted_stdout, untrusted_stderr, untrusted_port = launch_single_case(
            binary,
            untrusted_dir,
            wss_port,
            skip=False,
            servername="dot.phase4.test",
        )
        opened.append((untrusted_process, untrusted_stdout, untrusted_stderr))
        untrusted_rejected = rejected_exchange(untrusted_port, "untrusted.phase6d", 443)
        survived_untrusted = untrusted_process.poll() is None
        stop(untrusted_process)

        expected = {
            "TLS dot.phase4.test",
            "TLS explicit.phase6d.test",
            "TLS skip.phase6d.test",
            "WS phase6d-ws.example /vmess?token=1",
            "WS dot.phase4.test /secure-vmess",
            "WS front.phase6d.test /name-override",
            "WS case.phase6d.test /case",
            "CONNECT tls.phase6d:26001",
            "CONNECT ws.phase6d:26002",
            "CONNECT wss.phase6d:26003",
            "CONNECT wss-name.phase6d:26004",
        }
        return {
            "matrix": matrix,
            "skip-route": skip_route,
            "untrusted-rejected": untrusted_rejected,
            "survived-untrusted": survived_untrusted,
            "process-alive": process.poll() is None,
            "authority": wait_observations(authorities, expected),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        for child, child_stdout, child_stderr in opened:
            stop(child)
            child_stdout.close()
            child_stderr.close()
        for authority, authority_stdout, authority_stderr in handles:
            stop(authority)
            authority_stdout.close()
            authority_stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6d-vmess-websocket-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6DFVMESS_CARGO_TARGET", "phase6d-f-vmess")
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
    print("Phase 6D-F VMess TLS/WebSocket TCP differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

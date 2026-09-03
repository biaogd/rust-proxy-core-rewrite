#!/usr/bin/env python3
"""Bounded production gate for real sing-vless services and carrier pressure."""

from __future__ import annotations

import concurrent.futures
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
from phase6e_vless_grpc import DEFAULT_USER_AGENT
from phase6e_vless_tcp import exchange, rejected_exchange, vless_record
from phase6e_vless_websocket import build_authority, start_authority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-production-gate.json"


def grpc_record(port: int) -> str:
    return vless_record(
        "vless-grpc-pressure",
        port,
        network="grpc",
        extra=(
            "    grpc-opts:\n"
            "      grpc-service-name: pressure\n"
            "      max-connections: 2\n"
            "      min-streams: 16\n"
        ),
    )


def xhttp_record(name: str, port: int, host: str) -> str:
    return vless_record(
        name,
        port,
        network="xhttp",
        extra=(
            "    tls: true\n"
            "    servername: dot.phase4.test\n"
            "    xhttp-opts:\n"
            "      mode: stream-up\n"
            f"      host: {host}\n"
            f"      path: /{name}\n"
            "      x-padding-bytes: '8'\n"
            "      reuse-settings:\n"
            "        max-concurrency: '16'\n"
            "        max-connections: '1'\n"
        ),
    )


def concurrent_exchanges(
    mixed_port: int, destination_port: int, prefix: str, count: int
) -> list[bool]:
    def one(index: int) -> bool:
        payload = (f"{prefix}-{index}-".encode() * 128)[:2048]
        return exchange(mixed_port, f"{prefix}-{index}.phase6e", destination_port, payload)

    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
        futures = [executor.submit(one, index) for index in range(count)]
        return [future.result(timeout=max(IO_DEADLINE, 15.0)) for future in futures]


def exercise(
    binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    grpc_port, xhttp_port, invalid_port = (reserve_port() for _ in range(3))
    authority_specs = [
        (
            grpc_port,
            dict(
                log_name="authority-grpc",
                transport="grpc",
                expected_http_host=f"127.0.0.1:{grpc_port}",
                expected_http_path="/pressure/Tun",
                expected_grpc_user_agent=DEFAULT_USER_AGENT,
                packet_mode="standard",
                stream_barrier=32,
            ),
        ),
        (
            xhttp_port,
            dict(
                log_name="authority-xhttp",
                transport="xhttp",
                certificate=pathlib.Path(SERVER_CERTIFICATE),
                private_key=pathlib.Path(SERVER_KEY),
                expected_http_host="xhttp-pressure.phase6e",
                expected_http_path="/vless-xhttp-pressure/",
                packet_mode="standard",
            ),
        ),
        (
            invalid_port,
            dict(
                log_name="authority-invalid",
                transport="xhttp",
                certificate=pathlib.Path(SERVER_CERTIFICATE),
                private_key=pathlib.Path(SERVER_KEY),
                expected_http_host="expected-invalid.phase6e",
                expected_http_path="/vless-xhttp-invalid/",
                packet_mode="standard",
            ),
        ),
    ]
    handles = []
    outputs = []
    for port, options in authority_specs:
        process, stdout, stderr, output = start_authority(
            authority_binary, scratch, port, **options
        )
        handles.append((process, stdout, stderr))
        outputs.append(output)

    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        trusted_roots()
        + f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
{grpc_record(grpc_port)}{xhttp_record("vless-xhttp-pressure", xhttp_port, "xhttp-pressure.phase6e")}{xhttp_record("vless-xhttp-invalid", invalid_port, "wrong-invalid.phase6e")}rules:
  - DST-PORT,29601,vless-grpc-pressure
  - DST-PORT,29602,vless-xhttp-pressure
  - DST-PORT,29603,vless-xhttp-invalid
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    started = time.monotonic()
    try:
        wait_ready(process, mixed_port)
        grpc = concurrent_exchanges(mixed_port, 29601, "grpc-pressure", 32)
        xhttp = concurrent_exchanges(mixed_port, 29602, "xhttp-pressure", 16)
        rejected = [
            rejected_exchange(mixed_port, f"invalid-{index}.phase6e", 29603)
            for index in range(16)
        ]
        recovery = exchange(mixed_port, "recovery.phase6e", 29602, b"recovery")
        return {
            "real-sing-vless-grpc": {"count": len(grpc), "all": all(grpc)},
            "real-sing-vless-xhttp": {"count": len(xhttp), "all": all(xhttp)},
            "bounded-http-status-failures": {"count": len(rejected), "all": all(rejected)},
            "recovery": recovery,
            "process-alive": process.poll() is None,
            "duration-class": "bounded" if time.monotonic() - started < 60 else "slow",
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
    with tempfile.TemporaryDirectory(prefix="phase6e-vless-production-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6EVLESSPRODUCTION_CARGO_TARGET", "phase6e-production")
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
    print("Phase 6E VLESS production gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

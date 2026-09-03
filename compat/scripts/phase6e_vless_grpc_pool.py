#!/usr/bin/env python3
"""Go/Rust differential for VLESS gRPC pooling, limits, and keepalive."""

from __future__ import annotations

import concurrent.futures
import json
import pathlib
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase6e_vless_grpc import DEFAULT_USER_AGENT
from phase6e_vless_tcp import STANDARD_UUID, config_validation, exchange, vless_record
from phase6e_vless_websocket import build_authority, start_authority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-grpc-pool-diff.json"


def record(name: str, port: int, options: str = "") -> str:
    return vless_record(
        name,
        port,
        network="grpc",
        extra="    grpc-opts:\n      grpc-service-name: GunService\n" + options,
    )


def wait_stream_count(
    output: pathlib.Path,
    expected: int,
    future: concurrent.futures.Future[bool] | None = None,
) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed = sum(
            line.startswith("GRPC POST ")
            for line in output.read_text(errors="replace").splitlines()
        )
        if observed >= expected:
            return
        if future is not None and future.done():
            future.result()
            raise AssertionError("VLESS gRPC exchange ended before its stream was observed")
        time.sleep(0.01)
    raise TimeoutError(f"expected {expected} VLESS gRPC streams in {output}")


def run_concurrent(
    mixed_port: int,
    destination_port: int,
    count: int,
    authority_output: pathlib.Path,
) -> list[bool]:
    def one(index: int) -> bool:
        payload = f"vless-pool-{destination_port}-{index}".encode()
        return exchange(mixed_port, f"pool-{index}.phase6e", destination_port, payload)

    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
        futures = []
        for index in range(count):
            futures.append(executor.submit(one, index))
            wait_stream_count(authority_output, index + 1, futures[-1])
        return [future.result(timeout=IO_DEADLINE) for future in futures]


def connection_count(output: pathlib.Path, expected: int) -> int:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        connections = {
            line.strip()
            for line in output.read_text(errors="replace").splitlines()
            if line.startswith("GRPC-CONN ")
        }
        if len(connections) >= expected:
            return len(connections)
        time.sleep(0.02)
    raise TimeoutError(f"expected {expected} VLESS gRPC connections in {output}")


def exercise(
    binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    ports = [reserve_port() for _ in range(4)]
    authority_options = [
        {"stream_barrier": 3, "packet_mode": "standard"},
        {"stream_barrier": 4, "packet_mode": "standard"},
        {"stream_barrier": 3, "packet_mode": "standard"},
        {"close_h2_after_stream": True, "packet_mode": "standard"},
    ]
    authorities = []
    handles = []
    for index, (port, options) in enumerate(zip(ports, authority_options, strict=True)):
        process, stdout, stderr, output = start_authority(
            authority_binary,
            scratch,
            port,
            log_name=f"authority-{index}",
            transport="grpc",
            expected_http_host=f"127.0.0.1:{port}",
            expected_http_path="/GunService/Tun",
            expected_grpc_user_agent=DEFAULT_USER_AGENT,
            **options,
        )
        authorities.append((process, output))
        handles.append((process, stdout, stderr))

    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
{record("grpc-default", ports[0])}{record("grpc-max-connections", ports[1], "      max-connections: 2\n      min-streams: 2\n")}{record("grpc-max-streams", ports[2], "      max-connections: 0\n      max-streams: 1\n")}{record("grpc-reconnect", ports[3])}
rules:
  - DST-PORT,29201,grpc-default
  - DST-PORT,29202,grpc-max-connections
  - DST-PORT,29203,grpc-max-streams
  - DST-PORT,29204,grpc-reconnect
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        default = run_concurrent(mixed_port, 29201, 3, authorities[0][1])
        bounded_connections = run_concurrent(mixed_port, 29202, 4, authorities[1][1])
        bounded_streams = run_concurrent(mixed_port, 29203, 3, authorities[2][1])
        reconnect = [exchange(mixed_port, "reconnect-0.phase6e", 29204, b"reconnect-0")]
        time.sleep(0.2)
        reconnect.append(exchange(mixed_port, "reconnect-1.phase6e", 29204, b"reconnect-1"))
        return {
            "default": {
                "connections": connection_count(authorities[0][1], 1),
                "exchanges": default,
            },
            "max-connections-min-streams": {
                "expanded-pool": connection_count(authorities[1][1], 2) >= 2,
                "exchanges": bounded_connections,
            },
            "max-streams": {
                "expanded-pool": connection_count(authorities[2][1], 3) >= 3,
                "exchanges": bounded_streams,
            },
            "reconnect-after-h2-close": {
                "reconnected": connection_count(authorities[3][1], 2) >= 2,
                "exchanges": reconnect,
            },
            "process-alive": process.poll() is None,
            "signed-options-accepted": config_validation(
                binary,
                scratch,
                "proxies:\n"
                + record(
                    "grpc-signed",
                    ports[0],
                    "      ping-interval: -1\n"
                    "      max-connections: -1\n"
                    "      min-streams: -1\n"
                    "      max-streams: -1\n",
                ),
            ),
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
    with tempfile.TemporaryDirectory(prefix="phase6e-vless-grpc-pool-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6EVLESSGRPCPOOL_CARGO_TARGET", "phase6e-vless-pool")
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
    print("Phase 6E VLESS gRPC pool differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

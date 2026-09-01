#!/usr/bin/env python3
"""Go/Rust differential for Phase 6D-J VMess gRPC/Gun pooling and ping."""

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
from phase6d_vmess_grpc import DEFAULT_USER_AGENT, UUID
from phase6d_vmess_tcp import build_authority, config_validation, exchange, start_authority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6d-vmess-grpc-pool-diff.json"


def record(name: str, port: int, options: str = "") -> str:
    return f"""  - name: {name}
    type: vmess
    server: 127.0.0.1
    port: {port}
    uuid: {UUID}
    alterId: 0
    cipher: auto
    network: grpc
    grpc-opts:
      grpc-service-name: GunService
{options}"""


def wait_stream_count(output: pathlib.Path, expected: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed = sum(
            line.startswith("GRPC POST ")
            for line in output.read_text(errors="replace").splitlines()
        )
        if observed >= expected:
            return
        time.sleep(0.01)
    raise TimeoutError(f"expected {expected} gRPC streams in {output}")


def run_concurrent(
    mixed_port: int,
    destination_port: int,
    count: int,
    authority_output: pathlib.Path,
) -> list[bool]:
    def one(index: int) -> bool:
        payload = f"pool-{destination_port}-{index}".encode()
        return exchange(mixed_port, f"pool-{index}.phase6d", destination_port, payload)

    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
        futures = []
        for index in range(count):
            futures.append(executor.submit(one, index))
            # Go intentionally releases its pool mutex before Transport.Dial
            # increments the active count. Observe that increment's resulting
            # request before admitting the next caller, while the authority
            # barrier keeps every prior logical stream active.
            wait_stream_count(authority_output, index + 1)
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
    raise TimeoutError(f"expected {expected} gRPC connections in {output}")


def wait_for_ping(output: pathlib.Path) -> bool:
    deadline = time.monotonic() + max(IO_DEADLINE, 4)
    while time.monotonic() < deadline:
        if "H2-PING" in output.read_text(errors="replace").splitlines():
            return True
        time.sleep(0.02)
    raise TimeoutError("VMess gRPC client did not emit an HTTP/2 health ping")


def exercise(
    binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    ports = [reserve_port() for _ in range(4)]
    authority_options = [
        {"stream_barrier": 3},
        {"stream_barrier": 4},
        {"stream_barrier": 3},
        {"observe_h2_ping": True},
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
{record("grpc-default", ports[0])}{record("grpc-max-connections", ports[1], "      max-connections: 2\n      min-streams: 2\n")}{record("grpc-max-streams", ports[2], "      max-connections: 0\n      max-streams: 1\n")}{record("grpc-ping", ports[3], "      ping-interval: 1\n")}
rules:
  - DST-PORT,29001,grpc-default
  - DST-PORT,29002,grpc-max-connections
  - DST-PORT,29003,grpc-max-streams
  - DST-PORT,29004,grpc-ping
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        default = run_concurrent(mixed_port, 29001, 3, authorities[0][1])
        bounded_connections = run_concurrent(mixed_port, 29002, 4, authorities[1][1])
        bounded_streams = run_concurrent(mixed_port, 29003, 3, authorities[2][1])
        ping_first = exchange(mixed_port, "ping-first.phase6d", 29004, b"ping-first")
        ping_observed = wait_for_ping(authorities[3][1])
        ping_second = exchange(mixed_port, "ping-second.phase6d", 29004, b"ping-second")
        return {
            "default": {
                "connections": connection_count(authorities[0][1], 1),
                "exchanges": default,
            },
            "max-connections-min-streams": {
                "connections": connection_count(authorities[1][1], 2),
                "exchanges": bounded_connections,
            },
            "max-streams": {
                "connections": connection_count(authorities[2][1], 3),
                "exchanges": bounded_streams,
            },
            "ping-reuse": {
                "connections": connection_count(authorities[3][1], 1),
                "exchanges": [ping_first, ping_second],
                "ping": ping_observed,
            },
            "process-alive": process.poll() is None,
            "signed-options-accepted": config_validation(
                binary,
                scratch,
                f"""proxies:
{record("grpc-signed", ports[0], "      ping-interval: -1\n      max-connections: -1\n      min-streams: -1\n      max-streams: -1\n")}""",
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
    with tempfile.TemporaryDirectory(prefix="phase6d-vmess-grpc-pool-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6DJVMESS_CARGO_TARGET", "phase6d-j-vmess")
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
    print("Phase 6D-J VMess gRPC/Gun pool differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

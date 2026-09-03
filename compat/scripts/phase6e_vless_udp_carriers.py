#!/usr/bin/env python3
"""Go/Rust differential for common VLESS UDP TLS, WebSocket and Gun carriers."""

from __future__ import annotations

import json
import pathlib
import socket
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase6d_vmess_websocket import trusted_roots
from phase6e_vless_tcp import vless_record
from phase6e_vless_udp import exchange
from phase6e_vless_websocket import build_authority, start_authority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-udp-carriers-diff.json"


def wait_exchange(
    process: Any,
    client: socket.socket,
    mixed_port: int,
    host: str,
    port: int,
    payload: bytes,
) -> bool:
    deadline = time.monotonic() + IO_DEADLINE
    client.settimeout(0.25)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during VLESS UDP carrier readiness: {process.returncode}")
        try:
            if exchange(client, mixed_port, host, port, payload):
                client.settimeout(IO_DEADLINE)
                return True
        except TimeoutError:
            pass
        time.sleep(0.02)
    raise TimeoutError("VLESS UDP carrier did not become ready")


def wait_observations(authorities: list[tuple[Any, pathlib.Path]], expected: set[str]) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed: set[str] = set()
        for process, output in authorities:
            if process.poll() is not None:
                raise RuntimeError("VLESS UDP carrier authority exited")
            observed.update(
                line.strip()
                for line in output.read_text(errors="replace").splitlines()
                if line.startswith(("TLS ", "ALPN ", "WS ", "GRPC ", "PACKET "))
            )
        if expected <= observed:
            return sorted(expected)
        time.sleep(0.02)
    raise TimeoutError(f"missing VLESS UDP carrier observations: {sorted(expected - observed)}")


def record(name: str, port: int, network: str, *, tls: bool, options: str = "") -> str:
    tls_fields = ""
    if tls:
        tls_fields = "    tls: true\n    servername: dot.phase4.test\n"
    return vless_record(
        name,
        port,
        network=network,
        extra=f"    udp: true\n    packet-encoding: xudp\n{tls_fields}{options}",
    )


def exercise(binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    ports = {name: reserve_port() for name in ("tls", "ws", "grpc")}
    specs = [
        (
            "tls",
            dict(
                transport="tcp",
                certificate=pathlib.Path(SERVER_CERTIFICATE),
                private_key=pathlib.Path(SERVER_KEY),
                packet_mode="xudp",
            ),
        ),
        (
            "ws",
            dict(
                transport="ws",
                expected_ws_host="udp-ws.phase6e",
                expected_ws_path="/udp",
                packet_mode="xudp",
            ),
        ),
        (
            "grpc",
            dict(
                transport="grpc",
                certificate=pathlib.Path(SERVER_CERTIFICATE),
                private_key=pathlib.Path(SERVER_KEY),
                expected_http_host="dot.phase4.test",
                expected_http_path="/udp/Tun",
                expected_grpc_user_agent="phase6e-udp/1.0",
                packet_mode="xudp",
            ),
        ),
    ]
    authorities: list[tuple[Any, pathlib.Path]] = []
    handles = []
    for name, options in specs:
        process, stdout, stderr, output = start_authority(
            authority_binary,
            scratch,
            ports[name],
            log_name=f"authority-{name}",
            **options,
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
{record("vless-udp-tls", ports["tls"], "tcp", tls=True)}{record("vless-udp-ws", ports["ws"], "ws", tls=False, options="    ws-opts:\n      path: /udp\n      headers:\n        Host: udp-ws.phase6e\n")}{record("vless-udp-grpc", ports["grpc"], "grpc", tls=True, options="    grpc-opts:\n      grpc-service-name: udp\n      grpc-user-agent: phase6e-udp/1.0\n")}rules:
  - DST-PORT,28401,vless-udp-tls
  - DST-PORT,28402,vless-udp-ws
  - DST-PORT,28403,vless-udp-grpc
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    clients: list[socket.socket] = []
    try:
        wait_ready(process, mixed_port)
        for _ in range(3):
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.bind(("127.0.0.1", 0))
            clients.append(client)
        matrix = {
            "tls": wait_exchange(process, clients[0], mixed_port, "192.0.2.91", 28401, b"udp-tls"),
            "websocket": wait_exchange(
                process, clients[1], mixed_port, "192.0.2.92", 28402, bytes(range(256)) * 5
            ),
            "grpc": wait_exchange(
                process, clients[2], mixed_port, "192.0.2.93", 28403, bytes(range(256)) * 8
            ),
        }
        expected = {
            "TLS dot.phase4.test",
            "WS udp-ws.phase6e /udp",
            "ALPN h2",
            "GRPC POST dot.phase4.test /udp/Tun application/grpc phase6e-udp/1.0",
            "PACKET xudp 192.0.2.91:28401 7",
            "PACKET xudp 192.0.2.92:28402 1280",
            "PACKET xudp 192.0.2.93:28403 2048",
        }
        return {
            "matrix": matrix,
            "authority": wait_observations(authorities, expected),
            "process-alive": process.poll() is None,
        }
    finally:
        for client in clients:
            client.close()
        stop(process)
        stdout.close()
        stderr.close()
        for authority, authority_stdout, authority_stderr in handles:
            stop(authority)
            authority_stdout.close()
            authority_stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6e-vless-udp-carriers-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6EVLESSUDPCARRIERS_CARGO_TARGET", "phase6e-i-vless")
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
    print("Phase 6E-I VLESS UDP carrier differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

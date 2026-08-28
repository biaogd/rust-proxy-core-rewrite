#!/usr/bin/env python3
"""Go/Rust differential for Phase 5F2 local UDP NAT sessions."""

from __future__ import annotations

import json
import os
import pathlib
import signal
import socket
import socketserver
import tempfile
import threading
import time
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import decode_socks_udp, launch, socks_udp_packet, stop, wait_route
from phase5b1a import build_binaries, debug_files


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5f-udp-nat-diff.json"


class NatUdpServer(socketserver.ThreadingUDPServer):
    daemon_threads = True

    def __init__(self) -> None:
        self.observed: list[tuple[bytes, int]] = []
        self.observed_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), NatUdpHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def record(self, payload: bytes, source_port: int) -> None:
        with self.observed_lock:
            self.observed.append((payload, source_port))

    def source_port(self, payload: bytes) -> int:
        with self.observed_lock:
            matches = [port for current, port in self.observed if current == payload]
        if not matches:
            raise AssertionError(f"authority did not receive {payload!r}")
        return matches[-1]

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=IO_DEADLINE)


class NatUdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        payload, stream = self.request
        server = self.server
        if not isinstance(server, NatUdpServer):
            raise AssertionError("unexpected UDP server")
        server.record(payload, int(self.client_address[1]))
        if payload == b"burst":
            stream.sendto(b"burst-one", self.client_address)
            stream.sendto(b"burst-two", self.client_address)
        else:
            stream.sendto(payload, self.client_address)


def write_config(
    path: pathlib.Path, socks_port: int, mixed_port: int, target: str
) -> None:
    path.write_text(
        f"""socks-port: {socks_port}
mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,{target}
"""
    )


def receive_payload(client: socket.socket) -> bytes:
    packet, _ = client.recvfrom(65_535)
    address, _, payload = decode_socks_udp(packet)
    if address != "127.0.0.1":
        raise AssertionError(f"unexpected response address {address}")
    return payload


def round_trip(
    client: socket.socket, proxy_port: int, destination_port: int, payload: bytes
) -> bytes:
    deadline = time.monotonic() + (2 * IO_DEADLINE) + 1
    while time.monotonic() < deadline:
        client.sendto(
            socks_udp_packet(destination_port, payload),
            ("127.0.0.1", proxy_port),
        )
        try:
            return receive_payload(client)
        except TimeoutError:
            continue
    raise TimeoutError(f"UDP session did not return {payload!r}")


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority = NatUdpServer()
    tcp_echo = start_server(EchoHandler)
    socks_port, mixed_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    write_config(config, socks_port, mixed_port, "DIRECT")
    process, stdout, stderr = launch(binary, config, scratch)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(0.4)
    fixed_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fixed_client.bind(("127.0.0.1", 0))
    fixed_client.settimeout(0.4)
    try:
        wait_ready(process, socks_port)
        wait_ready(process, mixed_port)
        first = round_trip(client, mixed_port, authority.port, b"first")
        second = round_trip(client, mixed_port, authority.port, b"second")
        first_source = authority.source_port(b"first")
        second_source = authority.source_port(b"second")
        fixed_first = round_trip(
            fixed_client, socks_port, authority.port, b"fixed-first"
        )
        fixed_second = round_trip(
            fixed_client, socks_port, authority.port, b"fixed-second"
        )
        fixed_first_source = authority.source_port(b"fixed-first")
        fixed_second_source = authority.source_port(b"fixed-second")

        client.sendto(
            socks_udp_packet(authority.port, b"burst"),
            ("127.0.0.1", mixed_port),
        )
        burst = [receive_payload(client), receive_payload(client)]

        write_config(config, socks_port, mixed_port, "REJECT")
        os.kill(process.pid, signal.SIGHUP)
        wait_route(process, mixed_port, tcp_echo.port, "reject")
        retained = round_trip(client, mixed_port, authority.port, b"retained")
        fixed_retained = round_trip(
            fixed_client, socks_port, authority.port, b"fixed-retained"
        )

        fresh = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fresh.bind(("127.0.0.1", 0))
        fresh.settimeout(0.4)
        try:
            fresh.sendto(
                socks_udp_packet(authority.port, b"fresh"),
                ("127.0.0.1", mixed_port),
            )
            try:
                fresh.recvfrom(65_535)
                fresh_result = "responded"
            except TimeoutError:
                fresh_result = "rejected"
        finally:
            fresh.close()

        return {
            "sequential": {
                "mixed": [first.decode(), second.decode()],
                "fixed": [fixed_first.decode(), fixed_second.decode()],
            },
            "outbound-port-reused": {
                "mixed": first_source == second_source,
                "fixed": fixed_first_source == fixed_second_source,
            },
            "burst": [payload.decode() for payload in burst],
            "reload": {
                "existing-session": retained.decode(),
                "existing-fixed-session": fixed_retained.decode(),
                "new-session": fresh_result,
            },
        }
    finally:
        client.close()
        fixed_client.close()
        stop(process)
        stdout.close()
        stderr.close()
        authority.close()
        tcp_echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5f-udp-nat-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5FUDPNAT_CARGO_TARGET", "phase5f-udp-nat")
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
    print("Phase 5F2 UDP NAT session differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

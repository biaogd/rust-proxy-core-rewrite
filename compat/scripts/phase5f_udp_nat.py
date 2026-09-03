#!/usr/bin/env python3
"""Go/Rust differential for Phase 5F2 local UDP NAT sessions."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import socketserver
import tempfile
import threading
import time
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reload_via_controller, reserve_port, start_server, wait_ready
from phase3 import (
    decode_socks_udp,
    launch,
    socks_udp_packet,
    stop,
    udp_associate,
    wait_route,
)
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


class NatUdpServerV6(NatUdpServer):
    address_family = socket.AF_INET6

    def __init__(self) -> None:
        self.observed = []
        self.observed_lock = threading.Lock()
        socketserver.ThreadingUDPServer.__init__(self, ("::1", 0), NatUdpHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()


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
    path: pathlib.Path,
    socks_port: int,
    mixed_port: int,
    controller_port: int,
    target: str,
) -> None:
    path.write_text(
        f"""socks-port: {socks_port}
mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
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


def socks_udp_packet_v6(destination_port: int, payload: bytes) -> bytes:
    return (
        b"\x00\x00\x00\x04"
        + socket.inet_pton(socket.AF_INET6, "::1")
        + destination_port.to_bytes(2, "big")
        + payload
    )


def receive_payload_v6(client: socket.socket) -> bytes:
    packet, _ = client.recvfrom(65_535)
    if len(packet) < 22 or packet[:4] != b"\x00\x00\x00\x04":
        raise AssertionError(f"unexpected IPv6 SOCKS UDP response: {packet!r}")
    if socket.inet_ntop(socket.AF_INET6, packet[4:20]) != "::1":
        raise AssertionError(f"unexpected IPv6 response address: {packet!r}")
    return packet[22:]


def round_trip_v6(
    client: socket.socket, proxy_port: int, destination_port: int, payload: bytes
) -> bytes:
    deadline = time.monotonic() + (2 * IO_DEADLINE) + 1
    while time.monotonic() < deadline:
        client.sendto(
            socks_udp_packet_v6(destination_port, payload),
            ("::1", proxy_port),
        )
        try:
            response = receive_payload_v6(client)
            if response == payload:
                return response
        except TimeoutError:
            continue
    raise TimeoutError(f"IPv6 UDP session did not return {payload!r}")


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
            response = receive_payload(client)
            if response == payload:
                return response
        except TimeoutError:
            continue
    raise TimeoutError(f"UDP session did not return {payload!r}")


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority = NatUdpServer()
    second_authority = NatUdpServer()
    tcp_echo = start_server(EchoHandler)
    socks_port, mixed_port, controller_port = reserve_port(), reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    write_config(config, socks_port, mixed_port, controller_port, "DIRECT")
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
        association, _, _ = udp_associate(mixed_port)
        first = round_trip(client, mixed_port, authority.port, b"first")
        association.close()
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
        fanout = round_trip(client, mixed_port, second_authority.port, b"fanout")
        fanout_source = second_authority.source_port(b"fanout")

        client.sendto(
            socks_udp_packet(authority.port, b"burst"),
            ("127.0.0.1", mixed_port),
        )
        burst = [receive_payload(client), receive_payload(client)]

        for index in range(256):
            client.sendto(
                socks_udp_packet(authority.port, f"pressure-{index}".encode()),
                ("127.0.0.1", mixed_port),
            )
        pressure = round_trip(client, mixed_port, authority.port, b"pressure-marker")

        timeout_result = "ci-slow-gate-disabled"
        if os.environ.get("PHASE5F_TIMEOUT_TEST") == "1":
            timeout_before = authority.source_port(b"pressure-marker")
            time.sleep(62)
            expired = round_trip(client, mixed_port, authority.port, b"after-timeout")
            timeout_after = authority.source_port(b"after-timeout")
            if expired != b"after-timeout" or timeout_before == timeout_after:
                raise AssertionError(
                    "UDP NAT entry did not expire and recreate after the idle deadline"
                )
            timeout_result = "expired-and-recreated"

        # Keep the fixed-listener session demonstrably active immediately
        # before reload. Under a contended CI host, the mixed-listener pressure
        # loop can otherwise consume the 60-second NAT idle lifetime and turn
        # this into a new-session REJECT test instead of a generation-retention
        # test.
        round_trip(
            fixed_client, socks_port, authority.port, b"fixed-before-reload"
        )
        write_config(config, socks_port, mixed_port, controller_port, "REJECT")
        reload_via_controller(process, controller_port, config)
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
                "across-destinations": first_source == fanout_source,
            },
            "control-close-retains-session": second.decode(),
            "destination-fanout": fanout.decode(),
            "burst": [payload.decode() for payload in burst],
            "bounded-pressure": "survived" if pressure == b"pressure-marker" else "failed",
            "idle-timeout": timeout_result,
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
        second_authority.close()
        tcp_echo.close()


def exercise_ipv6(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority = NatUdpServerV6()
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
ipv6: true
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    client.bind(("::1", 0))
    client.settimeout(IO_DEADLINE)
    try:
        wait_ready(process, mixed_port)
        payloads = []
        sources = []
        for payload in (b"ipv6-first", b"ipv6-second"):
            payloads.append(
                round_trip_v6(client, mixed_port, authority.port, payload).decode()
            )
            sources.append(authority.source_port(payload))
        return {
            "payloads": payloads,
            "outbound-port-reused": sources[0] == sources[1],
        }
    finally:
        client.close()
        stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5f-udp-nat-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5FUDPNAT_CARGO_TARGET", "phase5f-udp-nat")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                ipv4 = scratch / "ipv4"
                ipv6 = scratch / "ipv6"
                ipv4.mkdir()
                ipv6.mkdir()
                observations[name] = {
                    "ipv4": exercise(binary, ipv4),
                    "ipv6": exercise_ipv6(binary, ipv6),
                }
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

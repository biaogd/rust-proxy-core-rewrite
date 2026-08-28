#!/usr/bin/env python3
"""Go/Rust differential for SOCKS5 UDP ASSOCIATE."""

from __future__ import annotations

import ipaddress
import hashlib
import json
import socket
import socketserver
import ssl
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port, wait_ready
from phase3 import decode_socks_udp, launch, socks_udp_packet, stop
from phase5b1a import build_binaries, debug_files
from phase5d_proxies import normalize, request
from phase5d_streams import wait_controller
from phase6b_tls_identity import server_certificates


FAILURE_ARTIFACT = ROOT / "compat/artifacts/phase6b-socks5-udp-diff.json"


def decode_address(packet: bytes, offset: int) -> tuple[str, int, int, int]:
    address_type = packet[offset]
    if address_type == 1:
        host = str(ipaddress.ip_address(packet[offset + 1 : offset + 5]))
        port_offset = offset + 5
    elif address_type == 4:
        host = str(ipaddress.ip_address(packet[offset + 1 : offset + 17]))
        port_offset = offset + 17
    elif address_type == 3:
        length = packet[offset + 1]
        host = packet[offset + 2 : offset + 2 + length].decode()
        port_offset = offset + 2 + length
    else:
        raise AssertionError(f"unsupported address type {address_type}")
    port = int.from_bytes(packet[port_offset : port_offset + 2], "big")
    return host, port, port_offset + 2, address_type


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        packet, _ = self.request
        if len(packet) < 4 or packet[:3] != b"\x00\x00\x00":
            return
        host, port, payload_offset, address_type = decode_address(packet, 3)
        self.server.observations.append(
            {
                "address-type": address_type,
                "host": host,
                "destination-port": port,
                "payload": packet[payload_offset:].decode(),
            }
        )
        self.server.socket.sendto(packet, self.client_address)


class RelayServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), RelayHandler)
        self.observations: list[dict[str, Any]] = []
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=IO_DEADLINE)


class ControlHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(IO_DEADLINE)
        version, count = recv_exact(self.request, 2)
        methods = list(recv_exact(self.request, count))
        observation: dict[str, Any] = {"version": version, "methods": methods}
        observation["tls"] = isinstance(self.request, ssl.SSLSocket)
        self.server.observations.append(observation)
        self.request.sendall(b"\x05\x02")
        auth_version, username_length = recv_exact(self.request, 2)
        username = recv_exact(self.request, username_length).decode()
        password_length = recv_exact(self.request, 1)[0]
        password = recv_exact(self.request, password_length).decode()
        observation.update(
            {
                "auth-version": auth_version,
                "username": username,
                "password": password,
            }
        )
        self.request.sendall(b"\x01\x00")
        request = recv_exact(self.request, 4)
        host, port, _, address_type = decode_address(
            request + recv_exact(self.request, 6), 3
        )
        observation.update(
            {
                "request": list(request[:3]),
                "address-type": address_type,
                "host": host,
                "port": port,
            }
        )
        relay_port = self.server.relay.port
        self.request.sendall(
            b"\x05\x00\x00\x01\x00\x00\x00\x00" + relay_port.to_bytes(2, "big")
        )
        try:
            while self.request.recv(4096):
                pass
        except (OSError, TimeoutError):
            pass


class ControlServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, relay: RelayServer, context: ssl.SSLContext | None = None) -> None:
        self.relay = relay
        self.context = context
        self.server_names: list[str | None] = []
        if context is not None:
            context.set_servername_callback(
                lambda _socket, name, _context: self.server_names.append(name)
            )
        self.observations: list[dict[str, Any]] = []
        super().__init__(("127.0.0.1", 0), ControlHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def get_request(self):
        stream, address = super().get_request()
        if self.context is None:
            return stream, address
        try:
            return self.context.wrap_socket(stream, server_side=True), address
        except Exception:
            stream.close()
            raise

    def handle_error(self, _request, _client_address) -> None:
        pass

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=IO_DEADLINE)


def exchange(mixed_port: int, destination_port: int, payload: bytes) -> tuple[str, int, bytes]:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(IO_DEADLINE)
    try:
        return exchange_on(client, mixed_port, destination_port, payload)
    finally:
        client.close()


def exchange_on(
    client: socket.socket,
    mixed_port: int,
    destination_port: int,
    payload: bytes,
) -> tuple[str, int, bytes]:
    client.sendto(socks_udp_packet(destination_port, payload), ("127.0.0.1", mixed_port))
    packet, _ = client.recvfrom(65_535)
    return decode_socks_udp(packet)


def wait_route(process: Any, mixed_port: int, destination_port: int) -> None:
    deadline = time.monotonic() + (2 * IO_DEADLINE)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during UDP readiness with {process.returncode}")
        try:
            if exchange(mixed_port, destination_port, b"ready")[2] == b"ready":
                return
        except (OSError, AssertionError):
            time.sleep(0.02)
    raise TimeoutError("SOCKS5 UDP outbound did not become ready")


def exercise(
    binary: Path,
    scratch: Path,
    material: dict[str, Path] | None = None,
) -> dict[str, Any]:
    relay = RelayServer()
    context = None
    tls_options = ""
    if material is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(material["server"], material["server-key"])
        server_der = ssl.PEM_cert_to_DER_cert(material["server"].read_text())
        if isinstance(server_der, str):
            server_der = server_der.encode("latin1")
        fingerprint = hashlib.sha256(server_der).hexdigest()
        tls_options = f'\n    tls: true\n    fingerprint: "{fingerprint}"'
    control = ControlServer(relay, context)
    mixed_port, controller_port = reserve_port(), reserve_port()
    first_port, second_port = 32_001, 32_002
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: udp-socks
    type: socks5
    server: 127.0.0.1
    port: {control.port}
    username: udp-user
    password: udp-pass
    udp: true
{tls_options}
rules:
  - MATCH,udp-socks
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_route(process, mixed_port, first_port)
        relay.observations.clear()
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(IO_DEADLINE)
        try:
            first = exchange_on(client, mixed_port, first_port, b"first")
            second = exchange_on(client, mixed_port, second_port, b"second")
        finally:
            client.close()
        code, body = request(controller_port, "GET", "/proxies/udp-socks")
        view = normalize(json.loads(body))
        return {
            "alive": process.poll() is None,
            "control": control.observations[-1],
            "sni": sorted({str(name) for name in control.server_names}),
            "relay": relay.observations,
            "responses": [
                [first[0], first[1] == first_port, first[2].decode()],
                [second[0], second[1] == second_port, second[2].decode()],
            ],
            "view": [code, view["type"], view["udp"], view["uot"]],
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        control.close()
        relay.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6b-socks5-udp-") as temporary:
        root = Path(temporary)
        material = server_certificates(root)
        binaries = build_binaries(root, "PHASE6BSOCKSUDP_CARGO_TARGET", "phase6b-socks5-udp")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                plaintext = scratch / "plaintext"
                tls = scratch / "tls"
                plaintext.mkdir()
                tls.mkdir()
                observations[name] = {
                    "plaintext": exercise(binary, plaintext),
                    "tls": exercise(binary, tls, material),
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
    print("Phase 6B SOCKS5 UDP ASSOCIATE differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

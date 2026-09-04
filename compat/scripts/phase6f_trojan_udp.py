#!/usr/bin/env python3
"""Go/Rust differential for Phase 6F-B Trojan UDP over native TLS."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import pathlib
import socket
import socketserver
import ssl
import tempfile
import textwrap
import threading
from typing import Any

from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_udp import decode_socks_udp, socks_udp_packet, wait_exchange


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6f-trojan-udp-diff.json"
PASSWORD = "phase6f-udp-password"


def read_address(stream: socket.socket) -> tuple[str, int, bytes]:
    address_type = recv_exact(stream, 1)[0]
    if address_type == 1:
        raw = recv_exact(stream, 4)
        host = str(ipaddress.ip_address(raw))
    elif address_type == 4:
        raw = recv_exact(stream, 16)
        host = str(ipaddress.ip_address(raw))
    elif address_type == 3:
        raw = recv_exact(stream, recv_exact(stream, 1)[0])
        host = raw.decode("ascii")
    else:
        raise ValueError(f"invalid address type {address_type}")
    port_bytes = recv_exact(stream, 2)
    return host, int.from_bytes(port_bytes, "big"), bytes([address_type]) + (
        bytes([len(raw)]) + raw if address_type == 3 else raw
    ) + port_bytes


class TrojanUdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        stream: socket.socket = self.request
        authority: TrojanUdpAuthority = self.server.authority
        try:
            password = recv_exact(stream, 56).decode()
            if recv_exact(stream, 2) != b"\r\n":
                return
            command = recv_exact(stream, 1)[0]
            initial_host, initial_port, _ = read_address(stream)
            if recv_exact(stream, 2) != b"\r\n":
                return
            authority.observe(f"ASSOCIATE {initial_host}:{initial_port} COMMAND {command}")
            if password != hashlib.sha224(PASSWORD.encode()).hexdigest() or command != 3:
                return
            while True:
                host, port, encoded_address = read_address(stream)
                length = int.from_bytes(recv_exact(stream, 2), "big")
                if length > 8192 or recv_exact(stream, 2) != b"\r\n":
                    return
                payload = recv_exact(stream, length)
                authority.observe(f"PACKET {host}:{port} {len(payload)}")
                stream.sendall(
                    encoded_address
                    + len(payload).to_bytes(2, "big")
                    + b"\r\n"
                    + payload
                )
        except (EOFError, OSError, UnicodeError, ValueError):
            return


class TrojanUdpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, authority: "TrojanUdpAuthority") -> None:
        self.authority = authority
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        self.context.set_alpn_protocols(["h2", "http/1.1"])
        super().__init__(("127.0.0.1", 0), TrojanUdpHandler)

    def get_request(self) -> tuple[socket.socket, Any]:
        stream, address = super().get_request()
        return self.context.wrap_socket(stream, server_side=True), address


class TrojanUdpAuthority:
    def __init__(self) -> None:
        self.observations: set[str] = set()
        self.lock = threading.Lock()
        self.server = TrojanUdpServer(self)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def observe(self, value: str) -> None:
        with self.lock:
            self.observations.add(value)

    def snapshot(self) -> list[str]:
        with self.lock:
            return sorted(self.observations)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def roots() -> str:
    root = pathlib.Path(ROOT_CERTIFICATE).read_text().strip()
    return "tls:\n  custom-certifactes:\n    - |-\n" + textwrap.indent(root, "      ") + "\n"


def exchange(client: socket.socket, mixed_port: int, host: str, port: int, payload: bytes) -> bool:
    client.sendto(socks_udp_packet(host, port, payload), ("127.0.0.1", mixed_port))
    response, _ = client.recvfrom(65_535)
    response_host, response_port, response_payload = decode_socks_udp(response)
    return response_host == str(ipaddress.ip_address(host)) and response_port == port and response_payload == payload


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority = TrojanUdpAuthority()
    authority.start()
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(roots() + f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: trojan-udp
    type: trojan
    server: 127.0.0.1
    port: {authority.port}
    password: {PASSWORD}
    sni: dot.phase4.test
    udp: true
rules:
  - MATCH,trojan-udp
""")
    process, stdout, stderr = launch(binary, config, scratch)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(IO_DEADLINE)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        first = wait_exchange(process, client, mixed_port, "127.0.0.1", 28401, b"ready")
        second = exchange(client, mixed_port, "192.0.2.91", 28402, bytes(range(256)) * 12)
        status, body = request(controller_port, "GET", "/proxies/trojan-udp")
        snapshot = json.loads(body)
        return {
            "first": first,
            "same-association-target-change": second,
            "controller": {
                "status": status,
                "type": snapshot["type"],
                "udp": snapshot["udp"],
                "uot": snapshot["uot"],
                "xudp": snapshot["xudp"],
            },
            "wire": authority.snapshot(),
            "process-alive": process.poll() is None,
        }
    finally:
        client.close()
        stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6f-trojan-udp-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6FTROJANUDP_CARGO_TARGET", "phase6f-trojan-udp")
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], scratch)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(json.dumps({"error": f"{type(error).__name__}: {error}", "observations": observations, "debug": debug_files(root)}, indent=2, sort_keys=True))
            raise
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6F-B Trojan native-TLS UDP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

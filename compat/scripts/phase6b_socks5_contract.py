#!/usr/bin/env python3
"""Go/Rust differential for the SOCKS5 TCP handshake contract."""

from __future__ import annotations

import ipaddress
import json
import selectors
import socket
import socketserver
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, recv_exact, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6b-socks5-contract-diff.json"


def relay(left: socket.socket, right: socket.socket) -> None:
    poller = selectors.DefaultSelector()
    poller.register(left, selectors.EVENT_READ, right)
    poller.register(right, selectors.EVENT_READ, left)
    try:
        while True:
            events = poller.select(timeout=IO_DEADLINE)
            if not events:
                return
            for key, _ in events:
                data = key.fileobj.recv(65_536)
                if not data:
                    return
                key.data.sendall(data)
    finally:
        poller.close()


class ContractHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(IO_DEADLINE)
        observation: dict[str, Any] = {}
        self.server.observations.append(observation)
        try:
            version, count = recv_exact(self.request, 2)
            methods = list(recv_exact(self.request, count))
            observation.update({"greeting-version": version, "methods": methods})
            self.request.sendall(bytes((self.server.selection_version, self.server.method)))
            if self.server.method in (0xFF,) or self.server.selection_version != 5:
                return
            if self.server.method == 2:
                try:
                    auth_version, username_length = recv_exact(self.request, 2)
                except (EOFError, TimeoutError, OSError):
                    observation["auth-request"] = False
                    return
                username = recv_exact(self.request, username_length).decode()
                password_length = recv_exact(self.request, 1)[0]
                password = recv_exact(self.request, password_length).decode()
                observation.update(
                    {
                        "auth-request": True,
                        "auth-version": auth_version,
                        "username": username,
                        "password": password,
                    }
                )
                self.request.sendall(b"\x01\x00")
            try:
                request_version, command, reserved, address_type = recv_exact(self.request, 4)
            except (EOFError, TimeoutError, OSError):
                observation["connect-request"] = False
                return
            if address_type == 1:
                host = str(ipaddress.ip_address(recv_exact(self.request, 4)))
            elif address_type == 4:
                host = str(ipaddress.ip_address(recv_exact(self.request, 16)))
            elif address_type == 3:
                host = recv_exact(self.request, recv_exact(self.request, 1)[0]).decode()
            else:
                observation.update(
                    {"connect-request": True, "address-type": address_type}
                )
                return
            port = int.from_bytes(recv_exact(self.request, 2), "big")
            observation.update(
                {
                    "connect-request": True,
                    "request": [request_version, command, reserved],
                    "address-type": address_type,
                    "host": host,
                    "port": port,
                }
            )
            with socket.create_connection(self.server.echo_address, timeout=IO_DEADLINE) as upstream:
                self.request.sendall(
                    bytes((5, self.server.reply, 0, 1, 127, 0, 0, 1, 0, 0))
                )
                relay(self.request, upstream)
        except (EOFError, TimeoutError, OSError) as error:
            observation["fixture-error"] = type(error).__name__


class ContractServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        echo_address: tuple[str, int],
        *,
        method: int = 0,
        selection_version: int = 5,
        reply: int = 0,
    ) -> None:
        super().__init__(("127.0.0.1", 0), ContractHandler)
        self.echo_address = echo_address
        self.method = method
        self.selection_version = selection_version
        self.reply = reply
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


def connect_target(proxy_port: int, host: str, port: int) -> socket.socket:
    stream = socket.create_connection(("127.0.0.1", proxy_port), timeout=IO_DEADLINE)
    stream.settimeout(IO_DEADLINE)
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    stream.sendall(
        f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
    )
    response = bytearray()
    while b"\r\n\r\n" not in response:
        response.extend(stream.recv(4096))
    if b" 200 " not in response.split(b"\r\n", 1)[0]:
        stream.close()
        raise AssertionError(response)
    return stream


def route_result(proxy_port: int, host: str, port: int, payload: bytes) -> bool:
    try:
        with connect_target(proxy_port, host, port) as stream:
            stream.sendall(payload)
            return recv_exact(stream, len(payload)) == payload
    except (EOFError, TimeoutError, OSError, ConnectionResetError, BrokenPipeError):
        return False


def wait_contract_ready(process: Any, proxy_port: int, port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during SOCKS5 readiness with {process.returncode}")
        if route_result(proxy_port, "ready.example", port, b"ready"):
            return
        time.sleep(0.02)
    raise TimeoutError("SOCKS5 outbound did not become ready")


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    echo_address = ("127.0.0.1", int(echo.server.server_address[1]))
    servers = {
        "noauth": ContractServer(echo_address),
        "user-only": ContractServer(echo_address, method=2),
        "password-only": ContractServer(echo_address),
        "downgrade": ContractServer(echo_address),
        "unexpected-auth": ContractServer(echo_address, method=2),
        "no-method": ContractServer(echo_address, method=0xFF),
        "bad-version": ContractServer(echo_address, selection_version=4),
        "reply-five": ContractServer(echo_address, reply=5),
        "wire": ContractServer(echo_address),
    }
    destination_ports = {
        name: 31_001 + offset for offset, name in enumerate(servers)
    }
    wire_ports = {"domain": 31_020, "ipv4": 31_021, "ipv6": 31_022}
    mixed_port = reserve_port()
    proxy_lines = []
    rule_lines = []
    for name, server in servers.items():
        credentials = ""
        if name == "user-only":
            credentials = "\n    username: only-user"
        elif name == "password-only":
            credentials = "\n    password: ignored-password"
        elif name == "downgrade":
            credentials = "\n    username: downgrade-user\n    password: downgrade-pass"
        proxy_lines.append(
            f"  - name: {name}\n    type: socks5\n    server: 127.0.0.1\n"
            f"    port: {server.port}{credentials}"
        )
        if name != "wire":
            rule_lines.append(f"  - DST-PORT,{destination_ports[name]},{name}")
    for port in wire_ports.values():
        rule_lines.append(f"  - DST-PORT,{port},wire")
    rule_lines.append("  - MATCH,REJECT")
    config = scratch / "config.yaml"
    config.write_text(
        f"mixed-port: {mixed_port}\nmode: rule\nlog-level: info\nipv6: true\n"
        f"proxies:\n{'\n'.join(proxy_lines)}\nrules:\n{'\n'.join(rule_lines)}\n"
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_contract_ready(process, mixed_port, destination_ports["noauth"])
        servers["noauth"].observations.clear()
        outcomes = {
            name: route_result(
                mixed_port,
                f"{name}.example",
                destination_ports[name],
                name.encode(),
            )
            for name in servers
            if name != "wire"
        }
        outcomes.update(
            {
                "wire-domain": route_result(
                    mixed_port, "unresolved.example", wire_ports["domain"], b"domain"
                ),
                "wire-ipv4": route_result(
                    mixed_port, "198.51.100.7", wire_ports["ipv4"], b"ipv4"
                ),
                "wire-ipv6": route_result(
                    mixed_port, "2001:db8::7", wire_ports["ipv6"], b"ipv6"
                ),
            }
        )
        return {
            "alive": process.poll() is None,
            "outcomes": outcomes,
            "observations": {
                name: server.observations for name, server in servers.items()
            },
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        for server in servers.values():
            server.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6b-socks5-contract-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE6BSOCKSCONTRACT_CARGO_TARGET",
            "phase6b-socks5-contract",
        )
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
    print("Phase 6B SOCKS5 TCP handshake contract differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

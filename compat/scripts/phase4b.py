#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4B hosts and redir-host mapping."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, EchoHandler, recv_exact, reserve_port
from phase4 import build_binaries, launch, stop, wait_dns_ready


FIXTURE = ROOT / "compat" / "fixtures" / "phase4" / "hosts.yaml.tmpl"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4b-diff.json"


def encode_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def decode_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    next_offset: int | None = None
    seen: set[int] = set()
    while True:
        if offset in seen or offset >= len(message):
            raise ValueError("invalid DNS name")
        seen.add(offset)
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("truncated DNS pointer")
            if next_offset is None:
                next_offset = offset + 2
            offset = ((length & 0x3F) << 8) | message[offset + 1]
            continue
        offset += 1
        if length == 0:
            return ".".join(labels).lower(), next_offset or offset
        labels.append(message[offset : offset + length].decode().lower())
        offset += length


def make_query(name: str, record_type: int, identifier: int) -> bytes:
    return (
        identifier.to_bytes(2, "big")
        + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + encode_name(name)
        + record_type.to_bytes(2, "big")
        + b"\x00\x01"
    )


def parse_query(query: bytes) -> tuple[str, int, int]:
    name, offset = decode_name(query, 12)
    return name, int.from_bytes(query[offset : offset + 2], "big"), offset + 4


def parse_response(message: bytes, identifier: int) -> dict[str, Any]:
    questions = int.from_bytes(message[4:6], "big")
    answers = int.from_bytes(message[6:8], "big")
    offset = 12
    question_name = ""
    for _ in range(questions):
        question_name, offset = decode_name(message, offset)
        offset += 4
    records: list[dict[str, Any]] = []
    for _ in range(answers):
        owner, offset = decode_name(message, offset)
        record_type = int.from_bytes(message[offset : offset + 2], "big")
        record_class = int.from_bytes(message[offset + 2 : offset + 4], "big")
        ttl = int.from_bytes(message[offset + 4 : offset + 8], "big")
        data_length = int.from_bytes(message[offset + 8 : offset + 10], "big")
        data_offset = offset + 10
        if record_type == 1:
            data = socket.inet_ntop(socket.AF_INET, message[data_offset : data_offset + 4])
        elif record_type == 28:
            data = socket.inet_ntop(socket.AF_INET6, message[data_offset : data_offset + 16])
        elif record_type == 5:
            data, _ = decode_name(message, data_offset)
        else:
            data = message[data_offset : data_offset + data_length].hex()
        records.append(
            {
                "owner": owner,
                "type": record_type,
                "class": record_class,
                "ttl": ttl,
                "data": data,
            }
        )
        offset = data_offset + data_length
    return {
        "id-echoed": int.from_bytes(message[:2], "big") == identifier,
        "flags": message[2:4].hex(),
        "question": question_name,
        "records": records,
    }


class AuthorityState:
    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.questions: list[str] = []
        self.lock = threading.Lock()

    def respond(self, query: bytes) -> bytes:
        name, record_type, question_end = parse_query(query)
        with self.lock:
            self.questions.append(name)
        answer = b""
        count = 0
        if record_type == 1:
            answer = (
                b"\xc0\x0c\x00\x01\x00\x01"
                + (30).to_bytes(4, "big")
                + b"\x00\x04"
                + socket.inet_aton(self.answer)
            )
            count = 1
        return (
            query[:2]
            + b"\x81\x80\x00\x01"
            + count.to_bytes(2, "big")
            + b"\x00\x00\x00\x00"
            + query[12:question_end]
            + answer
        )

    def snapshot(self) -> list[str]:
        with self.lock:
            return list(self.questions)


class AuthorityServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class AuthorityHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, server_socket = self.request
        state: AuthorityState = self.server.state  # type: ignore[attr-defined]
        server_socket.sendto(state.respond(query), self.client_address)


class AllInterfacesServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def udp_query(port: int, query: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(IO_DEADLINE)
        client.sendto(query, ("127.0.0.1", port))
        return client.recvfrom(65535)[0]


def local_interface_ip() -> str | None:
    if sys.platform == "darwin":
        for interface in ("en0", "en1"):
            result = subprocess.run(
                ["ipconfig", "getifaddr", interface],
                text=True,
                capture_output=True,
                check=False,
            )
            address = result.stdout.strip()
            if result.returncode == 0 and address and not address.startswith("127."):
                return address
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(("192.0.2.1", 9))
            address = str(probe.getsockname()[0])
        except OSError:
            return None
    return None if address.startswith("127.") else address


def system_host_candidate() -> tuple[str, str] | None:
    try:
        lines = pathlib.Path("/etc/hosts").read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        try:
            socket.inet_aton(fields[0])
        except OSError:
            continue
        for name in fields[1:]:
            if name.lower() != "localhost":
                return name.lower(), fields[0]
    return None


def socks5_connect(proxy_port: int, address: str, destination_port: int) -> socket.socket:
    stream = socket.create_connection(("127.0.0.1", proxy_port), timeout=IO_DEADLINE)
    stream.settimeout(IO_DEADLINE)
    stream.sendall(b"\x05\x01\x00")
    if recv_exact(stream, 2) != b"\x05\x00":
        raise AssertionError("SOCKS5 method negotiation failed")
    stream.sendall(
        b"\x05\x01\x00\x01"
        + socket.inet_aton(address)
        + destination_port.to_bytes(2, "big")
    )
    reply = recv_exact(stream, 4)
    if reply[:2] != b"\x05\x00":
        raise AssertionError(f"SOCKS5 CONNECT failed: {reply.hex()}")
    address_length = {1: 4, 4: 16}.get(reply[3])
    if address_length is None:
        address_length = recv_exact(stream, 1)[0]
    recv_exact(stream, address_length + 2)
    return stream


def wait_redir_host_echo(proxy_port: int, address: str, destination_port: int) -> str:
    deadline = time.monotonic() + IO_DEADLINE
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            with socks5_connect(proxy_port, address, destination_port) as stream:
                stream.settimeout(min(0.5, max(0.05, deadline - time.monotonic())))
                stream.sendall(b"mapped")
                return recv_exact(stream, 6).decode()
        except (EOFError, OSError, TimeoutError) as error:
            last_error = error
            time.sleep(0.02)
    raise AssertionError("redir-host mapping did not become observable") from last_error


def render_config(path: pathlib.Path, mixed_port: int, dns_port: int, upstream_port: int) -> None:
    path.write_text(
        FIXTURE.read_text()
        .replace("${MIXED_PORT}", str(mixed_port))
        .replace("${DNS_PORT}", str(dns_port))
        .replace("${UPSTREAM_PORT}", str(upstream_port))
    )


def config_validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    valid = scratch / "validation.yaml"
    render_config(valid, reserve_port(), reserve_port(), reserve_port())
    cycle = scratch / "cycle.yaml"
    source = valid.read_text()
    hosts_start = source.index("hosts:\n")
    dns_start = source.index("dns:\n")
    cycle.write_text(
        source[:hosts_start]
        + "hosts:\n  one.phase4.test: two.phase4.test\n"
        + "  two.phase4.test: one.phase4.test\n"
        + source[dns_start:]
    )
    return {
        "valid": subprocess.run(
            [str(binary), "-t", "-f", str(valid)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode,
        "cycle": subprocess.run(
            [str(binary), "-t", "-f", str(cycle)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode,
    }


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    interface_ip = local_interface_ip() or "192.0.2.42"
    authority_state = AuthorityState(interface_ip)
    authority = AuthorityServer(("127.0.0.1", 0), AuthorityHandler)
    authority.state = authority_state  # type: ignore[attr-defined]
    authority_thread = threading.Thread(target=authority.serve_forever, daemon=True)
    authority_thread.start()

    echo: AllInterfacesServer | None = None
    echo_thread: threading.Thread | None = None
    if local_interface_ip() is not None:
        echo = AllInterfacesServer(("0.0.0.0", 0), EchoHandler)
        echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
        echo_thread.start()

    dns_port = reserve_port()
    mixed_port = reserve_port()
    while mixed_port == dns_port:
        mixed_port = reserve_port()
    config = scratch / "config.yaml"
    render_config(config, mixed_port, dns_port, authority.server_address[1])
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        observation: dict[str, Any] = {}
        cases = [
            ("fixed-a", "fixed.phase4.test", 1, 0x5101),
            ("fixed-aaaa", "fixed.phase4.test", 28, 0x5102),
            ("cname-only", "alias.phase4.test", 5, 0x5103),
            ("alias-a", "alias.phase4.test", 1, 0x5104),
            ("alias-a-cached", "alias.phase4.test", 1, 0x5105),
        ]
        for label, name, record_type, identifier in cases:
            observation[label] = parse_response(
                udp_query(dns_port, make_query(name, record_type, identifier)),
                identifier,
            )

        candidate = system_host_candidate()
        if candidate is None:
            observation["system-host"] = {"available": False}
        else:
            name, expected = candidate
            response = parse_response(
                udp_query(dns_port, make_query(name, 1, 0x5106)), 0x5106
            )
            observation["system-host"] = {
                "available": True,
                "name": name,
                "expected": expected,
                "response": response,
            }

        if echo is None:
            observation["redir-host"] = "skipped-no-nonloopback-interface"
        else:
            udp_query(
                dns_port,
                make_query("mapped.phase4.test", 1, 0x5107),
            )
            observation["redir-host"] = wait_redir_host_echo(
                mixed_port, interface_ip, echo.server_address[1]
            )

        observation["upstream-questions"] = authority_state.snapshot()
        observation["exit-code"] = stop(process)
        return observation
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.shutdown()
        authority.server_close()
        authority_thread.join(timeout=IO_DEADLINE)
        if echo is not None:
            echo.shutdown()
            echo.server_close()
        if echo_thread is not None:
            echo_thread.join(timeout=IO_DEADLINE)


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4b-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations: dict[str, Any] = {}
        for implementation, binary in binaries.items():
            scratch = root / implementation
            scratch.mkdir()
            observations[implementation] = {
                "config": config_validation(binary, scratch),
                "runtime": exercise(binary, scratch / "run"),
            }
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4B mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4B Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

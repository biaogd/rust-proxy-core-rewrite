#!/usr/bin/env python3
"""Local Go/Rust differential suite for the Phase 4A classic DNS gate."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import (
    IO_DEADLINE,
    ROOT,
    RUST_ROOT,
    assert_go_oracle_baseline,
    cargo_target_path,
    terminate_process,
    reserve_port,
)


FIXTURE = ROOT / "compat" / "fixtures" / "phase4" / "dns.yaml.tmpl"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4-diff.json"
ANSWER = "192.0.2.42"
ANSWER_TTL = 30


class AuthorityState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counts = {"udp": 0, "tcp": 0}

    def answer(self, query: bytes, transport: str) -> bytes:
        with self._lock:
            self.counts[transport] += 1
        question_end = dns_question_end(query)
        header = (
            query[:2]
            + b"\x81\x80"
            + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        )
        answer = (
            b"\xc0\x0c\x00\x01\x00\x01"
            + ANSWER_TTL.to_bytes(4, "big")
            + b"\x00\x04"
            + socket.inet_aton(ANSWER)
        )
        return header + query[12:question_end] + answer

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self.counts)


class UDPAuthority(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class TCPAuthority(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPAuthorityHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, server_socket = self.request
        state: AuthorityState = self.server.state  # type: ignore[attr-defined]
        server_socket.sendto(state.answer(query, "udp"), self.client_address)


class TCPAuthorityHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        state: AuthorityState = self.server.state  # type: ignore[attr-defined]
        while True:
            try:
                length = recv_exact(self.request, 2)
            except (EOFError, OSError):
                return
            query = recv_exact(self.request, int.from_bytes(length, "big"))
            response = state.answer(query, "tcp")
            self.request.sendall(len(response).to_bytes(2, "big") + response)


class LocalAuthority:
    def __init__(self) -> None:
        self.state = AuthorityState()
        self.tcp = TCPAuthority(("127.0.0.1", 0), TCPAuthorityHandler)
        self.port = self.tcp.server_address[1]
        self.udp = UDPAuthority(("127.0.0.1", self.port), UDPAuthorityHandler)
        self.tcp.state = self.state  # type: ignore[attr-defined]
        self.udp.state = self.state  # type: ignore[attr-defined]
        self.threads = [
            threading.Thread(target=self.tcp.serve_forever, daemon=True),
            threading.Thread(target=self.udp.serve_forever, daemon=True),
        ]
        for thread in self.threads:
            thread.start()

    def close(self) -> None:
        self.tcp.shutdown()
        self.udp.shutdown()
        self.tcp.server_close()
        self.udp.server_close()
        for thread in self.threads:
            thread.join(timeout=IO_DEADLINE)


def recv_exact(stream: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise EOFError(f"expected {length} bytes, received {len(result)}")
        result.extend(chunk)
    return bytes(result)


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def dns_query(name: str, identifier: int) -> bytes:
    return (
        identifier.to_bytes(2, "big")
        + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + dns_name(name)
        + b"\x00\x01\x00\x01"
    )


def dns_question_end(message: bytes) -> int:
    offset = 12
    while True:
        length = message[offset]
        offset += 1
        if length == 0:
            break
        offset += length
    return offset + 4


def observe_response(response: bytes, expected_identifier: int) -> dict[str, Any]:
    question_end = dns_question_end(response)
    answer = question_end
    if response[answer : answer + 2] != b"\xc0\x0c":
        raise AssertionError(f"answer name was not compressed: {response.hex()}")
    ttl = int.from_bytes(response[answer + 6 : answer + 10], "big")
    if not ANSWER_TTL - 3 <= ttl <= ANSWER_TTL:
        raise AssertionError(f"answer TTL is outside the fresh fixture window: {ttl}")
    return {
        "id-echoed": int.from_bytes(response[:2], "big") == expected_identifier,
        "flags": response[2:4].hex(),
        "questions": int.from_bytes(response[4:6], "big"),
        "answers": int.from_bytes(response[6:8], "big"),
        "type": int.from_bytes(response[answer + 2 : answer + 4], "big"),
        "class": int.from_bytes(response[answer + 4 : answer + 6], "big"),
        # Cache timing crosses wall-clock second boundaries independently in
        # the two product processes. Preserve the narrow near-origin window;
        # Phase 4F11 owns exact cache-lifecycle observations.
        "ttl": "fresh-within-fixture-window",
        "address": socket.inet_ntoa(response[answer + 12 : answer + 16]),
    }


def udp_query(port: int, query: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(IO_DEADLINE)
        client.sendto(query, ("127.0.0.1", port))
        response, source = client.recvfrom(65535)
        if source[1] != port:
            raise AssertionError(f"unexpected DNS UDP source {source}")
        return response


def tcp_query(port: int, query: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=IO_DEADLINE) as client:
        client.settimeout(IO_DEADLINE)
        client.sendall(len(query).to_bytes(2, "big") + query)
        length = int.from_bytes(recv_exact(client, 2), "big")
        return recv_exact(client, length)


def wait_dns_ready(process: subprocess.Popen[bytes], port: int) -> None:
    # Startup competes with parallel build/test shards on CI. This is only the
    # process-readiness window; individual DNS I/O still uses IO_DEADLINE.
    deadline = time.monotonic() + max(30.0, (4 * IO_DEADLINE) + 1)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"DNS candidate exited with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("DNS TCP listener did not become ready")


def build_binaries(output: pathlib.Path) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()
    go_binary = output / "go-oracle"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_binary), "."],
        cwd=ROOT,
        check=True,
    )
    target = cargo_target_path("PHASE4_CARGO_TARGET", "phase4-rust")
    subprocess.run(
        ["cargo", "build", "--workspace", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def launch(
    binary: pathlib.Path, config: pathlib.Path, scratch: pathlib.Path
) -> tuple[subprocess.Popen[bytes], Any, Any]:
    stdout = (scratch / "stdout.log").open("wb")
    stderr = (scratch / "stderr.log").open("wb")
    process = subprocess.Popen(
        [str(binary), "-f", str(config)],
        cwd=scratch,
        # Keep Go's conditional XDG fallback in the same isolated home used by
        # the Rust candidate. Inheriting a runner-level XDG_CONFIG_HOME makes
        # Go persist fake-IP state in a shared cache while Rust reads the
        # fixture-local HOME, invalidating cross-process interchange evidence.
        env={
            **os.environ,
            "HOME": str(scratch),
            "XDG_CONFIG_HOME": str(scratch / ".config"),
        },
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    return process, stdout, stderr


def stop(process: subprocess.Popen[bytes]) -> int:
    # Normalize only termination requested by this cleanup helper; spontaneous
    # exits and forced-kill escalation remain observable.
    return terminate_process(process, normalize_requested=True)


def render_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    dns_port: int,
    upstream_port: int,
    upstream_transport: str,
) -> None:
    path.write_text(
        FIXTURE.read_text()
        .replace("${MIXED_PORT}", str(mixed_port))
        .replace("${DNS_PORT}", str(dns_port))
        .replace("${UPSTREAM_PORT}", str(upstream_port))
        .replace("${UPSTREAM_TRANSPORT}", upstream_transport)
    )


def exercise(binary: pathlib.Path, scratch: pathlib.Path, transport: str) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = LocalAuthority()
    dns_port, mixed_port = reserve_port(), reserve_port()
    config = scratch / f"{transport}.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        upstream_port=authority.port,
        upstream_transport=transport,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        observations: dict[str, Any] = {}
        for inbound, query_fn, identifier in (
            ("udp", udp_query, 0x4100),
            ("tcp", tcp_query, 0x4200),
        ):
            name = f"{inbound}-{transport}.phase4.test"
            first = query_fn(dns_port, dns_query(name, identifier))
            second = query_fn(dns_port, dns_query(name, identifier + 1))
            observations[inbound] = {
                "first": observe_response(first, identifier),
                "cached": observe_response(second, identifier + 1),
            }
        observations["upstream-counts"] = authority.state.snapshot()
        # Give both products a short quiet window before fixture cleanup. The
        # shared stop helper still handles the narrower Go signal-handler race.
        time.sleep(0.1)
        observations["exit-code"] = stop(process)
        return observations
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def config_validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    valid = scratch / "valid.yaml"
    render_config(
        valid,
        mixed_port=reserve_port(),
        dns_port=reserve_port(),
        upstream_port=reserve_port(),
        upstream_transport="udp",
    )
    empty = scratch / "empty-nameserver.yaml"
    empty.write_text(
        "\n".join(
            line
            for line in valid.read_text().splitlines()
            if not line.strip().startswith("- udp://")
        )
        + "\n"
    )
    return {
        "valid": subprocess.run(
            [str(binary), "-t", "-f", str(valid)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode,
        "empty-nameserver": subprocess.run(
            [str(binary), "-t", "-f", str(empty)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode,
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations: dict[str, Any] = {}
        for implementation, binary in binaries.items():
            implementation_root = root / implementation
            implementation_root.mkdir()
            observations[implementation] = {
                "config": config_validation(binary, implementation_root),
                "udp-upstream": exercise(
                    binary, implementation_root / "udp-run", "udp"
                ),
                "tcp-upstream": exercise(
                    binary, implementation_root / "tcp-run", "tcp"
                ),
            }
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4A mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4A Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

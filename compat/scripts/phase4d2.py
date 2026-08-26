#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4D2 DNS fallback."""

from __future__ import annotations

import json
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable

from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port
from phase4 import build_binaries, launch, stop, wait_dns_ready
from phase4b import make_query, parse_query, parse_response, udp_query


FIXTURE = ROOT / "compat" / "fixtures" / "phase4" / "fallback.yaml.tmpl"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4d2-diff.json"


class AuthorityState:
    def __init__(self, answer: str | Callable[[str], str]) -> None:
        self.answer = answer
        self.questions: list[list[str]] = []
        self.lock = threading.Lock()

    def respond(self, query: bytes, transport: str) -> bytes:
        name, record_type, question_end = parse_query(query)
        with self.lock:
            self.questions.append([transport, name, str(record_type)])
        answer_address = self.answer(name) if callable(self.answer) else self.answer
        answer = b""
        count = 0
        if record_type == 1:
            answer = (
                b"\xc0\x0c\x00\x01\x00\x01"
                + (30).to_bytes(4, "big")
                + b"\x00\x04"
                + socket.inet_aton(answer_address)
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

    def snapshot(self) -> list[list[str]]:
        with self.lock:
            return list(self.questions)


class UDPAuthority(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class TCPAuthority(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, server_socket = self.request
        state: AuthorityState = self.server.state  # type: ignore[attr-defined]
        server_socket.sendto(state.respond(query, "udp"), self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        state: AuthorityState = self.server.state  # type: ignore[attr-defined]
        while True:
            try:
                length = recv_exact(self.request, 2)
                query = recv_exact(self.request, int.from_bytes(length, "big"))
            except (EOFError, OSError):
                return
            response = state.respond(query, "tcp")
            self.request.sendall(len(response).to_bytes(2, "big") + response)


class LocalAuthority:
    def __init__(self, answer: str | Callable[[str], str]) -> None:
        self.state = AuthorityState(answer)
        self.tcp = TCPAuthority(("127.0.0.1", 0), TCPHandler)
        self.port = self.tcp.server_address[1]
        self.udp = UDPAuthority(("127.0.0.1", self.port), UDPHandler)
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


def main_answer(name: str) -> str:
    if name == "filtered.phase4.test":
        return "198.51.100.10"
    return "192.0.2.10"


def render_config(
    path: pathlib.Path,
    dns_port: int,
    authorities: dict[str, LocalAuthority],
    lazy: bool,
) -> None:
    path.write_text(
        FIXTURE.read_text()
        .replace("${DNS_PORT}", str(dns_port))
        .replace("${MAIN_PORT}", str(authorities["main"].port))
        .replace("${FALLBACK_PORT}", str(authorities["fallback"].port))
        .replace("${POLICY_PORT}", str(authorities["policy"].port))
        .replace("${FALLBACK_LAZY}", str(lazy).lower())
    )


def validation(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authorities: dict[str, LocalAuthority],
) -> dict[str, int]:
    valid = scratch / "valid.yaml"
    render_config(valid, reserve_port(), authorities, True)
    invalid_cidr = scratch / "invalid-cidr.yaml"
    invalid_cidr.write_text(valid.read_text().replace("198.51.100.0/24", "bad-cidr"))
    malformed_domain = scratch / "malformed-domain.yaml"
    malformed_domain.write_text(
        valid.read_text().replace("+.fallback.phase4.test", "a+b.phase4.test")
    )
    result: dict[str, int] = {}
    for name, path in {
        "valid": valid,
        "invalid-cidr": invalid_cidr,
        "malformed-domain": malformed_domain,
    }.items():
        result[name] = subprocess.run(
            [str(binary), "-t", "-f", str(path)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
    return result


def exercise(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authorities: dict[str, LocalAuthority],
    lazy: bool,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    render_config(config, dns_port, authorities, lazy)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        cases = [
            ("forced-domain", "force.fallback.phase4.test", 0x7201),
            ("safe-main", "safe.phase4.test", 0x7202),
            ("filtered-fallback", "filtered.phase4.test", 0x7203),
            ("filtered-cached", "filtered.phase4.test", 0x7204),
            ("policy-precedence", "policy.phase4.test", 0x7205),
        ]
        observations: dict[str, Any] = {}
        for label, name, identifier in cases:
            response = parse_response(
                udp_query(dns_port, make_query(name, 1, identifier)), identifier
            )
            if label == "filtered-cached":
                ttl = response["records"][0]["ttl"]
                if not 0 < ttl < 30:
                    raise AssertionError(f"cached fallback TTL did not age: {ttl}")
                response["records"][0]["ttl"] = "positive-aged"
            observations[label] = response
            # Let an eager fallback request become observable before the next
            # query without making its completion part of response latency.
            time.sleep(0.05)
        observations["exit-code"] = stop(process)
        return observations
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def make_authorities() -> dict[str, LocalAuthority]:
    return {
        "main": LocalAuthority(main_answer),
        "fallback": LocalAuthority("192.0.2.200"),
        "policy": LocalAuthority("192.0.2.40"),
    }


def run_mode(binary: pathlib.Path, scratch: pathlib.Path, lazy: bool) -> dict[str, Any]:
    authorities = make_authorities()
    try:
        return {
            "runtime": exercise(binary, scratch, authorities, lazy),
            "authorities": {
                name: authority.state.snapshot()
                for name, authority in authorities.items()
            },
        }
    finally:
        for authority in authorities.values():
            authority.close()


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    validation_authorities = make_authorities()
    try:
        config = validation(binary, scratch, validation_authorities)
    finally:
        for authority in validation_authorities.values():
            authority.close()
    return {
        "config": config,
        "eager": run_mode(binary, scratch / "eager", False),
        "lazy": run_mode(binary, scratch / "lazy", True),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4d2-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations: dict[str, Any] = {}
        for implementation, binary in binaries.items():
            scratch = root / implementation
            scratch.mkdir()
            observations[implementation] = run_candidate(binary, scratch)
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4D2 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4D2 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

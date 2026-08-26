#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4D1 nameserver policy."""

from __future__ import annotations

import json
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port
from phase4 import build_binaries, launch, stop, wait_dns_ready
from phase4b import make_query, parse_query, parse_response, udp_query


FIXTURE = ROOT / "compat" / "fixtures" / "phase4" / "policy.yaml.tmpl"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4d1-diff.json"


class AuthorityState:
    def __init__(self, address: str) -> None:
        self.address = address
        self.questions: list[list[str]] = []
        self.lock = threading.Lock()

    def respond(self, query: bytes, transport: str) -> bytes:
        name, record_type, question_end = parse_query(query)
        with self.lock:
            self.questions.append([transport, name, str(record_type)])
        answer = b""
        count = 0
        if record_type == 1:
            answer = (
                b"\xc0\x0c\x00\x01\x00\x01"
                + (30).to_bytes(4, "big")
                + b"\x00\x04"
                + socket.inet_aton(self.address)
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
    def __init__(self, address: str) -> None:
        self.state = AuthorityState(address)
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


def render_config(
    path: pathlib.Path,
    dns_port: int,
    authorities: dict[str, LocalAuthority],
) -> None:
    path.write_text(
        FIXTURE.read_text()
        .replace("${DNS_PORT}", str(dns_port))
        .replace("${MAIN_PORT}", str(authorities["main"].port))
        .replace("${SUFFIX_PORT}", str(authorities["suffix"].port))
        .replace("${WILDCARD_PORT}", str(authorities["wildcard"].port))
        .replace("${EXACT_PORT}", str(authorities["exact"].port))
    )


def validation(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authorities: dict[str, LocalAuthority],
) -> dict[str, int]:
    valid = scratch / "valid.yaml"
    render_config(valid, reserve_port(), authorities)
    malformed = scratch / "malformed-pattern.yaml"
    malformed.write_text(
        valid.read_text().replace("'+.suffix.phase4.test'", "'a+b.phase4.test'")
    )
    wrong_value = scratch / "wrong-value.yaml"
    wrong_value.write_text(
        valid.read_text().replace(
            f"udp://127.0.0.1:{authorities['suffix'].port}", "42", 1
        )
    )
    result: dict[str, int] = {}
    for name, path in {
        "valid": valid,
        "malformed-pattern": malformed,
        "wrong-value": wrong_value,
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
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    render_config(config, dns_port, authorities)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        cases = [
            ("main", "other.phase4.test", 0x7101),
            ("suffix-root", "suffix.phase4.test", 0x7102),
            ("suffix-deep", "deep.suffix.phase4.test", 0x7103),
            ("wildcard-one", "x.one.phase4.test", 0x7104),
            ("wildcard-deep-main", "deep.x.one.phase4.test", 0x7105),
            ("overlap-suffix", "other.overlap.phase4.test", 0x7106),
            ("overlap-exact", "exact.overlap.phase4.test", 0x7107),
            ("overlap-exact-cached", "exact.overlap.phase4.test", 0x7108),
        ]
        observations = {
            label: parse_response(
                udp_query(dns_port, make_query(name, 1, identifier)), identifier
            )
            for label, name, identifier in cases
        }
        observations["exit-code"] = stop(process)
        return observations
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authorities = {
        "main": LocalAuthority("192.0.2.10"),
        "suffix": LocalAuthority("192.0.2.20"),
        "wildcard": LocalAuthority("192.0.2.30"),
        "exact": LocalAuthority("192.0.2.40"),
    }
    try:
        return {
            "config": validation(binary, scratch, authorities),
            "runtime": exercise(binary, scratch / "run", authorities),
            "authorities": {
                name: authority.state.snapshot()
                for name, authority in authorities.items()
            },
        }
    finally:
        for authority in authorities.values():
            authority.close()


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4d1-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations: dict[str, Any] = {}
        for implementation, binary in binaries.items():
            scratch = root / implementation
            scratch.mkdir()
            observations[implementation] = run_candidate(binary, scratch)
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4D1 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4D1 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

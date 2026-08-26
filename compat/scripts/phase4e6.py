#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E6 HTTP/1.1 DoH reuse."""

from __future__ import annotations

import base64
import json
import socket
import socketserver
import ssl
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase4 import (
    AuthorityState,
    build_binaries,
    dns_query,
    launch,
    stop,
    tcp_query,
    wait_dns_ready,
)
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase4e5 import encrypted_udp_query, observe_or_raw, render_config, validation


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e6-diff.json"


class ReuseHTTPSAuthority(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, close_after_response: bool) -> None:
        self.state = AuthorityState()
        self.state.counts = {"https": 0}
        self.close_after_response = close_after_response
        self.connection_count = 0
        self.requests: list[dict[str, Any]] = []
        self.observation_lock = threading.Lock()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        self.context.set_alpn_protocols(["http/1.1"])
        super().__init__(("127.0.0.1", 0), ReuseHTTPSHandler)

    def get_request(self) -> tuple[socket.socket, Any]:
        stream, address = super().get_request()
        try:
            tls_stream = self.context.wrap_socket(stream, server_side=True)
        except Exception:
            stream.close()
            raise
        with self.observation_lock:
            self.connection_count += 1
        return tls_stream, address

    def record(self, observation: dict[str, Any]) -> None:
        with self.observation_lock:
            self.requests.append(observation)

    def snapshot(self) -> dict[str, Any]:
        with self.observation_lock:
            connections = self.connection_count
            requests = list(self.requests)
        return {
            "connections": connections,
            "queries": self.state.snapshot(),
            "requests": requests,
        }


class ReuseHTTPSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: ReuseHTTPSAuthority = self.server  # type: ignore[assignment]
        self.request.settimeout(IO_DEADLINE)
        responses = 0
        while True:
            raw = bytearray()
            try:
                while b"\r\n\r\n" not in raw:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        return
                    raw.extend(chunk)
                    if len(raw) > 16_384:
                        return
            except (OSError, TimeoutError):
                return
            header_block, body = bytes(raw).split(b"\r\n\r\n", 1)
            lines = header_block.decode("ascii").split("\r\n")
            method, target, version = lines[0].split(" ", 2)
            headers = {
                name.lower(): value.strip()
                for name, value in (line.split(":", 1) for line in lines[1:])
            }
            parsed = urllib.parse.urlsplit(target)
            parameters = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            encoded = parameters.get("dns", [""])
            try:
                query = base64.urlsafe_b64decode(encoded[0] + "=" * (-len(encoded[0]) % 4))
            except Exception:
                return
            valid = (
                method == "GET"
                and version == "HTTP/1.1"
                and parsed.path == "/dns-query"
                and set(parameters) == {"dns"}
                and len(encoded) == 1
                and len(query) >= 12
                and query[:2] == b"\x00\x00"
                and headers.get("accept") == "application/dns-message"
                and headers.get("connection") is None
                and not body
            )
            server.record(
                {
                    "method": method,
                    "path": parsed.path,
                    "version": version,
                    "dns-id-zero": len(query) >= 2 and query[:2] == b"\x00\x00",
                    "accept": headers.get("accept"),
                    "connection": headers.get("connection"),
                    "request-body-bytes": len(body),
                    "valid": valid,
                }
            )
            if not valid:
                return
            response = server.state.answer(query, "https")
            headers_out = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/dns-message\r\n"
                f"Content-Length: {len(response)}\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
            ).encode("ascii")
            try:
                self.request.sendall(headers_out + response)
            except OSError:
                return
            responses += 1
            if server.close_after_response or responses == 2:
                return


def exercise(
    binary: Path,
    scratch: Path,
    close_after_response: bool,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = ReuseHTTPSAuthority(close_after_response)
    authority_thread = threading.Thread(target=authority.serve_forever, daemon=True)
    authority_thread.start()
    mixed_port, dns_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        upstream_port=authority.server_address[1],
        server_name="dot.phase4.test",
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        first_name = "first.reuse.doh.phase4.test"
        second_name = "second.reuse.doh.phase4.test"
        first = encrypted_udp_query(dns_port, dns_query(first_name, 0x8310))
        second = tcp_query(dns_port, dns_query(second_name, 0x8320))
        cached = encrypted_udp_query(dns_port, dns_query(first_name, 0x8330))
        return {
            "first": observe_or_raw(first, 0x8310),
            "second": observe_or_raw(second, 0x8320),
            "cached": observe_cached(cached, 0x8330),
            "https-authority": authority.snapshot(),
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.shutdown()
        authority.server_close()
        authority_thread.join(timeout=IO_DEADLINE)


def observe_cached(response: bytes, identifier: int) -> dict[str, Any]:
    observation = observe_or_raw(response, identifier)
    ttl = observation.pop("ttl", None)
    observation["ttl-aged-positive"] = isinstance(ttl, int) and 0 < ttl < 30
    return observation


def run_candidate(binary: Path, scratch: Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    return {
        "config": validation(binary, scratch),
        "persistent": exercise(binary, scratch / "persistent", False),
        "stale-reconnect": exercise(binary, scratch / "stale-reconnect", True),
    }


def satisfies_phase_contract(observation: dict[str, Any]) -> bool:
    persistent = observation["persistent"]
    stale = observation["stale-reconnect"]
    return (
        observation["config"] == {"valid": 0, "wrong-scheme": 1}
        and persistent["https-authority"]["connections"] == 1
        and persistent["https-authority"]["queries"] == {"https": 2}
        and len(persistent["https-authority"]["requests"]) == 2
        and all(request["valid"] for request in persistent["https-authority"]["requests"])
        and stale["https-authority"]["connections"] == 2
        and stale["https-authority"]["queries"] == {"https": 2}
        and len(stale["https-authority"]["requests"]) == 2
        and all(request["valid"] for request in stale["https-authority"]["requests"])
        and all(
            case["address"] == "192.0.2.42" and case["id-echoed"] is True
            for scenario in (persistent, stale)
            for case in (scenario["first"], scenario["second"], scenario["cached"])
        )
        and persistent["exit-code"] == 0
        and stale["exit-code"] == 0
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e6-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if (
            observations["go"] != observations["rust"]
            or not satisfies_phase_contract(observations["go"])
        ):
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4E6 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E6 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

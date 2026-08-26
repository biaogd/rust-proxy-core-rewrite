#!/usr/bin/env python3
"""Local Go/Rust differential suite for the Phase 4E5 HTTPS DoH gate."""

from __future__ import annotations

import base64
import json
import pathlib
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase4 import (
    AuthorityState,
    build_binaries,
    dns_query,
    launch,
    observe_response,
    stop,
    tcp_query,
    wait_dns_ready,
)
from phase4e2 import (
    ROOT_CERTIFICATE,
    SERVER_CERTIFICATE,
    SERVER_KEY,
    rejected_query,
)


FIXTURE = ROOT / "compat" / "fixtures" / "phase4" / "doh-verified.yaml.tmpl"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e5-diff.json"


def encrypted_udp_query(port: int, query: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout((2 * IO_DEADLINE) + 1)
        client.sendto(query, ("127.0.0.1", port))
        response, source = client.recvfrom(65_535)
        if source[1] != port:
            raise AssertionError(f"unexpected DNS UDP source {source}")
        return response


class HTTPSAuthority(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, expected_path: str | None = "/dns-query") -> None:
        self.state = AuthorityState()
        self.state.counts = {"https": 0}
        self.expected_path = expected_path
        self.connection_count = 0
        self.requests: list[dict[str, Any]] = []
        self.observation_lock = threading.Lock()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        self.context.set_alpn_protocols(["http/1.1"])
        super().__init__(("127.0.0.1", 0), HTTPSHandler)

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


class HTTPSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: HTTPSAuthority = self.server  # type: ignore[assignment]
        self.request.settimeout(IO_DEADLINE)
        raw = bytearray()
        while b"\r\n\r\n" not in raw:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            raw.extend(chunk)
            if len(raw) > 16_384:
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
            and (server.expected_path is None or parsed.path == server.expected_path)
            and set(parameters) == {"dns"}
            and len(encoded) == 1
            and len(query) >= 12
            and query[:2] == b"\x00\x00"
            and headers.get("accept") == "application/dns-message"
            and not body
        )
        server.record(
            {
                "method": method,
                "path": parsed.path,
                "version": version,
                "dns-parameter-count": len(encoded),
                "dns-id-zero": len(query) >= 2 and query[:2] == b"\x00\x00",
                "accept": headers.get("accept"),
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
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        self.request.sendall(headers_out + response)


def render_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    dns_port: int,
    upstream_port: int,
    server_name: str,
) -> None:
    root_pem = "\n".join(f"      {line}" for line in ROOT_CERTIFICATE.read_text().splitlines())
    path.write_text(
        FIXTURE.read_text()
        .replace("${MIXED_PORT}", str(mixed_port))
        .replace("${DNS_PORT}", str(dns_port))
        .replace("${UPSTREAM_PORT}", str(upstream_port))
        .replace("${SERVER_NAME}", server_name)
        .replace("${ROOT_PEM}", root_pem)
    )


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    valid = scratch / "valid.yaml"
    render_config(
        valid,
        mixed_port=reserve_port(),
        dns_port=reserve_port(),
        upstream_port=reserve_port(),
        server_name="dot.phase4.test",
    )
    wrong_scheme = scratch / "wrong-scheme.yaml"
    wrong_scheme.write_text(valid.read_text().replace("https://", "bogus://"))
    return {
        name: subprocess.run(
            [str(binary), "-t", "-f", str(path)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        for name, path in {"valid": valid, "wrong-scheme": wrong_scheme}.items()
    }


def exercise(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    server_name: str,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = HTTPSAuthority()
    authority_thread = threading.Thread(target=authority.serve_forever, daemon=True)
    authority_thread.start()
    mixed_port, dns_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        upstream_port=authority.server_address[1],
        server_name=server_name,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        observations: dict[str, Any] = {}
        name = "verified.doh.phase4.test"
        if server_name == "dot.phase4.test":
            first = encrypted_udp_query(dns_port, dns_query(name, 0x8210))
            cached = tcp_query(dns_port, dns_query(name, 0x8220))
            observations["first"] = observe_or_raw(first, 0x8210)
            observations["cached"] = observe_or_raw(cached, 0x8220)
        else:
            for inbound, query_fn, identifier in (
                ("udp", encrypted_udp_query, 0x8230),
                ("tcp", tcp_query, 0x8240),
            ):
                observations[inbound] = rejected_query(
                    query_fn, dns_port, dns_query(f"{inbound}.{name}", identifier)
                )
        observations["https-authority"] = authority.snapshot()
        observations["exit-code"] = stop(process)
        return observations
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.shutdown()
        authority.server_close()
        authority_thread.join(timeout=IO_DEADLINE)


def observe_or_raw(response: bytes, identifier: int) -> dict[str, Any]:
    try:
        return observe_response(response, identifier)
    except (AssertionError, IndexError):
        return {"raw": response.hex()}


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    return {
        "config": validation(binary, scratch),
        "verified": exercise(binary, scratch / "verified", "dot.phase4.test"),
        "wrong-name": exercise(binary, scratch / "wrong-name", "wrong.phase4.test"),
    }


def satisfies_phase_contract(observation: dict[str, Any]) -> bool:
    verified = observation["verified"]
    authority = verified["https-authority"]
    wrong_name = observation["wrong-name"]
    return (
        observation["config"] == {"valid": 0, "wrong-scheme": 1}
        and verified["first"].get("address") == "192.0.2.42"
        and verified["first"].get("id-echoed") is True
        and verified["cached"].get("address") == "192.0.2.42"
        and verified["cached"].get("id-echoed") is True
        and authority["connections"] == 1
        and authority["queries"] == {"https": 1}
        and len(authority["requests"]) == 1
        and authority["requests"][0]["valid"] is True
        and wrong_name["https-authority"]["connections"] == 0
        and wrong_name["https-authority"]["queries"] == {"https": 0}
        and wrong_name["udp"].get("flags") == "8102"
        and wrong_name["tcp"].get("flags") == "8102"
        and verified["exit-code"] == 0
        and wrong_name["exit-code"] == 0
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e5-") as temporary:
        root = pathlib.Path(temporary)
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
            raise SystemExit(f"Phase 4E5 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E5 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

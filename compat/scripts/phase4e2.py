#!/usr/bin/env python3
"""Local Go/Rust differential suite for the Phase 4E2 verified-DoT gate."""

from __future__ import annotations

import json
import pathlib
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable

from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port
from phase4 import (
    AuthorityState,
    build_binaries,
    dns_query,
    launch,
    observe_response,
    stop,
    tcp_query,
    udp_query,
    wait_dns_ready,
)


FIXTURE = ROOT / "compat" / "fixtures" / "phase4" / "dot-verified.yaml.tmpl"
ROOT_CERTIFICATE = ROOT / "compat" / "fixtures" / "phase4" / "phase4e2-root.pem"
SERVER_CERTIFICATE = ROOT / "compat" / "fixtures" / "phase4" / "phase4e2-server.pem"
SERVER_KEY = ROOT / "compat" / "fixtures" / "phase4" / "phase4e2-server-key.pem"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e2-diff.json"


class TLSAuthority(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        self.state = AuthorityState()
        self.state.counts = {"tls": 0}
        self.connection_count = 0
        self.connection_lock = threading.Lock()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        super().__init__(("127.0.0.1", 0), TLSHandler)

    def get_request(self) -> tuple[socket.socket, Any]:
        stream, address = super().get_request()
        try:
            tls_stream = self.context.wrap_socket(stream, server_side=True)
        except Exception:
            stream.close()
            raise
        with self.connection_lock:
            self.connection_count += 1
        return tls_stream, address

    def snapshot(self) -> dict[str, Any]:
        with self.connection_lock:
            connections = self.connection_count
        return {"connections": connections, "queries": self.state.snapshot()}


class TLSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: TLSAuthority = self.server  # type: ignore[assignment]
        try:
            length = int.from_bytes(recv_exact(self.request, 2), "big")
            query = recv_exact(self.request, length)
        except (EOFError, OSError):
            return
        response = server.state.answer(query, "tls")
        self.request.sendall(len(response).to_bytes(2, "big") + response)


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
    wrong_scheme.write_text(valid.read_text().replace("tls://", "bogus://"))
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


def rejected_query(
    query_fn: Callable[[int, bytes], bytes], dns_port: int, query: bytes
) -> dict[str, Any]:
    try:
        response = query_fn(dns_port, query)
    except (EOFError, OSError, TimeoutError) as error:
        return {"error": type(error).__name__}
    return {
        "id-echoed": response[:2] == query[:2],
        "flags": response[2:4].hex(),
        "questions": int.from_bytes(response[4:6], "big"),
        "answers": int.from_bytes(response[6:8], "big"),
    }


def exercise(binary: pathlib.Path, scratch: pathlib.Path, server_name: str) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = TLSAuthority()
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
        for inbound, query_fn, identifier in (
            ("udp", udp_query, 0x7F10),
            ("tcp", tcp_query, 0x7F20),
        ):
            query = dns_query(f"{inbound}.verified.phase4.test", identifier)
            if server_name == "dot.phase4.test":
                first = query_fn(dns_port, query)
                cached = query_fn(dns_port, dns_query(f"{inbound}.verified.phase4.test", identifier + 1))
                observations[inbound] = {
                    "first": observe_response(first, identifier),
                    "cached": observe_response(cached, identifier + 1),
                }
            else:
                observations[inbound] = rejected_query(query_fn, dns_port, query)
        observations["tls-authority"] = authority.snapshot()
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


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    return {
        "config": validation(binary, scratch),
        "verified": exercise(binary, scratch / "verified", "dot.phase4.test"),
        "wrong-name": exercise(binary, scratch / "wrong-name", "wrong.phase4.test"),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e2-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4E2 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E2 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

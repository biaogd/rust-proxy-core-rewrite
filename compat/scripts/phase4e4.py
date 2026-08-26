#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E4 DoT connection reuse."""

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
from typing import Any

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
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY


FIXTURE = ROOT / "compat" / "fixtures" / "phase4" / "dot-reuse.yaml.tmpl"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e4-diff.json"


class ReuseTLSAuthority(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, close_after_response: bool) -> None:
        self.state = AuthorityState()
        self.state.counts = {"tls": 0}
        self.close_after_response = close_after_response
        self.connection_count = 0
        self.connection_lock = threading.Lock()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        super().__init__(("127.0.0.1", 0), ReuseTLSHandler)

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


class ReuseTLSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: ReuseTLSAuthority = self.server  # type: ignore[assignment]
        while True:
            try:
                length = int.from_bytes(recv_exact(self.request, 2), "big")
                query = recv_exact(self.request, length)
            except (EOFError, OSError):
                return
            response = server.state.answer(query, "tls")
            try:
                self.request.sendall(len(response).to_bytes(2, "big") + response)
            except OSError:
                return
            if server.close_after_response:
                return


def render_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    dns_port: int,
    upstream_port: int,
) -> None:
    root_pem = "\n".join(f"      {line}" for line in ROOT_CERTIFICATE.read_text().splitlines())
    path.write_text(
        FIXTURE.read_text()
        .replace("${MIXED_PORT}", str(mixed_port))
        .replace("${DNS_PORT}", str(dns_port))
        .replace("${UPSTREAM_PORT}", str(upstream_port))
        .replace("${ROOT_PEM}", root_pem)
    )


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    valid = scratch / "valid.yaml"
    render_config(
        valid,
        mixed_port=reserve_port(),
        dns_port=reserve_port(),
        upstream_port=reserve_port(),
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
        for name, path in {"valid-reuse": valid, "wrong-scheme": wrong_scheme}.items()
    }


def exercise(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    close_after_response: bool,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = ReuseTLSAuthority(close_after_response)
    authority_thread = threading.Thread(target=authority.serve_forever, daemon=True)
    authority_thread.start()
    mixed_port, dns_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        upstream_port=authority.server_address[1],
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        first_name = "first.reuse.phase4.test"
        second_name = "second.reuse.phase4.test"
        first = udp_query(dns_port, dns_query(first_name, 0x8110))
        second = tcp_query(dns_port, dns_query(second_name, 0x8120))
        cached = udp_query(dns_port, dns_query(first_name, 0x8130))
        observations = {
            "first": observe_response(first, 0x8110),
            "second": observe_response(second, 0x8120),
            "cached": observe_response(cached, 0x8130),
            "tls-authority": authority.snapshot(),
            "exit-code": stop(process),
        }
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
        "persistent": exercise(binary, scratch / "persistent", False),
        "stale-reconnect": exercise(binary, scratch / "stale-reconnect", True),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e4-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4E4 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E4 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

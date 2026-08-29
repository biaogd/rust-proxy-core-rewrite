#!/usr/bin/env python3
"""Go/Rust differential for the shared legacy Shadowsocks stream ciphers."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import socketserver
import tempfile
import threading
from typing import Any

from phase1 import (
    EchoHandler,
    HalfCloseHandler,
    IO_DEADLINE,
    ROOT,
    cargo_target_path,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import UdpEchoHandler, launch, socks_udp_packet, stop
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks import PASSWORD, start_authority
from phase6c_shadowsocks_ciphers import LARGE_PAYLOAD, echo, half_close, wait_route
from phase6c_shadowsocks_udp import domain_packet, exchange, wait_exchange


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-legacy-diff.json"
CIPHERS = (
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
)


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSSLEGACY_CARGO_TARGET", "phase6c-shadowsocks-legacy"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def exercise_cipher(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    cipher: str,
) -> dict[str, Any]:
    tcp_echo = start_server(EchoHandler)
    half_close_server = start_server(HalfCloseHandler)
    udp_echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    udp_thread = threading.Thread(target=udp_echo.serve_forever, daemon=True)
    udp_thread.start()
    udp_port = int(udp_echo.server_address[1])
    mixed_port = reserve_port()
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority, scratch, authority_port, cipher
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {cipher}
    password: {PASSWORD}
    udp: true
rules:
  - MATCH,local-ss
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_client.bind(("127.0.0.1", 0))
    udp_client.settimeout(IO_DEADLINE)
    try:
        wait_ready(process, mixed_port)
        wait_route(process, mixed_port, tcp_echo.port)
        first = f"legacy-{cipher}-udp".encode()
        domain = f"legacy-{cipher}-domain".encode()
        return {
            "tcp-domain": echo(mixed_port, "localhost", tcp_echo.port, b"domain"),
            "tcp-ipv4-large": echo(
                mixed_port, "127.0.0.1", tcp_echo.port, LARGE_PAYLOAD
            ),
            "tcp-half-close": half_close(mixed_port, half_close_server.port),
            "udp-ipv4": wait_exchange(
                process,
                udp_client,
                mixed_port,
                socks_udp_packet(udp_port, first),
                first,
            ),
            "udp-domain": exchange(
                udp_client,
                mixed_port,
                domain_packet("localhost", udp_port, domain),
                domain,
            ),
            "process-alive": process.poll() is None,
        }
    finally:
        udp_client.close()
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        tcp_echo.close()
        half_close_server.close()
        udp_echo.shutdown()
        udp_echo.server_close()
        udp_thread.join(timeout=IO_DEADLINE)


def exercise(
    binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    observations = {}
    for cipher in CIPHERS:
        cipher_scratch = scratch / cipher
        cipher_scratch.mkdir()
        observations[cipher] = exercise_cipher(
            binary, authority, cipher_scratch, cipher
        )
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-legacy-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE6CSSLEGACY_CARGO_TARGET",
            "phase6c-shadowsocks-legacy",
        )
        authority = authority_binary()
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, authority, scratch)
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
    print("Phase 6C-G legacy Shadowsocks TCP/UDP cipher differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

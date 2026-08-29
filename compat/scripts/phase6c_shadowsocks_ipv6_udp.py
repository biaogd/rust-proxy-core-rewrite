#!/usr/bin/env python3
"""Go/Rust differential for Shadowsocks UDP relay to IPv6 destinations."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import socketserver
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, cargo_target_path, reserve_port, wait_ready
from phase3 import UdpEchoHandler, launch, stop
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks import PASSWORD, start_authority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-ipv6-udp-diff.json"
CIPHERS = ("aes-128-gcm", "aes-128-ctr", "xchacha20-ietf-poly1305")


class ThreadingUdpServerV6(socketserver.ThreadingUDPServer):
    address_family = socket.AF_INET6
    daemon_threads = True


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSSIPV6UDP_CARGO_TARGET", "phase6c-shadowsocks-ipv6-udp"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def ipv6_packet(destination_port: int, payload: bytes) -> bytes:
    return (
        b"\x00\x00\x00\x04"
        + socket.inet_pton(socket.AF_INET6, "::1")
        + destination_port.to_bytes(2, "big")
        + payload
    )


def decode_ipv6_response(packet: bytes) -> tuple[str, int, bytes]:
    if len(packet) < 22 or packet[:4] != b"\x00\x00\x00\x04":
        raise AssertionError(f"unexpected IPv6 SOCKS UDP response: {packet!r}")
    address = socket.inet_ntop(socket.AF_INET6, packet[4:20])
    port = int.from_bytes(packet[20:22], "big")
    return address, port, packet[22:]


def wait_exchange(
    process: Any,
    client: socket.socket,
    proxy_port: int,
    destination_port: int,
    payload: bytes,
) -> bool:
    deadline = time.monotonic() + (2 * IO_DEADLINE)
    client.settimeout(0.2)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during IPv6 UDP relay: {process.returncode}")
        client.sendto(ipv6_packet(destination_port, payload), ("127.0.0.1", proxy_port))
        try:
            response, _ = client.recvfrom(65_535)
            address, port, returned = decode_ipv6_response(response)
            if address == "::1" and port == destination_port and returned == payload:
                client.settimeout(IO_DEADLINE)
                return True
        except TimeoutError:
            pass
        time.sleep(0.02)
    raise TimeoutError("Shadowsocks IPv6 UDP route did not become ready")


def exercise_cipher(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    cipher: str,
) -> dict[str, bool]:
    echo = ThreadingUdpServerV6(("::1", 0), UdpEchoHandler)
    echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
    echo_thread.start()
    echo_port = int(echo.server_address[1])
    mixed_port = reserve_port()
    socks_port = reserve_port()
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority, scratch, authority_port, cipher
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
socks-port: {socks_port}
mode: rule
log-level: info
ipv6: true
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
    mixed_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socks_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        wait_ready(process, mixed_port)
        wait_ready(process, socks_port)
        return {
            "mixed-ipv6": wait_exchange(
                process, mixed_client, mixed_port, echo_port, b"mixed-ipv6"
            ),
            "socks5-ipv6": wait_exchange(
                process, socks_client, socks_port, echo_port, b"socks5-ipv6"
            ),
            "process-alive": process.poll() is None,
        }
    finally:
        mixed_client.close()
        socks_client.close()
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        echo.shutdown()
        echo.server_close()
        echo_thread.join(timeout=IO_DEADLINE)


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
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-ipv6-udp-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE6CSSIPV6UDP_CARGO_TARGET", "phase6c-shadowsocks-ipv6-udp"
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
    print("Phase 6C-L Shadowsocks IPv6 UDP differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

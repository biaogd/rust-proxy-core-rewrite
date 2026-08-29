#!/usr/bin/env python3
"""Go/Rust differential for the Phase 6C-C SIP004 AEAD UDP slice."""

from __future__ import annotations

import http.client
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
from phase3 import UdpEchoHandler, decode_socks_udp, launch, socks_udp_packet, stop
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks import PASSWORD, SECRET, start_authority
from phase6c_shadowsocks_ciphers import CIPHERS


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-udp-diff.json"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSSUDP_CARGO_TARGET", "phase6c-shadowsocks-udp"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def domain_packet(host: str, port: int, payload: bytes) -> bytes:
    encoded = host.encode("ascii")
    if not encoded or len(encoded) > 255:
        raise ValueError("SOCKS5 UDP domain must contain 1..255 ASCII bytes")
    return b"\x00\x00\x00\x03" + bytes([len(encoded)]) + encoded + port.to_bytes(
        2, "big"
    ) + payload


def exchange(
    client: socket.socket, mixed_port: int, packet: bytes, expected: bytes
) -> bool:
    client.sendto(packet, ("127.0.0.1", mixed_port))
    response, _ = client.recvfrom(65_535)
    address, _, payload = decode_socks_udp(response)
    return address == "127.0.0.1" and payload == expected


def wait_exchange(
    process: Any,
    client: socket.socket,
    mixed_port: int,
    packet: bytes,
    expected: bytes,
) -> bool:
    client.settimeout(0.2)
    deadline = time.monotonic() + (2 * IO_DEADLINE)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during UDP readiness: {process.returncode}")
        try:
            if exchange(client, mixed_port, packet, expected):
                client.settimeout(IO_DEADLINE)
                return True
        except TimeoutError:
            pass
        time.sleep(0.02)
    raise TimeoutError("Shadowsocks UDP route did not become ready")


def proxy_snapshot(controller_port: int) -> dict[str, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", controller_port, timeout=5)
    connection.request(
        "GET",
        "/proxies/local-ss",
        headers={"Authorization": f"Bearer {SECRET}"},
    )
    response = connection.getresponse()
    body = response.read()
    connection.close()
    if response.status != 200:
        raise AssertionError((response.status, body))
    payload = json.loads(body)
    return {
        "name": payload["name"],
        "type": payload["type"],
        "udp": payload["udp"],
        "uot": payload["uot"],
    }


def exercise_listener(
    process: Any, proxy_port: int, echo_port: int, label: str
) -> dict[str, bool]:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(IO_DEADLINE)
    first = f"ss-udp-{label}-ipv4-first".encode()
    domain_payload = f"ss-udp-{label}-domain".encode()
    reused = bytes(range(256)) * 16
    try:
        return {
            "ipv4": wait_exchange(
                process,
                client,
                proxy_port,
                socks_udp_packet(echo_port, first),
                first,
            ),
            "domain": exchange(
                client,
                proxy_port,
                domain_packet("localhost", echo_port, domain_payload),
                domain_payload,
            ),
            "same-client-session-reuse": exchange(
                client,
                proxy_port,
                socks_udp_packet(echo_port, reused),
                reused,
            ),
        }
    finally:
        client.close()


def exercise_cipher(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    cipher: str,
) -> dict[str, Any]:
    echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
    echo_thread.start()
    echo_port = int(echo.server_address[1])
    mixed_port = reserve_port()
    socks_port = reserve_port()
    controller_port = reserve_port()
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority, scratch, authority_port, cipher
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
socks-port: {socks_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
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
    try:
        wait_ready(process, mixed_port)
        wait_ready(process, socks_port)
        return {
            "mixed": exercise_listener(process, mixed_port, echo_port, "mixed"),
            "socks5": exercise_listener(process, socks_port, echo_port, "socks5"),
            "controller": proxy_snapshot(controller_port),
            "process-alive": process.poll() is None,
        }
    finally:
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
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-udp-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE6CSSUDP_CARGO_TARGET", "phase6c-shadowsocks-udp"
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
    print("Phase 6C-C Shadowsocks SIP004 AEAD UDP differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

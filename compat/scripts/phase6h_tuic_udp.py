#!/usr/bin/env python3
"""Go/Rust differential for 6H-B TUIC v5 outbound UDP (Go TUIC inbound authority)."""

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

from hy2_support import build_binaries
from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_udp import decode_socks_udp, socks_udp_packet
from phase6h_tuic_tcp import (
    UUID,
    config_validation,
    start_authority,
    tuic_record,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6h-tuic-udp-diff.json"
LARGE_UDP = bytes(range(256)) * 8  # 2048 bytes → native fragments under MaxFragSize


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(data, self.client_address)


def start_udp_echo() -> tuple[socketserver.ThreadingUDPServer, int]:
    server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    server.allow_reuse_address = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, int(server.server_address[1])


def socks_udp_associate(mixed_port: int) -> tuple[socket.socket, socket.socket, int]:
    control = socket.create_connection(("127.0.0.1", mixed_port), timeout=IO_DEADLINE)
    control.sendall(b"\x05\x01\x00")
    if control.recv(2) != b"\x05\x00":
        raise AssertionError("socks auth failed")
    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    response = recv_exact(control, 10)
    if response[0:2] != b"\x05\x00" or response[3] != 1:
        raise AssertionError(f"udp associate failed: {response!r}")
    bind_port = int.from_bytes(response[8:10], "big")
    if bind_port == 0:
        bind_port = mixed_port
    datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    datagram.settimeout(IO_DEADLINE)
    return control, datagram, bind_port


def udp_exchange(mixed_port: int, host: str, target_port: int, payload: bytes) -> bool:
    control, datagram, bind_port = socks_udp_associate(mixed_port)
    try:
        datagram.sendto(
            socks_udp_packet(host, target_port, payload), ("127.0.0.1", bind_port)
        )
        response, _ = datagram.recvfrom(65_535)
        _, _, body = decode_socks_udp(response)
        return body == payload
    finally:
        datagram.close()
        control.close()


def udp_exchange_retry(
    mixed_port: int,
    host: str,
    target_port: int,
    payload: bytes,
    *,
    attempts: int = 8,
) -> bool:
    for _ in range(attempts):
        try:
            if udp_exchange(mixed_port, host, target_port, payload):
                return True
        except (
            AssertionError,
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionResetError,
            EOFError,
            OSError,
            TimeoutError,
        ):
            pass
        time.sleep(0.15)
    return False


def udp_multi_dest(mixed_port: int, ports: list[int]) -> bool:
    control, datagram, bind_port = socks_udp_associate(mixed_port)
    try:
        for index, port in enumerate(ports):
            payload = f"dest-{index}".encode()
            datagram.sendto(
                socks_udp_packet("127.0.0.1", port, payload), ("127.0.0.1", bind_port)
            )
            response, _ = datagram.recvfrom(65_535)
            _, _, body = decode_socks_udp(response)
            if body != payload:
                return False
        return True
    finally:
        datagram.close()
        control.close()


def tuic_udp_record(
    name: str,
    server_port: int,
    *,
    relay_mode: str | None = None,
) -> str:
    extra = ""
    if relay_mode is not None:
        extra = f"    udp-relay-mode: {relay_mode}\n"
    return tuic_record(name, server_port) + extra


def snapshot(controller_port: int, name: str) -> dict[str, Any]:
    status, body = request(controller_port, "GET", f"/proxies/{name}")
    if status != 200:
        raise AssertionError((status, body))
    payload = json.loads(body)
    return {
        "name": payload["name"],
        "type": payload["type"],
        "udp": payload["udp"],
    }


def exercise(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    udp_echo, udp_port = start_udp_echo()
    udp_echo2, udp_port2 = start_udp_echo()
    udp_echo3, quic_port = start_udp_echo()
    mixed_port, controller_port, authority_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    authority_scratch = scratch / "authority"
    authority_scratch.mkdir()
    authority, authority_stdout, authority_stderr = start_authority(
        authority_binary, authority_scratch, authority_port
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: true
proxies:
{tuic_udp_record("tuic-native", authority_port, relay_mode="native")}{tuic_udp_record("tuic-quic", authority_port, relay_mode="quic")}rules:
  - DST-PORT,{udp_port},tuic-native
  - DST-PORT,{udp_port2},tuic-native
  - DST-PORT,{quic_port},tuic-quic
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        native_ready = udp_exchange_retry(
            mixed_port, "127.0.0.1", udp_port, b"native-ready"
        )
        native_large = udp_exchange_retry(
            mixed_port, "127.0.0.1", udp_port, LARGE_UDP
        )
        native_empty = udp_exchange_retry(mixed_port, "127.0.0.1", udp_port, b"")
        native_multi = False
        for _ in range(8):
            try:
                native_multi = udp_multi_dest(mixed_port, [udp_port, udp_port2])
                if native_multi:
                    break
            except (AssertionError, OSError, TimeoutError):
                time.sleep(0.15)
        native_reassociate = udp_exchange_retry(
            mixed_port, "127.0.0.1", udp_port, b"after-close"
        )
        quic_ready = udp_exchange_retry(
            mixed_port, "127.0.0.1", quic_port, b"quic-ready"
        )
        quic_large = udp_exchange_retry(
            mixed_port, "127.0.0.1", quic_port, LARGE_UDP
        )
        return {
            "native-ready": native_ready,
            "native-large": native_large,
            "native-empty": native_empty,
            "native-multi-dest": native_multi,
            "native-reassociate": native_reassociate,
            "quic-ready": quic_ready,
            "quic-large": quic_large,
            "alive": process.poll() is None,
            "native-snapshot": snapshot(controller_port, "tuic-native"),
            "quic-snapshot": snapshot(controller_port, "tuic-quic"),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop(authority)
        authority_stdout.close()
        authority_stderr.close()
        udp_echo.shutdown()
        udp_echo.server_close()
        udp_echo2.shutdown()
        udp_echo2.server_close()
        udp_echo3.shutdown()
        udp_echo3.server_close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-6hb-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6HTUIC_CARGO_TARGET", "phase-6hb")
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(
                    binaries[name], binaries["go"], scratch
                )
            observations["rust-accepts-max-udp-size"] = config_validation(
                binaries["rust"],
                root / "rust-validate-size",
                "proxies:\n"
                "  - name: sized\n"
                "    type: tuic\n"
                "    server: 127.0.0.1\n"
                "    port: 443\n"
                f"    uuid: {UUID}\n"
                "    password: x\n"
                "    max-udp-relay-packet-size: 1200\n",
            )
            observations["rust-rejects-max-datagram-frame-size"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-frame",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: tuic\n"
                "    server: 127.0.0.1\n"
                "    port: 443\n"
                f"    uuid: {UUID}\n"
                "    password: x\n"
                "    max-datagram-frame-size: 1400\n",
            )
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

    go = observations["go"]
    rust = observations["rust"]
    if (
        go != rust
        or not all(
            rust[key]
            for key in (
                "native-ready",
                "native-large",
                "native-empty",
                "native-multi-dest",
                "native-reassociate",
                "quic-ready",
                "quic-large",
                "alive",
            )
        )
        or not observations.get("rust-accepts-max-udp-size", False)
        or not observations.get("rust-rejects-max-datagram-frame-size", False)
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {
                    "go": go,
                    "rust": rust,
                    "rust-accepts-max-udp-size": observations.get(
                        "rust-accepts-max-udp-size"
                    ),
                    "rust-rejects-max-datagram-frame-size": observations.get(
                        "rust-rejects-max-datagram-frame-size"
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("6H-B TUIC v5 UDP differential passed")
    print(json.dumps(rust, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

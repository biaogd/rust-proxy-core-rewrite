#!/usr/bin/env python3
"""Go/Rust differential for 7E-B Snell v3 outbound UDP."""

from __future__ import annotations

import json
import os
import pathlib
import socketserver
import tempfile
import threading
import time
from typing import Any

from hy2_support import build_binaries
from phase1 import ROOT, cargo_target_path, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import debug_files
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_udp import decode_socks_udp, socks_udp_packet
from phase6h_tuic_udp import socks_udp_associate
from phase7e_snell_tcp import (
    PSK,
    PSK_V3,
    authority_binary,
    config_validation,
    proxy_snapshot,
    snell_record,
    start_authority,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase7e-snell-udp-diff.json"
LARGE_UDP = bytes(range(256)) * 4  # 1024 bytes, under Snell 0x3FFF record cap


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(data, self.client_address)


def listen_udp_echo() -> tuple[socketserver.ThreadingUDPServer, threading.Thread, int]:
    server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    server.allow_reuse_address = True
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, port


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


def udp_multi_dest(mixed_port: int, host: str, ports: list[int]) -> bool:
    control, datagram, bind_port = socks_udp_associate(mixed_port)
    try:
        for index, port in enumerate(ports):
            payload = f"dest-{index}".encode()
            datagram.sendto(
                socks_udp_packet(host, port, payload), ("127.0.0.1", bind_port)
            )
            response, _ = datagram.recvfrom(65_535)
            _, _, body = decode_socks_udp(response)
            if body != payload:
                return False
        return True
    finally:
        datagram.close()
        control.close()


def exercise(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    echo, echo_thread, echo_port = listen_udp_echo()
    echo2, echo2_thread, echo_port2 = listen_udp_echo()
    _ = echo_thread, echo2_thread

    mixed_port, controller_port, authority_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority, scratch / "authority", authority_port, PSK_V3, 3
    )

    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
hosts:
  echo.snell.test: 127.0.0.1
proxies:
{snell_record("inline-snell", authority_port, PSK_V3, version=3, extra="    udp: true\n")}
rules:
  - MATCH,inline-snell
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        time.sleep(0.3)

        udp_ready = udp_exchange_retry(mixed_port, "127.0.0.1", echo_port, b"udp-ready")
        udp_large = udp_exchange_retry(mixed_port, "127.0.0.1", echo_port, LARGE_UDP)
        udp_empty = udp_exchange_retry(mixed_port, "127.0.0.1", echo_port, b"")
        domain_udp = udp_exchange_retry(
            mixed_port, "echo.snell.test", echo_port, b"udp-domain"
        )
        udp_multi = False
        for _ in range(8):
            try:
                udp_multi = udp_multi_dest(
                    mixed_port, "127.0.0.1", [echo_port, echo_port2]
                )
                if udp_multi:
                    break
            except (AssertionError, OSError, TimeoutError):
                time.sleep(0.15)
        udp_reassociate = udp_exchange_retry(
            mixed_port, "127.0.0.1", echo_port, b"after-close"
        )
        snapshot = proxy_snapshot(controller_port, "inline-snell")
        return {
            "udp-ready": udp_ready,
            "udp-large": udp_large,
            "udp-empty": udp_empty,
            "udp-domain": domain_udp,
            "udp-multi-dest": udp_multi,
            "udp-reassociate": udp_reassociate,
            "snapshot": {
                "name": snapshot["name"],
                "type": snapshot["type"],
                "udp": snapshot["udp"],
            },
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop(authority_process)
        authority_stdout.close()
        authority_stderr.close()
        echo.shutdown()
        echo.server_close()
        echo2.shutdown()
        echo2.server_close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-7eb-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE7ESNELL_CARGO_TARGET", "phase-7ea")
        authority = authority_binary()
        if not authority.exists():
            target = cargo_target_path("PHASE7ESNELL_CARGO_TARGET", "phase-7ea")
            profile = os.environ.get("HY2_BUILD_PROFILE", "debug")
            raise RuntimeError(
                f"rewrite-snell-authority was not built: {target / profile}"
            )
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], authority, scratch)
            observations["rust-v3-udp-accepted"] = config_validation(
                binaries["rust"],
                root / "rust-validate-v3-udp",
                "proxies:\n"
                "  - name: ok\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK_V3}\n"
                "    version: 3\n"
                "    udp: true\n",
            )
            observations["rust-v1-udp-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-v1-udp",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK}\n"
                "    udp: true\n",
            )
            observations["rust-reuse-accepted"] = config_validation(
                binaries["rust"],
                root / "rust-validate-reuse",
                "proxies:\n"
                "  - name: ok\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK}\n"
                "    version: 3\n"
                "    udp: true\n"
                "    reuse: true\n",
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
    rust_only = [
        "rust-v3-udp-accepted",
        "rust-v1-udp-rejected",
        "rust-reuse-accepted",
    ]
    if (
        go != rust
        or not all(observations.get(key) for key in rust_only)
        or rust.get("snapshot", {}).get("udp") is not True
        or go.get("snapshot", {}).get("udp") is not True
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {
                    "go": go,
                    "rust": rust,
                    **{key: observations.get(key) for key in rust_only},
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("7E-B Snell v3 UDP differential passed")
    print(json.dumps(rust, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

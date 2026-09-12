#!/usr/bin/env python3
"""Go/Rust differential for 6I-B WireGuard userspace outbound UDP."""

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
from phase6i_wireguard_tcp import (
    authority_binary,
    config_validation,
    generate_keypair,
    proxy_snapshot,
    reachable_ipv4,
    start_authority,
    wg_record,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6i-wireguard-udp-diff.json"
LARGE_UDP = bytes(range(256)) * 4  # 1024 bytes, fits default MTU 1408 without frag


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(data, self.client_address)


def listen_udp_echo() -> tuple[socketserver.ThreadingUDPServer, threading.Thread, int]:
    server = socketserver.ThreadingUDPServer(("0.0.0.0", 0), UdpEchoHandler)
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


def wg_udp_record(
    name: str,
    server_port: int,
    private_key: str,
    public_key: str,
) -> str:
    return wg_record(
        name,
        server_port,
        private_key,
        public_key,
        extra="    udp: true\n",
    )


def exercise(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    client_private: str,
    client_public: str,
    server_private: str,
    server_public: str,
) -> dict[str, Any]:
    inner_host = reachable_ipv4()
    echo, echo_thread, echo_port = listen_udp_echo()
    echo2, echo2_thread, echo_port2 = listen_udp_echo()
    _ = echo_thread, echo2_thread

    mixed_port, controller_port, authority_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    authority_scratch = scratch / "authority"
    wg_process, authority_stdout, authority_stderr = start_authority(
        authority,
        authority_scratch,
        authority_port,
        server_private,
        client_public,
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
  echo.wg.test: {inner_host}
proxies:
{wg_udp_record("inline-wg", authority_port, client_private, server_public)}
rules:
  - MATCH,inline-wg
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        time.sleep(0.3)

        udp_ready = udp_exchange_retry(mixed_port, inner_host, echo_port, b"udp-ready")
        udp_large = udp_exchange_retry(mixed_port, inner_host, echo_port, LARGE_UDP)
        domain_udp = udp_exchange_retry(
            mixed_port, "echo.wg.test", echo_port, b"udp-domain"
        )
        udp_multi = False
        for _ in range(8):
            try:
                udp_multi = udp_multi_dest(mixed_port, inner_host, [echo_port, echo_port2])
                if udp_multi:
                    break
            except (AssertionError, OSError, TimeoutError):
                time.sleep(0.15)
        udp_reassociate = udp_exchange_retry(
            mixed_port, inner_host, echo_port, b"after-close"
        )
        snapshot = proxy_snapshot(controller_port, "inline-wg")
        return {
            "udp-ready": udp_ready,
            "udp-large": udp_large,
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
        stop(wg_process)
        authority_stdout.close()
        authority_stderr.close()
        echo.shutdown()
        echo.server_close()
        echo2.shutdown()
        echo2.server_close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-6ib-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6IWG_CARGO_TARGET", "phase-6ia")
        authority = authority_binary()
        if not authority.exists():
            target = cargo_target_path("PHASE6IWG_CARGO_TARGET", "phase-6ia")
            profile = os.environ.get("HY2_BUILD_PROFILE", "debug")
            raise RuntimeError(
                f"rewrite-wireguard-authority was not built: {target / profile}"
            )
        key_scratch = root / "keys"
        key_scratch.mkdir()
        client_private, client_public = generate_keypair(binaries["rust"], key_scratch)
        server_private, server_public = generate_keypair(binaries["rust"], key_scratch)
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(
                    binaries[name],
                    authority,
                    scratch,
                    client_private,
                    client_public,
                    server_private,
                    server_public,
                )
            observations["rust-ipv6-accepted"] = config_validation(
                binaries["rust"],
                root / "rust-validate-ipv6",
                "proxies:\n"
                "  - name: dual\n"
                "    type: wireguard\n"
                "    server: 127.0.0.1\n"
                "    port: 51820\n"
                f"    private-key: {client_private}\n"
                f"    public-key: {server_public}\n"
                "    ip: 10.0.0.2\n"
                "    ipv6: fd00::2\n",
            )
            observations["rust-remote-dns-accepted"] = config_validation(
                binaries["rust"],
                root / "rust-validate-dns",
                "proxies:\n"
                "  - name: dns\n"
                "    type: wireguard\n"
                "    server: 127.0.0.1\n"
                "    port: 51820\n"
                f"    private-key: {client_private}\n"
                f"    public-key: {server_public}\n"
                "    ip: 10.0.0.2\n"
                "    remote-dns-resolve: true\n"
                "    dns: [1.1.1.1, 8.8.8.8:53]\n",
            )
            observations["rust-amnezia-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-amnezia",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: wireguard\n"
                "    server: 127.0.0.1\n"
                "    port: 51820\n"
                f"    private-key: {client_private}\n"
                f"    public-key: {server_public}\n"
                "    ip: 10.0.0.2\n"
                "    amnezia-wg-option:\n"
                "      jc: 4\n",
            )
            observations["rust-peers-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-peers",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: wireguard\n"
                "    server: 127.0.0.1\n"
                "    port: 51820\n"
                f"    private-key: {client_private}\n"
                f"    public-key: {server_public}\n"
                "    ip: 10.0.0.2\n"
                "    peers:\n"
                "      - server: 127.0.0.1\n"
                "        port: 51820\n"
                f"        public-key: {server_public}\n"
                "        allowed-ips: [0.0.0.0/0]\n",
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
        or not observations.get("rust-ipv6-accepted", False)
        or not observations.get("rust-remote-dns-accepted", False)
        or not observations.get("rust-amnezia-rejected", False)
        or not observations.get("rust-peers-rejected", False)
        or rust.get("snapshot", {}).get("udp") is not True
        or go.get("snapshot", {}).get("udp") is not True
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(observations, indent=2, sort_keys=True)
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("6I-B WireGuard UDP differential passed")
    print(json.dumps(rust, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""IN-C Go/Rust differential for Trojan gRPC/Gun inbound TCP and UDP.

Named `type: trojan` listeners with `grpc-service-name` accept TLS + HTTP/2 Gun,
then Trojan auth/relay. Product Trojan outbound (`network: grpc`) exercises both
Go and Rust inbounds for TCP, UDP multi-dest, and wrong-password fail-closed.
Combined ws-path+grpc stays rejected until a shared HTTP mux lands.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import socket
import socketserver
import tempfile
import threading
import time
from typing import Any

from phase1 import (
    IO_DEADLINE,
    ROOT,
    EchoHandler,
    connect_tunnel,
    recv_exact,
    reserve_port,
    wait_ready,
)
from phase3 import UdpEchoHandler, launch, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase6e_vless_udp import exchange as socks_udp_exchange

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-inc-trojan-grpc-diff.json"
PASSWORD = "phase-inc-trojan-grpc-password"
SNI = "dot.phase4.test"
GRPC_SERVICE = "trojan"
LARGE_PAYLOAD = bytes(range(256)) * 256


def stage_tls_material(scratch: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    profile = scratch / ".config" / "mihomo"
    profile.mkdir(parents=True, exist_ok=True)
    certificate = profile / "server.pem"
    private_key = profile / "server-key.pem"
    shutil.copyfile(SERVER_CERTIFICATE, certificate)
    shutil.copyfile(SERVER_KEY, private_key)
    return certificate, private_key


def inbound_yaml(port: int, certificate: pathlib.Path, private_key: pathlib.Path) -> str:
    return f"""listeners:
  - name: trojan-grpc
    type: trojan
    listen: 127.0.0.1
    port: {port}
    certificate: {certificate}
    private-key: {private_key}
    grpc-service-name: {GRPC_SERVICE}
    users:
      - username: alice
        password: {PASSWORD}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""


def outbound_client_yaml(mixed_port: int, trojan_port: int, *, password: str = PASSWORD) -> str:
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: trojan-grpc
    type: trojan
    server: 127.0.0.1
    port: {trojan_port}
    password: {password}
    sni: {SNI}
    skip-cert-verify: true
    network: grpc
    grpc-opts:
      grpc-service-name: {GRPC_SERVICE}
    udp: true
proxy-groups:
  - name: PROXY
    type: select
    proxies: [trojan-grpc]
rules:
  - MATCH,PROXY
"""


def wait_tcp_route(process: Any, mixed_port: int, echo_port: int) -> None:
    wait_ready(process, mixed_port)
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"client exited during readiness with {process.returncode}")
        try:
            tunnel = connect_tunnel(mixed_port, "127.0.0.1", echo_port)
            try:
                tunnel.sendall(b"ready")
                if recv_exact(tunnel, 5) == b"ready":
                    return
            finally:
                tunnel.close()
        except (AssertionError, EOFError, OSError):
            pass
        time.sleep(0.02)
    raise TimeoutError("Trojan gRPC inbound route did not become ready")


def validate_config(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    observations: dict[str, bool] = {}
    scratch.mkdir(parents=True, exist_ok=True)
    accept_dir = scratch / "accept"
    accept_dir.mkdir()
    certificate, private_key = stage_tls_material(accept_dir)
    accept_port = reserve_port()
    good = scratch / "accept.yaml"
    good.write_text(inbound_yaml(accept_port, certificate, private_key))
    accepted = launch(binary, good, accept_dir)
    try:
        wait_ready(accepted[0], accept_port)
        observations["accept-named-grpc"] = accepted[0].poll() is None
    finally:
        stop(accepted[0])
        accepted[1].close()
        accepted[2].close()

    reject_dir = scratch / "reject"
    reject_dir.mkdir()
    reject_certificate, reject_key = stage_tls_material(reject_dir)
    reject_port = reserve_port()
    bad = scratch / "reject-ws-plus-grpc.yaml"
    bad.write_text(
        inbound_yaml(reject_port, reject_certificate, reject_key).replace(
            "grpc-service-name:",
            "ws-path: /trojan\n    grpc-service-name:",
        )
    )
    rejected = launch(binary, bad, reject_dir)
    try:
        deadline = time.monotonic() + IO_DEADLINE
        while rejected[0].poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        observations["reject-ws-plus-grpc"] = rejected[0].poll() is not None
    finally:
        stop(rejected[0])
        rejected[1].close()
        rejected[2].close()
    return observations


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    tcp_echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    tcp_echo.allow_reuse_address = True
    tcp_thread = threading.Thread(target=tcp_echo.serve_forever, daemon=True)
    tcp_thread.start()
    tcp_port = int(tcp_echo.server_address[1])

    udp_echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    udp_thread = threading.Thread(target=udp_echo.serve_forever, daemon=True)
    udp_thread.start()
    udp_port = int(udp_echo.server_address[1])

    server_dir = scratch / "server"
    server_dir.mkdir()
    certificate, private_key = stage_tls_material(server_dir)
    trojan_port = reserve_port()
    server_config = scratch / "server.yaml"
    server_config.write_text(inbound_yaml(trojan_port, certificate, private_key))
    server, server_out, server_err = launch(binary, server_config, server_dir)

    client_dir = scratch / "client"
    client_dir.mkdir()
    mixed_port = reserve_port()
    client_config = scratch / "client.yaml"
    client_config.write_text(outbound_client_yaml(mixed_port, trojan_port))
    client, client_out, client_err = launch(binary, client_config, client_dir)

    udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_client.bind(("127.0.0.1", 0))
    udp_client.settimeout(IO_DEADLINE)
    try:
        wait_ready(server, trojan_port)
        wait_tcp_route(client, mixed_port, tcp_port)

        tunnel = connect_tunnel(mixed_port, "127.0.0.1", tcp_port)
        try:
            small_payload = b"inc-grpc"
            tunnel.sendall(small_payload)
            small = recv_exact(tunnel, len(small_payload)) == small_payload
        finally:
            tunnel.close()

        tunnel = connect_tunnel(mixed_port, "127.0.0.1", tcp_port)
        try:
            tunnel.sendall(LARGE_PAYLOAD)
            large = recv_exact(tunnel, len(LARGE_PAYLOAD)) == LARGE_PAYLOAD
        finally:
            tunnel.close()

        wrong_dir = scratch / "wrong-client"
        wrong_dir.mkdir()
        wrong_mixed = reserve_port()
        wrong_config = scratch / "wrong-client.yaml"
        wrong_config.write_text(
            outbound_client_yaml(wrong_mixed, trojan_port, password="wrong-password")
        )
        wrong, wrong_out, wrong_err = launch(binary, wrong_config, wrong_dir)
        try:
            wait_ready(wrong, wrong_mixed)
            wrong_password = False
            try:
                tunnel = connect_tunnel(wrong_mixed, "127.0.0.1", tcp_port)
                try:
                    tunnel.sendall(b"should-fail")
                    wrong_password = recv_exact(tunnel, 11) != b"should-fail"
                finally:
                    tunnel.close()
            except (AssertionError, EOFError, OSError):
                wrong_password = True
        finally:
            stop(wrong)
            wrong_out.close()
            wrong_err.close()

        first = socks_udp_exchange(
            udp_client, mixed_port, "127.0.0.1", udp_port, b"inc-grpc-udp-1"
        )
        second = socks_udp_exchange(
            udp_client,
            mixed_port,
            "127.0.0.1",
            udp_port,
            b"inc-grpc-udp-2-" + (b"z" * 2048),
        )
        return {
            "config": validate_config(binary, scratch / "config-cases"),
            "small": small,
            "large": large,
            "wrong-password-rejected": wrong_password,
            "udp-multi-dest": bool(first and second),
            "process-alive": server.poll() is None and client.poll() is None,
        }
    finally:
        udp_client.close()
        stop(client)
        client_out.close()
        client_err.close()
        stop(server)
        server_out.close()
        server_err.close()
        tcp_echo.shutdown()
        tcp_echo.server_close()
        tcp_thread.join(timeout=1)
        udp_echo.shutdown()
        udp_echo.server_close()
        udp_thread.join(timeout=1)


def parity_view(observations: dict[str, Any]) -> dict[str, Any]:
    config = dict(observations["config"])
    config.pop("reject-ws-plus-grpc", None)
    return {
        "config": config,
        "small": observations["small"],
        "large": observations["large"],
        "wrong-password-rejected": observations["wrong-password-rejected"],
        "udp-multi-dest": observations["udp-multi-dest"],
        "process-alive": observations["process-alive"],
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-inc-trojan-grpc-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE_INC_TROJAN_GRPC_CARGO_TARGET", "phase-inc-trojan-grpc")
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], scratch)
            if not observations["rust"]["config"].get("reject-ws-plus-grpc"):
                raise AssertionError(
                    "Rust IN-C must reject combined Trojan ws-path + grpc-service-name"
                )
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "error": str(error),
                        "observations": observations,
                        "debug": debug_files(root),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            raise
    rust_parity = parity_view(observations["rust"])
    go_parity = parity_view(observations["go"])
    if rust_parity != go_parity:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        print(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

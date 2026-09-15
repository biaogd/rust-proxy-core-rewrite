#!/usr/bin/env python3
"""IN-E Go/Rust differential for VMess TLS named inbound TCP and UDP.

Both products expose a named `type: vmess` TLS listener. Product VMess outbound
(`alterId: 0`, `cipher: auto`) dials the named inbound for TCP small/large/
half-close and wrong-UUID fail-closed, plus standard-mode UDP (no
packet-encoding / XUDP). Mux/XUDP is covered by `phase_ine_vmess_xudp.py`;
WSS/gRPC by sibling IN-E scripts.

Scope: plain TLS only (certificate + private-key). Reality/mKCP/Mekya and
nonzero alterId stay rejected on Rust; combined ws+grpc stays rejected.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import socket
import socketserver
import subprocess
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
from phase3 import UdpEchoHandler, decode_socks_udp, launch, socks_udp_packet, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-ine-vmess-tls-diff.json"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
SNI = "dot.phase4.test"
LARGE_PAYLOAD = bytes(range(256)) * 256


def stage_tls_material(scratch: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    profile = scratch / ".config" / "mihomo"
    profile.mkdir(parents=True, exist_ok=True)
    certificate = profile / "server.pem"
    private_key = profile / "server-key.pem"
    shutil.copyfile(SERVER_CERTIFICATE, certificate)
    shutil.copyfile(SERVER_KEY, private_key)
    return certificate, private_key


def inbound_yaml(
    port: int,
    certificate: pathlib.Path,
    private_key: pathlib.Path,
    *,
    extra: str = "",
) -> str:
    return f"""listeners:
  - name: vmess-tls
    type: vmess
    listen: 127.0.0.1
    port: {port}
    certificate: {certificate}
    private-key: {private_key}
    users:
      - username: alice
        uuid: {UUID}
{extra}mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""


def outbound_client_yaml(mixed_port: int, vmess_port: int, *, uuid: str = UUID) -> str:
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: vmess-out
    type: vmess
    server: 127.0.0.1
    port: {vmess_port}
    uuid: {uuid}
    alterId: 0
    cipher: auto
    network: tcp
    tls: true
    servername: {SNI}
    skip-cert-verify: true
    udp: true
proxy-groups:
  - name: PROXY
    type: select
    proxies: [vmess-out]
rules:
  - MATCH,PROXY
"""


def product_round_trip(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    vmess_port: int,
    echo_port: int,
    payload: bytes,
    *,
    half_close: bool = False,
    label: str = "case",
    uuid: str = UUID,
) -> bool:
    client_dir = scratch / f"{label}-client"
    client_dir.mkdir(parents=True, exist_ok=True)
    mixed_port = reserve_port()
    config = client_dir / "client.yaml"
    config.write_text(outbound_client_yaml(mixed_port, vmess_port, uuid=uuid))
    process, stdout, stderr = launch(binary, config, client_dir)
    try:
        wait_ready(process, mixed_port)
        deadline = time.monotonic() + IO_DEADLINE
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return False
            try:
                tunnel = connect_tunnel(mixed_port, "127.0.0.1", echo_port)
                try:
                    tunnel.sendall(payload)
                    if half_close:
                        tunnel.shutdown(socket.SHUT_WR)
                    return recv_exact(tunnel, len(payload)) == payload
                finally:
                    tunnel.close()
            except (AssertionError, EOFError, OSError):
                time.sleep(0.02)
        return False
    except (AssertionError, EOFError, OSError):
        return False
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def socks_udp_exchange(mixed_port: int, echo_port: int, payload: bytes) -> bool:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(IO_DEADLINE)
    try:
        client.sendto(socks_udp_packet(echo_port, payload), ("127.0.0.1", mixed_port))
        packet, _ = client.recvfrom(65_535)
        address, port, body = decode_socks_udp(packet)
        return address == "127.0.0.1" and port == echo_port and body == payload
    finally:
        client.close()


def wait_tcp_route(process: Any, port: int, echo_port: int, binary: pathlib.Path, scratch: pathlib.Path) -> None:
    wait_ready(process, port)
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during TCP readiness with {process.returncode}")
        if product_round_trip(binary, scratch, port, echo_port, b"ready", label="ready"):
            return
        time.sleep(0.02)
    raise TimeoutError("VMess TLS TCP inbound route did not become ready")


def config_validation(binary: pathlib.Path, scratch: pathlib.Path, source: str) -> bool:
    config = scratch / f"validate-{len(list(scratch.glob('validate-*')))}.yaml"
    config.write_text(source)
    result = subprocess.run(
        [str(binary), "-t", "-f", str(config)],
        cwd=scratch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=IO_DEADLINE,
    )
    return result.returncode == 0


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
        observations["accept-named-tls"] = accepted[0].poll() is None
    finally:
        stop(accepted[0])
        accepted[1].close()
        accepted[2].close()
    return observations


def assert_rust_only_rejections(binary: pathlib.Path, scratch: pathlib.Path) -> None:
    certificate, private_key = stage_tls_material(scratch)
    base_port = reserve_port()
    cases = {
        "ws-path+grpc-service-name": "    ws-path: /vmess\n    grpc-service-name: GunService\n",
        "nonzero-alterId": "",
    }
    for label, extra in cases.items():
        if label == "nonzero-alterId":
            source = f"""listeners:
  - name: vmess-bad
    type: vmess
    listen: 127.0.0.1
    port: {base_port}
    certificate: {certificate}
    private-key: {private_key}
    users:
      - uuid: {UUID}
        alterId: 1
mode: rule
rules:
  - MATCH,DIRECT
"""
        else:
            source = inbound_yaml(base_port, certificate, private_key, extra=extra)
        if config_validation(binary, scratch, source):
            raise AssertionError(f"Rust must reject named VMess field: {label}")


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

    certificate, private_key = stage_tls_material(scratch)
    vmess_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(inbound_yaml(vmess_port, certificate, private_key))
    process, stdout, stderr = launch(binary, config, scratch)

    client_dir = scratch / "udp-client"
    client_dir.mkdir()
    mixed_port = reserve_port()
    client_config = client_dir / "client.yaml"
    client_config.write_text(outbound_client_yaml(mixed_port, vmess_port))
    client, client_out, client_err = launch(binary, client_config, client_dir)
    try:
        wait_tcp_route(process, vmess_port, tcp_port, binary, scratch / "tcp-ready")
        small = product_round_trip(
            binary, scratch, vmess_port, tcp_port, b"ine-vmess", label="small"
        )
        large = product_round_trip(
            binary, scratch, vmess_port, tcp_port, LARGE_PAYLOAD, label="large"
        )
        half_close = product_round_trip(
            binary,
            scratch,
            vmess_port,
            tcp_port,
            b"product-vmess-half-close",
            half_close=True,
            label="half-close",
        )
        wrong_uuid = not product_round_trip(
            binary,
            scratch,
            vmess_port,
            tcp_port,
            b"should-fail",
            label="wrong-uuid",
            uuid="00000000-0000-0000-0000-000000000000",
        )
        wait_ready(client, mixed_port)
        udp = False
        deadline = time.monotonic() + IO_DEADLINE
        while time.monotonic() < deadline:
            try:
                if socks_udp_exchange(mixed_port, udp_port, b"ine-udp-1"):
                    udp = socks_udp_exchange(
                        mixed_port, udp_port, b"ine-udp-2-" + (b"z" * 2048)
                    )
                    break
            except (AssertionError, OSError, TimeoutError, socket.timeout):
                time.sleep(0.02)
        return {
            "config": validate_config(binary, scratch / "config-cases"),
            "small": small,
            "large": large,
            "wrong-uuid-rejected": wrong_uuid,
            "product-outbound-half-close": half_close,
            "udp-multi-payload": udp,
            "process-alive": process.poll() is None and client.poll() is None,
        }
    finally:
        stop(client)
        client_out.close()
        client_err.close()
        stop(process)
        stdout.close()
        stderr.close()
        tcp_echo.shutdown()
        tcp_echo.server_close()
        tcp_thread.join(timeout=1)
        udp_echo.shutdown()
        udp_echo.server_close()
        udp_thread.join(timeout=1)


def parity_view(observations: dict[str, Any]) -> dict[str, Any]:
    return {
        "config": observations["config"],
        "small": observations["small"],
        "large": observations["large"],
        "wrong-uuid-rejected": observations["wrong-uuid-rejected"],
        "product-outbound-half-close": observations["product-outbound-half-close"],
        "udp-multi-payload": observations["udp-multi-payload"],
        "process-alive": observations["process-alive"],
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-ine-vmess-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE_INE_VMESS_CARGO_TARGET", "phase-ine-vmess")
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], scratch)
            assert_rust_only_rejections(binaries["rust"], root / "rust-rejections")
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
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

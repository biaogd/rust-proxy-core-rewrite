#!/usr/bin/env python3
"""IN-E Go/Rust differential for VMess TLS named inbound XUDP (Mux).

Product VMess outbound with `packet-encoding: xudp` proves Go and Rust named
`type: vmess` TLS inbounds accept Mux associations and relay multi-destination
UDP via SOCKS on the product's own outbound client.
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
    recv_exact,
    reserve_port,
    wait_ready,
)
from phase3 import UdpEchoHandler, decode_socks_udp, launch, socks_udp_packet, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-ine-vmess-xudp-diff.json"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
SNI = "dot.phase4.test"
PAYLOAD_SMALL = b"ine-vmess-xudp"
PAYLOAD_LARGE = bytes(range(256)) * 8


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
    extra_rules: str = "",
) -> str:
    return f"""listeners:
  - name: vmess-xudp
    type: vmess
    listen: 127.0.0.1
    port: {port}
    certificate: {certificate}
    private-key: {private_key}
    users:
      - username: alice
        uuid: {UUID}
mode: rule
log-level: info
ipv6: false
rules:
{extra_rules}  - MATCH,DIRECT
"""


def outbound_client_yaml(mixed_port: int, vmess_port: int) -> str:
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: vmess-xudp-out
    type: vmess
    server: 127.0.0.1
    port: {vmess_port}
    uuid: {UUID}
    alterId: 0
    cipher: auto
    network: tcp
    tls: true
    udp: true
    packet-encoding: xudp
    servername: {SNI}
    skip-cert-verify: true
proxy-groups:
  - name: PROXY
    type: select
    proxies: [vmess-xudp-out]
rules:
  - MATCH,PROXY
"""


def socks_udp_exchange(
    mixed_port: int,
    echo_port: int,
    payload: bytes,
    *,
    client: socket.socket | None = None,
) -> bool:
    owns_client = client is None
    if client is None:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        client.settimeout(IO_DEADLINE)
    try:
        client.sendto(socks_udp_packet(echo_port, payload), ("127.0.0.1", mixed_port))
        packet, _ = client.recvfrom(65_535)
        address, port, body = decode_socks_udp(packet)
        return address == "127.0.0.1" and port == echo_port and body == payload
    finally:
        if owns_client:
            client.close()


def wait_udp_route(process: Any, mixed_port: int, echo_port: int) -> None:
    wait_ready(process, mixed_port)
    deadline = time.monotonic() + (2 * IO_DEADLINE)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during UDP readiness with {process.returncode}")
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        client.settimeout(0.25)
        try:
            client.sendto(socks_udp_packet(echo_port, b"ready"), ("127.0.0.1", mixed_port))
            packet, _ = client.recvfrom(65_535)
            address, port, body = decode_socks_udp(packet)
            if address == "127.0.0.1" and port == echo_port and body == b"ready":
                return
        except (AssertionError, OSError, TimeoutError, socket.timeout):
            pass
        finally:
            client.close()
        time.sleep(0.02)
    raise TimeoutError("VMess XUDP SOCKS UDP route did not become ready")


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo_a = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    echo_a.allow_reuse_address = True
    thread_a = threading.Thread(target=echo_a.serve_forever, daemon=True)
    thread_a.start()
    echo_a_port = int(echo_a.server_address[1])

    echo_b = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    echo_b.allow_reuse_address = True
    thread_b = threading.Thread(target=echo_b.serve_forever, daemon=True)
    thread_b.start()
    echo_b_port = int(echo_b.server_address[1])

    certificate, private_key = stage_tls_material(scratch)
    vmess_port = reserve_port()
    server_cfg = scratch / "server.yaml"
    server_cfg.write_text(inbound_yaml(vmess_port, certificate, private_key))
    server, server_out, server_err = launch(binary, server_cfg, scratch)

    client_dir = scratch / "client"
    client_dir.mkdir()
    mixed_port = reserve_port()
    client_cfg = client_dir / "client.yaml"
    client_cfg.write_text(outbound_client_yaml(mixed_port, vmess_port))
    client, client_out, client_err = launch(binary, client_cfg, client_dir)

    association: socket.socket | None = None
    try:
        wait_udp_route(client, mixed_port, echo_a_port)
        small = socks_udp_exchange(mixed_port, echo_a_port, PAYLOAD_SMALL)
        large = socks_udp_exchange(mixed_port, echo_a_port, PAYLOAD_LARGE)

        association = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        association.bind(("127.0.0.1", 0))
        association.settimeout(IO_DEADLINE)
        multi_a = socks_udp_exchange(
            mixed_port, echo_a_port, b"xudp-dest-a", client=association
        )
        multi_b = socks_udp_exchange(
            mixed_port, echo_b_port, b"xudp-dest-b", client=association
        )
        return {
            "small": small,
            "large": large,
            "multi-dest-a": multi_a,
            "multi-dest-b": multi_b,
            "server-alive": server.poll() is None,
            "client-alive": client.poll() is None,
        }
    finally:
        if association is not None:
            association.close()
        stop(client)
        client_out.close()
        client_err.close()
        stop(server)
        server_out.close()
        server_err.close()
        echo_a.shutdown()
        echo_a.server_close()
        thread_a.join(timeout=1)
        echo_b.shutdown()
        echo_b.server_close()
        thread_b.join(timeout=1)


def exercise_allow_then_reject(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    echo_allow = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    echo_allow.allow_reuse_address = True
    thread_allow = threading.Thread(target=echo_allow.serve_forever, daemon=True)
    thread_allow.start()
    allow_port = int(echo_allow.server_address[1])

    echo_reject = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    echo_reject.allow_reuse_address = True
    thread_reject = threading.Thread(target=echo_reject.serve_forever, daemon=True)
    thread_reject.start()
    reject_port = int(echo_reject.server_address[1])

    certificate, private_key = stage_tls_material(scratch)
    vmess_port = reserve_port()
    server_cfg = scratch / "server.yaml"
    server_cfg.write_text(
        inbound_yaml(
            vmess_port,
            certificate,
            private_key,
            extra_rules=f"  - DST-PORT,{reject_port},REJECT\n",
        )
    )
    server, server_out, server_err = launch(binary, server_cfg, scratch)

    client_dir = scratch / "client"
    client_dir.mkdir()
    mixed_port = reserve_port()
    client_cfg = client_dir / "client.yaml"
    client_cfg.write_text(outbound_client_yaml(mixed_port, vmess_port))
    client, client_out, client_err = launch(binary, client_cfg, client_dir)

    association: socket.socket | None = None
    try:
        wait_udp_route(client, mixed_port, allow_port)
        association = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        association.bind(("127.0.0.1", 0))
        association.settimeout(IO_DEADLINE)
        allow_ok = socks_udp_exchange(
            mixed_port, allow_port, b"xudp-allow", client=association
        )
        association.settimeout(0.75)
        reject_leaked = False
        try:
            reject_leaked = socks_udp_exchange(
                mixed_port, reject_port, b"xudp-reject", client=association
            )
        except (AssertionError, OSError, TimeoutError, socket.timeout):
            reject_leaked = False
        return {
            "allow-ok": allow_ok,
            "reject-second-dest-blocked": allow_ok and not reject_leaked,
        }
    finally:
        if association is not None:
            association.close()
        stop(client)
        client_out.close()
        client_err.close()
        stop(server)
        server_out.close()
        server_err.close()
        echo_allow.shutdown()
        echo_allow.server_close()
        thread_allow.join(timeout=1)
        echo_reject.shutdown()
        echo_reject.server_close()
        thread_reject.join(timeout=1)


def parity_view(observations: dict[str, Any]) -> dict[str, Any]:
    return {
        "small": observations["small"],
        "large": observations["large"],
        "multi-dest-a": observations["multi-dest-a"],
        "multi-dest-b": observations["multi-dest-b"],
        "server-alive": observations["server-alive"],
        "client-alive": observations["client-alive"],
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-ine-vmess-xudp-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE_INE_VMESS_XUDP_CARGO_TARGET", "phase-ine-vmess-xudp")
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], scratch)
            observations["rust"]["allow-then-reject"] = exercise_allow_then_reject(
                binaries["rust"], root / "rust-reject"
            )
            observations["go"]["allow-then-reject"] = exercise_allow_then_reject(
                binaries["go"], root / "go-reject"
            )
            if not observations["rust"]["allow-then-reject"].get("reject-second-dest-blocked"):
                raise AssertionError("Rust IN-E XUDP must not leak rejected second destinations")
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

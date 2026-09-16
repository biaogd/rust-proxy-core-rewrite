#!/usr/bin/env python3
"""IN-F Go/Rust differential for TUIC v5 named inbound UDP.

Product TUIC outbound (`udp-relay-mode: native`) dials the named TUIC inbound.
SOCKS UDP associate covers small/large echo, multi-destination on one
association, and allow→reject per-destination re-match (asserted on Rust; Go
recorded).

Scope mirrors `phase_inf_tuic_tcp.py`: TLS cert/key, users uuid→password,
optional ALPN h3.
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
    reserve_port,
    wait_ready,
)
from phase3 import UdpEchoHandler, decode_socks_udp, launch, socks_udp_packet, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-inf-tuic-udp-diff.json"
PASSWORD = "phase-inf-tuic-udp-password"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
SNI = "dot.phase4.test"
PAYLOAD_SMALL = b"inf-tuic-udp"
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
  - name: tuic-udp-in
    type: tuic
    listen: 127.0.0.1
    port: {port}
    certificate: {certificate}
    private-key: {private_key}
    users:
      {UUID}: {PASSWORD}
    alpn:
      - h3
mode: rule
log-level: info
ipv6: false
rules:
{extra_rules}  - MATCH,DIRECT
"""


def outbound_client_yaml(mixed_port: int, tuic_port: int) -> str:
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: tuic-out
    type: tuic
    server: 127.0.0.1
    port: {tuic_port}
    uuid: {UUID}
    password: {PASSWORD}
    sni: {SNI}
    alpn: [h3]
    skip-cert-verify: true
    udp-relay-mode: native
proxy-groups:
  - name: PROXY
    type: select
    proxies: [tuic-out]
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


def wait_udp_route(
    process: Any,
    mixed_port: int,
    echo_port: int,
) -> None:
    wait_ready(process, mixed_port)
    deadline = time.monotonic() + max(IO_DEADLINE * 4, 20.0)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during UDP readiness with {process.returncode}")
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        client.settimeout(0.35)
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
        time.sleep(0.05)
    raise TimeoutError("TUIC UDP inbound route did not become ready")


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
    tuic_port = reserve_port()
    server_cfg = scratch / "server.yaml"
    server_cfg.write_text(inbound_yaml(tuic_port, certificate, private_key))
    server, server_out, server_err = launch(binary, server_cfg, scratch)

    client_dir = scratch / "client"
    client_dir.mkdir()
    mixed_port = reserve_port()
    client_cfg = client_dir / "client.yaml"
    client_cfg.write_text(outbound_client_yaml(mixed_port, tuic_port))
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
            mixed_port, echo_a_port, b"tuic-dest-a", client=association
        )
        multi_b = socks_udp_exchange(
            mixed_port, echo_b_port, b"tuic-dest-b", client=association
        )
        return {
            "small": small,
            "large": large,
            "multi-dest-a": multi_a,
            "multi-dest-b": multi_b,
            "process-alive": server.poll() is None and client.poll() is None,
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
    """First destination DIRECT, second DST-PORT REJECT on the same TUIC UDP assoc."""
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
    tuic_port = reserve_port()
    server_cfg = scratch / "server.yaml"
    server_cfg.write_text(
        inbound_yaml(
            tuic_port,
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
    client_cfg.write_text(outbound_client_yaml(mixed_port, tuic_port))
    client, client_out, client_err = launch(binary, client_cfg, client_dir)

    association: socket.socket | None = None
    try:
        wait_udp_route(client, mixed_port, allow_port)
        association = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        association.bind(("127.0.0.1", 0))
        association.settimeout(IO_DEADLINE)
        allow_ok = socks_udp_exchange(
            mixed_port, allow_port, b"tuic-allow", client=association
        )
        association.settimeout(0.75)
        reject_leaked = False
        try:
            reject_leaked = socks_udp_exchange(
                mixed_port, reject_port, b"tuic-reject", client=association
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
        "process-alive": observations["process-alive"],
    }


REQUIRED_TRUE = (
    "small",
    "large",
    "multi-dest-a",
    "multi-dest-b",
    "process-alive",
)


def required_cases_pass(parity: dict[str, Any]) -> bool:
    return all(parity.get(key) for key in REQUIRED_TRUE)


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-inf-tuic-udp-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE_INF_TUIC_UDP_CARGO_TARGET", "phase-inf-tuic-udp"
        )
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], scratch)
            rust_reject = exercise_allow_then_reject(
                binaries["rust"], root / "rust-allow-reject"
            )
            go_reject = exercise_allow_then_reject(
                binaries["go"], root / "go-allow-reject"
            )
            observations["rust"]["allow-then-reject"] = rust_reject
            observations["go"]["allow-then-reject"] = go_reject
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
    rust_reject = observations["rust"]["allow-then-reject"]
    if (
        rust_parity != go_parity
        or not required_cases_pass(rust_parity)
        or not rust_reject.get("allow-ok")
        or not rust_reject.get("reject-second-dest-blocked")
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        print(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

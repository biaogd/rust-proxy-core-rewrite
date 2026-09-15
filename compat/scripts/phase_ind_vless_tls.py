#!/usr/bin/env python3
"""IN-D Go/Rust differential for VLESS TLS named inbound TCP and UDP.

Both products expose a named `type: vless` TLS listener (Go:
`listener/inbound/vless.go` + `listener/sing_vless`; Rust:
`named_listeners::parse_vless_listener` + `runtime/vless_listener.rs`). A
shared Python VLESS wire client proves UUID auth, TCP relay, standard-mode
UDP-over-TLS and wrong-uuid fail-closed behavior directly against the wire
protocol (the same style `phase_inc_trojan_tls.py` uses for Trojan). Half-close
and one plain round trip are additionally proven through the product's own
VLESS *outbound* client dialing the same named inbound, matching the task's
"Product VLESS outbound vs Go/Rust named vless TLS inbound" requirement.

Scope for this slice (see `docs/rust-rewrite/roadmap.md` IN-D): native TLS
carrier only (WS/gRPC covered by sibling IN-D scripts), no Vision/REALITY, and
UDP is standard mode with one fixed destination per association (no packet-addr
). Mux/XUDP multi-destination is covered by `phase_ind_vless_xudp.py`; Vision
is covered by `phase_ind_vless_vision.py`. Certificate TLS remains the scope of this script; REALITY inbound is covered by
`phase_ind_vless_reality.py`. Combined ws+grpc and certificate+reality-config
stay rejected.
"""

from __future__ import annotations

import ipaddress
import json
import pathlib
import shutil
import socket
import socketserver
import ssl
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
from phase3 import UdpEchoHandler, launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-ind-vless-tls-diff.json"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
SNI = "dot.phase4.test"
LARGE_PAYLOAD = bytes(range(256)) * 256

VERSION = 0
COMMAND_TCP = 1
COMMAND_UDP = 2
ADDRESS_IPV4 = 1
ADDRESS_DOMAIN = 2
ADDRESS_IPV6 = 3


def encode_address(host: str) -> bytes:
    """VLESS address-type + address bytes (port is framed separately)."""
    try:
        packed = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode()
        return bytes([ADDRESS_DOMAIN, len(encoded)]) + encoded
    if isinstance(packed, ipaddress.IPv4Address):
        return bytes([ADDRESS_IPV4]) + packed.packed
    return bytes([ADDRESS_IPV6]) + packed.packed


def uuid_bytes(uuid_text: str) -> bytes:
    return bytes.fromhex(uuid_text.replace("-", ""))


def request_header(uuid_text: str, command: int, host: str, port: int) -> bytes:
    """version | uuid | addon-len(0) | cmd | port(be16) | atyp | addr."""
    return (
        bytes([VERSION])
        + uuid_bytes(uuid_text)
        + bytes([0])
        + bytes([command])
        + port.to_bytes(2, "big")
        + encode_address(host)
    )


def stage_tls_material(scratch: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """Copy fixtures under the product profile home for Go SAFE_PATHS."""
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
  - name: vless-tls
    type: vless
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


def outbound_client_yaml(mixed_port: int, vless_port: int) -> str:
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: vless-out
    type: vless
    server: 127.0.0.1
    port: {vless_port}
    uuid: {UUID}
    encryption: none
    network: tcp
    tls: true
    servername: {SNI}
    skip-cert-verify: true
proxy-groups:
  - name: PROXY
    type: select
    proxies: [vless-out]
rules:
  - MATCH,PROXY
"""


def connect_tls(port: int) -> ssl.SSLSocket:
    context = ssl.create_default_context(cafile=str(ROOT_CERTIFICATE))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    raw = socket.create_connection(("127.0.0.1", port), timeout=IO_DEADLINE)
    raw.settimeout(IO_DEADLINE)
    return context.wrap_socket(raw, server_hostname=SNI)


def vless_tcp_exchange(
    port: int,
    host: str,
    target_port: int,
    payload: bytes,
    *,
    uuid_text: str = UUID,
) -> bool:
    stream = connect_tls(port)
    try:
        stream.sendall(request_header(uuid_text, COMMAND_TCP, host, target_port) + payload)
        response = recv_exact(stream, 2)
        if response != b"\0\0":
            return False
        return recv_exact(stream, len(payload)) == payload
    finally:
        stream.close()


def vless_udp_exchange(
    port: int,
    host: str,
    target_port: int,
    payloads: list[bytes],
    *,
    uuid_text: str = UUID,
) -> bool:
    """Standard-mode VLESS UDP: one fixed destination per association.

    The Go server (`serverPacketConn`) writes the two-byte response header
    lazily, combined with the *first* reply packet's own length prefix,
    rather than immediately after the request like Rust. Reading the ack
    separately before any payload is sent would deadlock against Go, so the
    request header and first payload frame are sent together and every
    response (including the ack) is parsed as one continuous byte stream,
    exactly like the TCP exchange above.
    """
    stream = connect_tls(port)
    try:
        first_payload = payloads[0]
        first_frame = len(first_payload).to_bytes(2, "big") + first_payload
        stream.sendall(request_header(uuid_text, COMMAND_UDP, host, target_port) + first_frame)
        response = recv_exact(stream, 2)
        if response != b"\0\0":
            return False
        length = int.from_bytes(recv_exact(stream, 2), "big")
        if length != len(first_payload) or recv_exact(stream, length) != first_payload:
            return False
        for payload in payloads[1:]:
            frame = len(payload).to_bytes(2, "big") + payload
            stream.sendall(frame)
            length = int.from_bytes(recv_exact(stream, 2), "big")
            if length != len(payload):
                return False
            if recv_exact(stream, length) != payload:
                return False
        return True
    finally:
        stream.close()


def product_round_trip(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    vless_port: int,
    echo_port: int,
    payload: bytes,
    *,
    half_close: bool = False,
    label: str = "case",
) -> bool:
    """TCP exchange via product VLESS outbound -> named VLESS TLS inbound."""
    client_dir = scratch / f"{label}-client"
    client_dir.mkdir(parents=True, exist_ok=True)
    mixed_port = reserve_port()
    config = client_dir / "client.yaml"
    config.write_text(outbound_client_yaml(mixed_port, vless_port))
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


def wait_tcp_route(process: Any, port: int, echo_port: int) -> None:
    wait_ready(process, port)
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during TCP readiness with {process.returncode}")
        try:
            if vless_tcp_exchange(port, "127.0.0.1", echo_port, b"ready"):
                return
        except (AssertionError, EOFError, OSError, ssl.SSLError):
            pass
        time.sleep(0.02)
    raise TimeoutError("VLESS TLS TCP inbound route did not become ready")


def config_validation(binary: pathlib.Path, scratch: pathlib.Path, source: str) -> bool:
    """Runs `-t` validation and returns True when the config is accepted."""
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
    """Combined WS+gRPC stays rejected; cert+reality-config remains mutually exclusive."""
    certificate, private_key = stage_tls_material(scratch)
    base_port = reserve_port()
    cases = {
        "ws-path+grpc-service-name": "    ws-path: /vless\n    grpc-service-name: GunService\n",
        "certificate+reality-config": (
            "    reality-config:\n"
            "      dest: itunes.apple.com:443\n"
            "      private-key: yMqyglp3FKXPpjcrwNfBYCQS-UrXduKhlDVqqlnMrWw\n"
            "      short-id: [10f897e26c4b9478]\n"
            "      server-names: [itunes.apple.com]\n"
        ),
    }
    for label, extra in cases.items():
        accepted = config_validation(
            binary,
            scratch,
            inbound_yaml(base_port, certificate, private_key, extra=extra),
        )
        if accepted:
            raise AssertionError(f"Rust must reject named VLESS field: {label}")


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
    vless_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(inbound_yaml(vless_port, certificate, private_key))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_tcp_route(process, vless_port, tcp_port)
        small = vless_tcp_exchange(vless_port, "127.0.0.1", tcp_port, b"ind-vless")
        large = vless_tcp_exchange(vless_port, "127.0.0.1", tcp_port, LARGE_PAYLOAD)
        wrong_uuid = False
        try:
            wrong_uuid = not vless_tcp_exchange(
                vless_port,
                "127.0.0.1",
                tcp_port,
                b"should-fail",
                uuid_text="00000000-0000-0000-0000-000000000000",
            )
        except (AssertionError, EOFError, OSError, ssl.SSLError):
            wrong_uuid = True
        udp = vless_udp_exchange(
            vless_port,
            "127.0.0.1",
            udp_port,
            [b"ind-udp-1", b"ind-udp-2-" + (b"z" * 2048)],
        )
        product_small = product_round_trip(
            binary, scratch, vless_port, tcp_port, b"product-vless-out", label="small"
        )
        product_half_close = product_round_trip(
            binary,
            scratch,
            vless_port,
            tcp_port,
            b"product-vless-half-close",
            half_close=True,
            label="half-close",
        )
        return {
            "config": validate_config(binary, scratch / "config-cases"),
            "small": small,
            "large": large,
            "wrong-uuid-rejected": wrong_uuid,
            "udp-multi-payload": udp,
            "product-outbound-small": product_small,
            "product-outbound-half-close": product_half_close,
            "process-alive": process.poll() is None,
        }
    finally:
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
    """Shared Go/Rust fields. Rust-only IN-D deferred-key rejection stays out."""
    return {
        "config": observations["config"],
        "small": observations["small"],
        "large": observations["large"],
        "wrong-uuid-rejected": observations["wrong-uuid-rejected"],
        "udp-multi-payload": observations["udp-multi-payload"],
        "product-outbound-small": observations["product-outbound-small"],
        "product-outbound-half-close": observations["product-outbound-half-close"],
        "process-alive": observations["process-alive"],
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-ind-vless-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE_IND_VLESS_CARGO_TARGET", "phase-ind-vless")
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

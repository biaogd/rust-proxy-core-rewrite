#!/usr/bin/env python3
"""IN-C Go/Rust differential for Trojan TLS inbound TCP and UDP-over-TLS.

Both products expose a named `type: trojan` TLS listener. A shared Python
Trojan TLS client proves password auth, TCP relay, half-close, UDP multi-dest
echo and wrong-password fail-closed behavior against Go and Rust inbounds.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import pathlib
import shutil
import socket
import socketserver
import ssl
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, EchoHandler, recv_exact, reserve_port, wait_ready
from phase3 import UdpEchoHandler, launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-inc-trojan-tls-diff.json"
PASSWORD = "phase-inc-trojan-password"
SNI = "dot.phase4.test"
LARGE_PAYLOAD = bytes(range(256)) * 256


def password_key(password: str) -> bytes:
    return hashlib.sha224(password.encode()).hexdigest().encode()


def encode_address(host: str, port: int) -> bytes:
    try:
        packed = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode()
        return bytes([3, len(encoded)]) + encoded + port.to_bytes(2, "big")
    if isinstance(packed, ipaddress.IPv4Address):
        return bytes([1]) + packed.packed + port.to_bytes(2, "big")
    return bytes([4]) + packed.packed + port.to_bytes(2, "big")


def stage_tls_material(scratch: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """Copy fixtures under the product profile home for Go SAFE_PATHS."""
    profile = scratch / ".config" / "mihomo"
    profile.mkdir(parents=True, exist_ok=True)
    certificate = profile / "server.pem"
    private_key = profile / "server-key.pem"
    shutil.copyfile(SERVER_CERTIFICATE, certificate)
    shutil.copyfile(SERVER_KEY, private_key)
    return certificate, private_key


def inbound_yaml(port: int, certificate: pathlib.Path, private_key: pathlib.Path) -> str:
    return f"""listeners:
  - name: trojan-tls
    type: trojan
    listen: 127.0.0.1
    port: {port}
    certificate: {certificate}
    private-key: {private_key}
    users:
      - username: alice
        password: {PASSWORD}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""


def connect_tls(port: int) -> ssl.SSLSocket:
    context = ssl.create_default_context(cafile=str(ROOT_CERTIFICATE))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_alpn_protocols(["h2", "http/1.1"])
    raw = socket.create_connection(("127.0.0.1", port), timeout=IO_DEADLINE)
    raw.settimeout(IO_DEADLINE)
    return context.wrap_socket(raw, server_hostname=SNI)


def trojan_tcp_exchange(
    port: int,
    host: str,
    target_port: int,
    payload: bytes,
    *,
    password: str = PASSWORD,
    half_close: bool = False,
) -> bool:
    stream = connect_tls(port)
    try:
        header = password_key(password) + b"\r\n\x01" + encode_address(host, target_port) + b"\r\n"
        stream.sendall(header + payload)
        if half_close:
            stream.shutdown(socket.SHUT_WR)
        return recv_exact(stream, len(payload)) == payload
    finally:
        stream.close()


def trojan_udp_exchange(
    port: int,
    destinations: list[tuple[str, int, bytes]],
    *,
    password: str = PASSWORD,
) -> bool:
    stream = connect_tls(port)
    try:
        initial_host, initial_port, _ = destinations[0]
        header = (
            password_key(password)
            + b"\r\n\x03"
            + encode_address(initial_host, initial_port)
            + b"\r\n"
        )
        stream.sendall(header)
        for host, target_port, payload in destinations:
            frame = (
                encode_address(host, target_port)
                + len(payload).to_bytes(2, "big")
                + b"\r\n"
                + payload
            )
            stream.sendall(frame)
            reply_address = encode_address(host, target_port)
            got_address = recv_exact(stream, len(reply_address))
            if got_address != reply_address:
                return False
            length = int.from_bytes(recv_exact(stream, 2), "big")
            if length != len(payload) or recv_exact(stream, 2) != b"\r\n":
                return False
            if recv_exact(stream, length) != payload:
                return False
        return True
    finally:
        stream.close()


def wait_tcp_route(process: Any, port: int, echo_port: int) -> None:
    wait_ready(process, port)
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during TCP readiness with {process.returncode}")
        try:
            if trojan_tcp_exchange(port, "127.0.0.1", echo_port, b"ready"):
                return
        except (AssertionError, EOFError, OSError, ssl.SSLError):
            pass
        time.sleep(0.02)
    raise TimeoutError("Trojan TLS TCP inbound route did not become ready")


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

    reject_dir = scratch / "reject"
    reject_dir.mkdir()
    reject_certificate, reject_key = stage_tls_material(reject_dir)
    reject_port = reserve_port()
    bad = scratch / "reject-ws.yaml"
    bad.write_text(
        inbound_yaml(reject_port, reject_certificate, reject_key).replace(
            "users:",
            "ws-path: /trojan\n    users:",
        )
    )
    rejected = launch(binary, bad, reject_dir)
    try:
        deadline = time.monotonic() + IO_DEADLINE
        while rejected[0].poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        observations["reject-ws-path"] = rejected[0].poll() is not None
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

    certificate, private_key = stage_tls_material(scratch)
    trojan_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(inbound_yaml(trojan_port, certificate, private_key))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_tcp_route(process, trojan_port, tcp_port)
        small = trojan_tcp_exchange(trojan_port, "127.0.0.1", tcp_port, b"inc-trojan")
        large = trojan_tcp_exchange(trojan_port, "127.0.0.1", tcp_port, LARGE_PAYLOAD)
        half_close = trojan_tcp_exchange(
            trojan_port,
            "127.0.0.1",
            tcp_port,
            b"half-close",
            half_close=True,
        )
        wrong_password = False
        try:
            wrong_password = not trojan_tcp_exchange(
                trojan_port,
                "127.0.0.1",
                tcp_port,
                b"should-fail",
                password="wrong-password",
            )
        except (AssertionError, EOFError, OSError, ssl.SSLError):
            wrong_password = True
        udp = trojan_udp_exchange(
            trojan_port,
            [
                ("127.0.0.1", udp_port, b"inc-udp-1"),
                ("127.0.0.1", udp_port, b"inc-udp-2-" + (b"z" * 2048)),
            ],
        )
        return {
            "config": validate_config(binary, scratch / "config-cases"),
            "small": small,
            "large": large,
            "half-close": half_close,
            "wrong-password-rejected": wrong_password,
            "udp-multi-dest": udp,
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
    """Shared Go/Rust fields. Rust-only IN-C carrier rejection stays out of equality."""
    config = dict(observations["config"])
    config.pop("reject-ws-path", None)
    return {
        "config": config,
        "small": observations["small"],
        "large": observations["large"],
        "half-close": observations["half-close"],
        "wrong-password-rejected": observations["wrong-password-rejected"],
        "udp-multi-dest": observations["udp-multi-dest"],
        "process-alive": observations["process-alive"],
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-inc-trojan-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE_INC_TROJAN_CARGO_TARGET", "phase-inc-trojan")
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], scratch)
            if not observations["rust"]["config"].get("reject-ws-path"):
                raise AssertionError("Rust IN-C must reject named Trojan ws-path")
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

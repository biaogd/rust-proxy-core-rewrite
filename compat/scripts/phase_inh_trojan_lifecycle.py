#!/usr/bin/env python3
"""IN-H-A Go/Rust differential for Trojan TLS inbound production lifecycle.

Covers invalid-reload rollback, listener removal reclaim, certificate path
rotation, credential isolation from /configs + logs, and a slow-handshake
bound. Not full production acceptance (no long soak / three-platform claim).
"""

from __future__ import annotations

import hashlib
import http.client
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

from phase1 import (
    IO_DEADLINE,
    ROOT,
    EchoHandler,
    recv_exact,
    reload_via_controller,
    reserve_port,
    wait_ready,
)
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-inh-trojan-lifecycle-diff.json"
PASSWORD = "phase-inh-trojan-password"
SNI = "dot.phase4.test"
SLOW_HANDSHAKE_BOUND_SECS = 12.0


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


def stage_tls_material(
    scratch: pathlib.Path, *, stem: str = "server"
) -> tuple[pathlib.Path, pathlib.Path]:
    profile = scratch / ".config" / "mihomo"
    profile.mkdir(parents=True, exist_ok=True)
    certificate = profile / f"{stem}.pem"
    private_key = profile / f"{stem}-key.pem"
    shutil.copyfile(SERVER_CERTIFICATE, certificate)
    shutil.copyfile(SERVER_KEY, private_key)
    return certificate, private_key


def inbound_yaml(
    *,
    mixed_port: int,
    controller_port: int,
    trojan_port: int | None,
    certificate: pathlib.Path | None,
    private_key: pathlib.Path | None,
) -> str:
    listeners = ""
    if trojan_port is not None and certificate is not None and private_key is not None:
        listeners = f"""listeners:
  - name: trojan-tls
    type: trojan
    listen: 127.0.0.1
    port: {trojan_port}
    certificate: {certificate}
    private-key: {private_key}
    users:
      - username: alice
        password: {PASSWORD}
"""
    return f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
{listeners}mode: rule
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
) -> bool:
    stream = connect_tls(port)
    try:
        header = password_key(password) + b"\r\n\x01" + encode_address(host, target_port) + b"\r\n"
        stream.sendall(header + payload)
        return recv_exact(stream, len(payload)) == payload
    finally:
        stream.close()


def wait_trojan_route(
    process: Any,
    port: int,
    echo_port: int,
    payload: bytes = b"ready",
) -> None:
    deadline = time.monotonic() + max(IO_DEADLINE * 4, 20.0)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during Trojan readiness with {process.returncode}")
        try:
            if trojan_tcp_exchange(port, "127.0.0.1", echo_port, payload):
                return
        except (AssertionError, EOFError, OSError, ssl.SSLError, TimeoutError):
            time.sleep(0.05)
    raise TimeoutError("Trojan TLS inbound route did not become ready")


def port_refused(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return False
    except ConnectionRefusedError:
        return True
    except OSError:
        return True


def wait_port_refused(process: Any, port: int) -> bool:
    deadline = time.monotonic() + max(IO_DEADLINE, 10.0)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited while waiting for port reclaim: {process.returncode}")
        if port_refused(port):
            return True
        time.sleep(0.05)
    return False


def get_configs(controller_port: int) -> bytes:
    status, body = request(controller_port, "GET", "/configs")
    if status != 200:
        raise AssertionError(f"GET /configs returned {status}: {body!r}")
    return body


def slow_handshake_bounded(port: int) -> bool:
    """TCP connect then stall before ClientHello; peer must close within bound."""
    raw = socket.create_connection(("127.0.0.1", port), timeout=IO_DEADLINE)
    raw.settimeout(SLOW_HANDSHAKE_BOUND_SECS + 2.0)
    started = time.monotonic()
    try:
        data = raw.recv(1)
        elapsed = time.monotonic() - started
        return data == b"" and elapsed <= SLOW_HANDSHAKE_BOUND_SECS
    except TimeoutError:
        return False
    finally:
        raw.close()


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    tcp_echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    tcp_echo.allow_reuse_address = True
    tcp_thread = threading.Thread(target=tcp_echo.serve_forever, daemon=True)
    tcp_thread.start()
    echo_port = int(tcp_echo.server_address[1])

    mixed_port = reserve_port()
    controller_port = reserve_port()
    trojan_port = reserve_port()
    certificate, private_key = stage_tls_material(scratch, stem="server-a")

    config = scratch / "config.yaml"
    config.write_text(
        inbound_yaml(
            mixed_port=mixed_port,
            controller_port=controller_port,
            trojan_port=trojan_port,
            certificate=certificate,
            private_key=private_key,
        )
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_trojan_route(process, trojan_port, echo_port, b"baseline")
        baseline = trojan_tcp_exchange(trojan_port, "127.0.0.1", echo_port, b"inh-baseline")

        # Invalid reload must fail and leave the Trojan listener serving.
        config.write_text("this: is: not: valid: yaml: [[[\n")
        reload_via_controller(
            process,
            controller_port,
            config,
            secret=SECRET,
            expected_status=400,
        )
        if process.poll() is not None:
            raise AssertionError("proxy exited after invalid reload")
        after_invalid = trojan_tcp_exchange(
            trojan_port, "127.0.0.1", echo_port, b"after-invalid-reload"
        )

        # Restore valid config on disk before further reloads.
        config.write_text(
            inbound_yaml(
                mixed_port=mixed_port,
                controller_port=controller_port,
                trojan_port=trojan_port,
                certificate=certificate,
                private_key=private_key,
            )
        )

        # Wrong-password attempt for credential isolation observations.
        wrong_password = not trojan_tcp_exchange(
            trojan_port,
            "127.0.0.1",
            echo_port,
            b"should-fail",
            password="wrong-password",
        )
        configs_body = get_configs(controller_port)
        configs_text = configs_body.decode("utf-8", errors="replace")
        # Flush recent logs into the captured files.
        time.sleep(0.2)
        stdout.flush()
        stderr.flush()
        stdout_path = scratch / "stdout.log"
        stderr_path = scratch / "stderr.log"
        log_blob = ""
        if stdout_path.exists():
            log_blob += stdout_path.read_text(errors="replace")
        if stderr_path.exists():
            log_blob += stderr_path.read_text(errors="replace")
        password_hash = password_key(PASSWORD).decode()
        credential_isolated = (
            PASSWORD not in configs_text
            and PASSWORD not in log_blob
            and password_hash not in configs_text
            and password_hash not in log_blob
        )

        slow_handshake = slow_handshake_bounded(trojan_port)
        after_slow = trojan_tcp_exchange(trojan_port, "127.0.0.1", echo_port, b"after-slow")

        # Certificate path rotation: new paths, same material; delete old files.
        rotated_cert, rotated_key = stage_tls_material(scratch, stem="server-b")
        config.write_text(
            inbound_yaml(
                mixed_port=mixed_port,
                controller_port=controller_port,
                trojan_port=trojan_port,
                certificate=rotated_cert,
                private_key=rotated_key,
            )
        )
        reload_via_controller(process, controller_port, config, secret=SECRET)
        certificate.unlink(missing_ok=True)
        private_key.unlink(missing_ok=True)
        wait_trojan_route(process, trojan_port, echo_port, b"rotated-ready")
        after_cert_rotation = trojan_tcp_exchange(
            trojan_port, "127.0.0.1", echo_port, b"after-cert-rotation"
        )

        # Listener removal reclaim.
        config.write_text(
            inbound_yaml(
                mixed_port=mixed_port,
                controller_port=controller_port,
                trojan_port=None,
                certificate=None,
                private_key=None,
            )
        )
        reload_via_controller(process, controller_port, config, secret=SECRET)
        listener_removed = wait_port_refused(process, trojan_port)
        process_alive = process.poll() is None
        # Mixed port should still accept connections after Trojan removal.
        mixed_alive = not port_refused(mixed_port)

        return {
            "baseline": baseline,
            "invalid-reload-rollback": after_invalid,
            "wrong-password-rejected": wrong_password,
            "credential-isolated": credential_isolated,
            "slow-handshake-bounded": slow_handshake,
            "after-slow-handshake": after_slow,
            "cert-path-rotation": after_cert_rotation,
            "listener-removed": listener_removed,
            "mixed-alive-after-removal": mixed_alive,
            "process-alive": process_alive,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        tcp_echo.shutdown()
        tcp_echo.server_close()
        tcp_thread.join(timeout=1)


REQUIRED_TRUE = (
    "baseline",
    "invalid-reload-rollback",
    "wrong-password-rejected",
    "credential-isolated",
    "slow-handshake-bounded",
    "after-slow-handshake",
    "cert-path-rotation",
    "listener-removed",
    "mixed-alive-after-removal",
    "process-alive",
)


def required_cases_pass(observations: dict[str, Any]) -> bool:
    return all(observations.get(key) for key in REQUIRED_TRUE)


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-inh-trojan-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE_INH_TROJAN_CARGO_TARGET", "phase-inh-trojan-lifecycle"
        )
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], scratch)
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
    if (
        observations["rust"] != observations["go"]
        or not required_cases_pass(observations["rust"])
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

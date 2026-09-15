#!/usr/bin/env python3
"""IN-D Go/Rust differential for VLESS Vision TLS named inbound.

Both products expose a named `type: vless` TLS listener with per-user
`flow: xtls-rprx-vision`. Product VLESS outbound with matching Vision flow
dials the inbound for TCP small/large relay, half-close, and nested TLS
DIRECT when the relay target is a TLS 1.3 echo. REALITY inbound stays out
of scope.
"""

from __future__ import annotations

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
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-ind-vless-vision-diff.json"
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
) -> str:
    return f"""listeners:
  - name: vless-vision
    type: vless
    listen: 127.0.0.1
    port: {port}
    certificate: {certificate}
    private-key: {private_key}
    users:
      - username: alice
        uuid: {UUID}
        flow: xtls-rprx-vision
mode: rule
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
    flow: xtls-rprx-vision
    servername: {SNI}
    skip-cert-verify: true
proxy-groups:
  - name: PROXY
    type: select
    proxies: [vless-out]
rules:
  - MATCH,PROXY
"""


class TlsEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certfile=str(SERVER_CERTIFICATE), keyfile=str(SERVER_KEY))
        with context.wrap_socket(self.request, server_side=True) as tls:
            tls.settimeout(IO_DEADLINE)
            payload = recv_exact(tls, 1)
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                payload += chunk
            tls.sendall(payload)


def listen_tls_echo() -> tuple[socketserver.ThreadingTCPServer, threading.Thread, int]:
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), TlsEchoHandler)
    server.allow_reuse_address = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, int(server.server_address[1])


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
    scratch.mkdir(parents=True, exist_ok=True)
    accept_dir = scratch / "accept"
    accept_dir.mkdir()
    certificate, private_key = stage_tls_material(accept_dir)
    accept_port = reserve_port()
    good = scratch / "accept.yaml"
    good.write_text(inbound_yaml(accept_port, certificate, private_key))
    process, stdout, stderr = launch(binary, good, accept_dir)
    try:
        wait_ready(process, accept_port)
        return {"accept-named-vision-tls": process.poll() is None}
    finally:
        stop(process)
        stdout.close()
        stderr.close()


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


def nested_tls_exchange(mixed_port: int, tls_echo_port: int, payload: bytes) -> bool:
    context = ssl.create_default_context(cafile=str(ROOT_CERTIFICATE))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    raw = connect_tunnel(mixed_port, "127.0.0.1", tls_echo_port)
    raw.settimeout(IO_DEADLINE)
    try:
        with context.wrap_socket(raw, server_hostname=SNI) as stream:
            stream.sendall(payload)
            return stream.recv(len(payload)) == payload
    except (AssertionError, EOFError, OSError, ssl.SSLError):
        return False


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    tcp_echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    tcp_echo.allow_reuse_address = True
    tcp_thread = threading.Thread(target=tcp_echo.serve_forever, daemon=True)
    tcp_thread.start()
    tcp_port = int(tcp_echo.server_address[1])

    tls_echo, tls_echo_thread, tls_echo_port = listen_tls_echo()

    certificate, private_key = stage_tls_material(scratch)
    vless_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(inbound_yaml(vless_port, certificate, private_key))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, vless_port)
        small = product_round_trip(
            binary, scratch, vless_port, tcp_port, b"ind-vless-vision", label="small"
        )
        large = product_round_trip(
            binary, scratch, vless_port, tcp_port, LARGE_PAYLOAD, label="large"
        )
        half_close = product_round_trip(
            binary,
            scratch,
            vless_port,
            tcp_port,
            b"ind-vless-vision-half",
            half_close=True,
            label="half-close",
        )
        mixed_port = reserve_port()
        nested_client_dir = scratch / "nested-client"
        nested_client_dir.mkdir(parents=True, exist_ok=True)
        nested_config = nested_client_dir / "client.yaml"
        nested_config.write_text(outbound_client_yaml(mixed_port, vless_port))
        nested_process, nested_stdout, nested_stderr = launch(
            binary, nested_config, nested_client_dir
        )
        try:
            wait_ready(nested_process, mixed_port)
            nested_tls = nested_tls_exchange(
                mixed_port, tls_echo_port, b"vision-nested-tls"
            )
        finally:
            stop(nested_process)
            nested_stdout.close()
            nested_stderr.close()
        return {
            "config": validate_config(binary, scratch / "config-cases"),
            "product-outbound-small": small,
            "product-outbound-large": large,
            "product-outbound-half-close": half_close,
            "nested-tls-direct": nested_tls,
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        tcp_echo.shutdown()
        tcp_echo.server_close()
        tcp_thread.join(timeout=1)
        tls_echo.shutdown()
        tls_echo.server_close()
        tls_echo_thread.join(timeout=1)


def parity_view(observations: dict[str, Any]) -> dict[str, Any]:
    return {
        "config": observations["config"],
        "product-outbound-small": observations["product-outbound-small"],
        "product-outbound-large": observations["product-outbound-large"],
        "product-outbound-half-close": observations["product-outbound-half-close"],
        "nested-tls-direct": observations["nested-tls-direct"],
        "process-alive": observations["process-alive"],
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-ind-vless-vision-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE_IND_VLESS_VISION_CARGO_TARGET", "phase-ind-vless-vision"
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

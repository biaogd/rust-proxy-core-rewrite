#!/usr/bin/env python3
"""IN-D Go/Rust differential for VLESS REALITY + Vision named inbound.

Both products expose a named `type: vless` listener with `reality-config` and
per-user `flow: xtls-rprx-vision`. Product VLESS outbound with matching
`reality-opts` + Vision flow dials each named inbound for TCP small/large
relay, half-close, and nested TLS DIRECT when the relay target is a TLS 1.3
echo. Dest camouflage fallback remains out of scope (auth-fail aborts).
"""

from __future__ import annotations

import json
import pathlib
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

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-ind-vless-reality-vision-diff.json"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
SNI = "dot.phase4.test"
LARGE_PAYLOAD = bytes(range(256)) * 256

REALITY_PUBLIC_KEY = "Cu7X8PtrU22DHCW46oyZfgEEFLoWMxJYWhHOpBIokhc"
REALITY_PRIVATE_KEY = "yMqyglp3FKXPpjcrwNfBYCQS-UrXduKhlDVqqlnMrWw"
REALITY_SHORT_ID = "10f897e26c4b9478"
REALITY_SERVER_NAME = "itunes.apple.com"
REALITY_DEST = "itunes.apple.com:443"


def inbound_yaml(port: int) -> str:
    return f"""listeners:
  - name: vless-reality-vision
    type: vless
    listen: 127.0.0.1
    port: {port}
    reality-config:
      dest: {REALITY_DEST}
      private-key: {REALITY_PRIVATE_KEY}
      short-id:
        - {REALITY_SHORT_ID}
      server-names:
        - {REALITY_SERVER_NAME}
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
    client-fingerprint: chrome
    servername: {REALITY_SERVER_NAME}
    reality-opts:
      public-key: {REALITY_PUBLIC_KEY}
      short-id: {REALITY_SHORT_ID}
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


def wait_reality_vision_route(
    binary: pathlib.Path,
    process: Any,
    scratch: pathlib.Path,
    vless_port: int,
    echo_port: int,
) -> None:
    wait_ready(process, vless_port)
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"proxy exited during REALITY+Vision readiness with {process.returncode}"
            )
        if product_round_trip(
            binary,
            scratch / "ready-probe",
            vless_port,
            echo_port,
            b"ready",
            label="ready",
        ):
            return
        time.sleep(0.05)
    raise TimeoutError("VLESS REALITY+Vision inbound route did not become ready")


def config_validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    scratch.mkdir(parents=True, exist_ok=True)
    port = reserve_port()
    good = scratch / "accept.yaml"
    good.write_text(inbound_yaml(port))
    accept_run = scratch / "accept-run"
    accept_run.mkdir(parents=True, exist_ok=True)
    accepted = launch(binary, good, accept_run)
    try:
        wait_ready(accepted[0], port)
        ok = accepted[0].poll() is None
    finally:
        stop(accepted[0])
        accepted[1].close()
        accepted[2].close()
    return {"accept-named-reality-vision": ok}


def assert_rust_only_rejections(binary: pathlib.Path, scratch: pathlib.Path) -> None:
    """PEM certificate + reality-config stays mutually exclusive on Rust."""
    scratch.mkdir(parents=True, exist_ok=True)
    reject = scratch / "reject-cert-reality.yaml"
    reject.write_text(
        inbound_yaml(reserve_port()).replace(
            "reality-config:",
            "certificate: ./missing.crt\n    private-key: ./missing.key\n    reality-config:",
        )
    )
    result = subprocess.run(
        [str(binary), "-t", "-f", str(reject)],
        cwd=scratch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=IO_DEADLINE,
    )
    if result.returncode == 0:
        raise AssertionError("Rust must reject certificate + reality-config")


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    tcp_echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    tcp_echo.allow_reuse_address = True
    tcp_thread = threading.Thread(target=tcp_echo.serve_forever, daemon=True)
    tcp_thread.start()
    tcp_port = int(tcp_echo.server_address[1])

    tls_echo, tls_echo_thread, tls_echo_port = listen_tls_echo()

    vless_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(inbound_yaml(vless_port))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_reality_vision_route(binary, process, scratch, vless_port, tcp_port)
        small = product_round_trip(
            binary, scratch, vless_port, tcp_port, b"ind-vless-reality-vision", label="small"
        )
        large = product_round_trip(
            binary, scratch, vless_port, tcp_port, LARGE_PAYLOAD, label="large"
        )
        half_close = product_round_trip(
            binary,
            scratch,
            vless_port,
            tcp_port,
            b"ind-vless-reality-vision-half",
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
                mixed_port, tls_echo_port, b"reality-vision-nested-tls"
            )
        finally:
            stop(nested_process)
            nested_stdout.close()
            nested_stderr.close()
        return {
            "config": config_validation(binary, scratch / "config-cases"),
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
    with tempfile.TemporaryDirectory(prefix="phase-ind-vless-reality-vision-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE_IND_VLESS_REALITY_VISION_CARGO_TARGET",
            "phase-ind-vless-reality-vision",
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

        assert_rust_only_rejections(binaries["rust"], root / "rust-only-rejections")

        rust_view = parity_view(observations["rust"])
        go_view = parity_view(observations["go"])
        if rust_view != go_view:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "rust": rust_view,
                        "go": go_view,
                        "debug": debug_files(root),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            raise SystemExit("IN-D VLESS REALITY+Vision Go/Rust differential mismatch")

        if not all(
            [
                rust_view["product-outbound-small"],
                rust_view["product-outbound-large"],
                rust_view["product-outbound-half-close"],
                rust_view["nested-tls-direct"],
                rust_view["config"]["accept-named-reality-vision"],
                rust_view["process-alive"],
            ]
        ):
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps({"observations": observations}, indent=2, sort_keys=True)
            )
            raise SystemExit("IN-D VLESS REALITY+Vision evidence failed")

    print(json.dumps({"phase-ind-vless-reality-vision": rust_view}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

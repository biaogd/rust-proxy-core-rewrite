#!/usr/bin/env python3
"""IN-F Go/Rust differential for TUIC v5 named inbound TCP.

Both products expose a named `type: tuic` QUIC listener. Product TUIC outbound
dials the named inbound for TCP small/large/half-close and wrong-password
fail-closed.

Scope: TLS certificate + private-key, users uuid→password, optional ALPN h3 and
congestion-controller. v4 token/ECH/client-auth/Brutal/cwnd stay rejected on Rust.
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
from phase3 import launch, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-inf-tuic-tcp-diff.json"
PASSWORD = "phase-inf-tuic-password"
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
  - name: tuic-in
    type: tuic
    listen: 127.0.0.1
    port: {port}
    certificate: {certificate}
    private-key: {private_key}
    users:
      {UUID}: {PASSWORD}
    alpn:
      - h3
{extra}mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""


def outbound_client_yaml(mixed_port: int, tuic_port: int, *, password: str = PASSWORD) -> str:
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
    password: {password}
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


def product_round_trip(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    tuic_port: int,
    echo_port: int,
    payload: bytes,
    *,
    half_close: bool = False,
    label: str = "case",
    password: str = PASSWORD,
) -> bool:
    client_dir = scratch / f"{label}-client"
    client_dir.mkdir(parents=True, exist_ok=True)
    mixed_port = reserve_port()
    config = client_dir / "client.yaml"
    config.write_text(outbound_client_yaml(mixed_port, tuic_port, password=password))
    process, stdout, stderr = launch(binary, config, client_dir)
    try:
        wait_ready(process, mixed_port)
        with connect_tunnel(mixed_port, "127.0.0.1", echo_port) as stream:
            stream.settimeout(IO_DEADLINE)
            stream.sendall(payload)
            if half_close:
                first = recv_exact(stream, 1)
                stream.shutdown(socket.SHUT_WR)
                rest = recv_exact(stream, len(payload) - 1) if len(payload) > 1 else b""
                return first + rest == payload
            return recv_exact(stream, len(payload)) == payload
    except (
        AssertionError,
        BrokenPipeError,
        ConnectionAbortedError,
        ConnectionResetError,
        EOFError,
        OSError,
        TimeoutError,
    ):
        return False
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def config_validation(binary: pathlib.Path, scratch: pathlib.Path, body: str) -> bool:
    scratch.mkdir(parents=True, exist_ok=True)
    config = scratch / f"validate-{len(list(scratch.glob('validate-*')))}.yaml"
    config.write_text(body)
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
    certificate, private_key = stage_tls_material(scratch)
    port = reserve_port()
    return {
        "accept-named-tuic": config_validation(
            binary, scratch, inbound_yaml(port, certificate, private_key)
        )
    }


def wait_tcp_route(
    process: subprocess.Popen[bytes],
    tuic_port: int,
    echo_port: int,
    binary: pathlib.Path,
    scratch: pathlib.Path,
) -> None:
    deadline = time.monotonic() + max(IO_DEADLINE * 4, 20.0)
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            if product_round_trip(
                binary, scratch, tuic_port, echo_port, b"ready", label="ready"
            ):
                return
        except Exception as error:  # noqa: BLE001
            last_error = error
        time.sleep(0.2)
    if last_error is not None:
        raise last_error
    raise TimeoutError("TUIC inbound TCP route did not become ready")


def assert_rust_only_rejections(binary: pathlib.Path, scratch: pathlib.Path) -> None:
    certificate, private_key = stage_tls_material(scratch)
    base_port = reserve_port()
    for label, extra in {
        "token": "    token: [v4-only-token]\n",
        "ech-key": "    ech-key: unused\n",
        "cwnd": "    cwnd: 10\n",
        "bbr-profile": "    bbr-profile: aggressive\n",
        "brutal": "    congestion-controller: brutal\n",
        "client-auth-type": "    client-auth-type: require-and-verify\n",
    }.items():
        source = inbound_yaml(base_port, certificate, private_key, extra=extra)
        if config_validation(binary, scratch, source):
            raise AssertionError(f"Rust must reject named TUIC field: {label}")


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    tcp_echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    tcp_echo.allow_reuse_address = True
    tcp_thread = threading.Thread(target=tcp_echo.serve_forever, daemon=True)
    tcp_thread.start()
    tcp_port = int(tcp_echo.server_address[1])

    certificate, private_key = stage_tls_material(scratch)
    tuic_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(inbound_yaml(tuic_port, certificate, private_key))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_tcp_route(process, tuic_port, tcp_port, binary, scratch / "tcp-ready")
        small = product_round_trip(
            binary, scratch, tuic_port, tcp_port, b"inf-tuic", label="small"
        )
        large = product_round_trip(
            binary, scratch, tuic_port, tcp_port, LARGE_PAYLOAD, label="large"
        )
        half_close = product_round_trip(
            binary,
            scratch,
            tuic_port,
            tcp_port,
            b"product-tuic-half-close",
            half_close=True,
            label="half-close",
        )
        wrong_password = not product_round_trip(
            binary,
            scratch,
            tuic_port,
            tcp_port,
            b"should-fail",
            label="wrong-password",
            password="wrong-password",
        )
        return {
            "config": validate_config(binary, scratch / "config-cases"),
            "small": small,
            "large": large,
            "wrong-password-rejected": wrong_password,
            "product-outbound-half-close": half_close,
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        tcp_echo.shutdown()
        tcp_echo.server_close()
        tcp_thread.join(timeout=1)


def parity_view(observations: dict[str, Any]) -> dict[str, Any]:
    return {
        "config": observations["config"],
        "small": observations["small"],
        "large": observations["large"],
        "wrong-password-rejected": observations["wrong-password-rejected"],
        "product-outbound-half-close": observations["product-outbound-half-close"],
        "process-alive": observations["process-alive"],
    }


REQUIRED_TRUE = (
    "small",
    "large",
    "product-outbound-half-close",
    "wrong-password-rejected",
    "process-alive",
)


def required_cases_pass(parity: dict[str, Any]) -> bool:
    if not all(parity.get(key) for key in REQUIRED_TRUE):
        return False
    config = parity.get("config")
    if not isinstance(config, dict):
        return False
    return bool(config.get("accept-named-tuic"))


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-inf-tuic-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE_INF_TUIC_CARGO_TARGET", "phase-inf-tuic")
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
    if rust_parity != go_parity or not required_cases_pass(rust_parity):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        print(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

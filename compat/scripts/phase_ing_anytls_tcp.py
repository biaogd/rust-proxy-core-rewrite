#!/usr/bin/env python3
"""IN-G Go/Rust differential for AnyTLS named inbound TCP.

Both products expose a named `type: anytls` TLS listener. Product AnyTLS
outbound dials the named inbound for TCP small/large/half-close and
wrong-password fail-closed.

Scope: TLS certificate + private-key, users map, default padding. Carriers
(ECH/mTLS/shadow-tls/res-tls/jls/allow-insecure) stay rejected on Rust.
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

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-ing-anytls-tcp-diff.json"
PASSWORD = "phase-ing-anytls-password"
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
  - name: anytls-in
    type: anytls
    listen: 127.0.0.1
    port: {port}
    certificate: {certificate}
    private-key: {private_key}
    users:
      alice: {PASSWORD}
{extra}mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""


def outbound_client_yaml(mixed_port: int, anytls_port: int, *, password: str = PASSWORD) -> str:
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: anytls-out
    type: anytls
    server: 127.0.0.1
    port: {anytls_port}
    password: {password}
    sni: {SNI}
    skip-cert-verify: true
    udp: true
    disable-reuse: true
proxy-groups:
  - name: PROXY
    type: select
    proxies: [anytls-out]
rules:
  - MATCH,PROXY
"""


def product_round_trip(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    anytls_port: int,
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
    config.write_text(outbound_client_yaml(mixed_port, anytls_port, password=password))
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
                        first = recv_exact(tunnel, 1)
                        tunnel.shutdown(socket.SHUT_WR)
                        rest = (
                            recv_exact(tunnel, len(payload) - 1) if len(payload) > 1 else b""
                        )
                        return first + rest == payload
                    return recv_exact(tunnel, len(payload)) == payload
                finally:
                    tunnel.close()
            except (AssertionError, EOFError, OSError, TimeoutError):
                time.sleep(0.05)
        return False
    except (AssertionError, EOFError, OSError, TimeoutError):
        return False
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def wait_tcp_route(
    process: Any,
    port: int,
    echo_port: int,
    binary: pathlib.Path,
    scratch: pathlib.Path,
) -> None:
    deadline = time.monotonic() + max(IO_DEADLINE * 4, 20.0)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during TCP readiness with {process.returncode}")
        if product_round_trip(binary, scratch, port, echo_port, b"ready", label="ready"):
            return
        time.sleep(0.1)
    raise TimeoutError("AnyTLS TCP inbound route did not become ready")


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
        observations["accept-named-anytls"] = accepted[0].poll() is None
    finally:
        stop(accepted[0])
        accepted[1].close()
        accepted[2].close()
    return observations


def assert_rust_only_rejections(binary: pathlib.Path, scratch: pathlib.Path) -> None:
    certificate, private_key = stage_tls_material(scratch)
    base_port = reserve_port()
    for label, extra in {
        "ech-key": "    ech-key: unused\n",
        "client-auth-type": "    client-auth-type: require-and-verify\n",
        "shadow-tls": "    shadow-tls:\n      enable: true\n",
        "res-tls": "    res-tls:\n      enable: true\n",
        "jls-config": "    jls-config:\n      enable: true\n",
        "allow-insecure": "    allow-insecure: true\n",
    }.items():
        source = inbound_yaml(base_port, certificate, private_key, extra=extra)
        if config_validation(binary, scratch, source):
            raise AssertionError(f"Rust must reject named AnyTLS field: {label}")


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    tcp_echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    tcp_echo.allow_reuse_address = True
    tcp_thread = threading.Thread(target=tcp_echo.serve_forever, daemon=True)
    tcp_thread.start()
    tcp_port = int(tcp_echo.server_address[1])

    certificate, private_key = stage_tls_material(scratch)
    anytls_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(inbound_yaml(anytls_port, certificate, private_key))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_tcp_route(process, anytls_port, tcp_port, binary, scratch / "tcp-ready")
        small = product_round_trip(
            binary, scratch, anytls_port, tcp_port, b"ing-anytls", label="small"
        )
        large = product_round_trip(
            binary, scratch, anytls_port, tcp_port, LARGE_PAYLOAD, label="large"
        )
        half_close = product_round_trip(
            binary,
            scratch,
            anytls_port,
            tcp_port,
            b"product-anytls-half-close",
            half_close=True,
            label="half-close",
        )
        wrong_password = not product_round_trip(
            binary,
            scratch,
            anytls_port,
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
    return bool(config.get("accept-named-anytls"))


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-ing-anytls-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE_ING_ANYTLS_CARGO_TARGET", "phase-ing-anytls")
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

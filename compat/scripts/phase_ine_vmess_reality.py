#!/usr/bin/env python3
"""IN-E / W3.3 Go/Rust differential for VMess REALITY named inbound (native TCP).

Both products expose a named `type: vmess` listener with `reality-config` (Go:
`listener/inbound/reality.go` + sing-vmess; Rust: `named_listeners` +
`accept_reality`). Product VMess outbound with `reality-opts` dials each named
inbound and proves TCP relay / half-close. Dest camouflage fallback is out of
scope for this slice (auth-fail aborts). PEM certificate + reality-config is a
Rust-only rejection (same posture as `phase_ind_vless_reality.py`).
Nonzero alterId stays rejected on Rust.
"""

from __future__ import annotations

import json
import pathlib
import socket
import socketserver
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
from phase5b1a import build_binaries, debug_files

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-ine-vmess-reality-diff.json"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
LARGE_PAYLOAD = bytes(range(256)) * 256

REALITY_PUBLIC_KEY = "Cu7X8PtrU22DHCW46oyZfgEEFLoWMxJYWhHOpBIokhc"
REALITY_PRIVATE_KEY = "yMqyglp3FKXPpjcrwNfBYCQS-UrXduKhlDVqqlnMrWw"
REALITY_SHORT_ID = "10f897e26c4b9478"
REALITY_SERVER_NAME = "itunes.apple.com"
REALITY_DEST = "itunes.apple.com:443"


def inbound_yaml(port: int) -> str:
    return f"""listeners:
  - name: vmess-reality
    type: vmess
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
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""


def outbound_client_yaml(mixed_port: int, vmess_port: int) -> str:
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: vmess-out
    type: vmess
    server: 127.0.0.1
    port: {vmess_port}
    uuid: {UUID}
    alterId: 0
    cipher: auto
    network: tcp
    tls: true
    client-fingerprint: chrome
    servername: {REALITY_SERVER_NAME}
    reality-opts:
      public-key: {REALITY_PUBLIC_KEY}
      short-id: {REALITY_SHORT_ID}
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
) -> bool:
    client_dir = scratch / f"{label}-client"
    client_dir.mkdir(parents=True, exist_ok=True)
    mixed_port = reserve_port()
    config = client_dir / "client.yaml"
    config.write_text(outbound_client_yaml(mixed_port, vmess_port))
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


def wait_reality_route(
    binary: pathlib.Path,
    process: Any,
    scratch: pathlib.Path,
    vmess_port: int,
    echo_port: int,
) -> None:
    wait_ready(process, vmess_port)
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during REALITY readiness with {process.returncode}")
        if product_round_trip(
            binary,
            scratch / "ready-probe",
            vmess_port,
            echo_port,
            b"ready",
            label="ready",
        ):
            return
        time.sleep(0.05)
    raise TimeoutError("VMess REALITY inbound route did not become ready")


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

    return {"accept-named-reality": ok}


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
    result = __import__("subprocess").run(
        [str(binary), "-t", "-f", str(reject)],
        cwd=scratch,
        stdout=__import__("subprocess").PIPE,
        stderr=__import__("subprocess").PIPE,
        check=False,
        timeout=IO_DEADLINE,
    )
    if result.returncode == 0:
        raise AssertionError("Rust must reject certificate + reality-config")

    nonzero = scratch / "reject-alterid.yaml"
    nonzero.write_text(
        inbound_yaml(reserve_port()).replace(
            f"uuid: {UUID}",
            f"uuid: {UUID}\n        alterId: 1",
        )
    )
    result = __import__("subprocess").run(
        [str(binary), "-t", "-f", str(nonzero)],
        cwd=scratch,
        stdout=__import__("subprocess").PIPE,
        stderr=__import__("subprocess").PIPE,
        check=False,
        timeout=IO_DEADLINE,
    )
    if result.returncode == 0:
        raise AssertionError("Rust must reject nonzero alterId on VMess inbound")


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    tcp_echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    tcp_echo.allow_reuse_address = True
    tcp_thread = threading.Thread(target=tcp_echo.serve_forever, daemon=True)
    tcp_thread.start()
    tcp_port = int(tcp_echo.server_address[1])

    vmess_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(inbound_yaml(vmess_port))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_reality_route(binary, process, scratch, vmess_port, tcp_port)
        small = product_round_trip(
            binary, scratch, vmess_port, tcp_port, b"ine-vmess-reality", label="small"
        )
        large = product_round_trip(
            binary, scratch, vmess_port, tcp_port, LARGE_PAYLOAD, label="large"
        )
        half_close = product_round_trip(
            binary,
            scratch,
            vmess_port,
            tcp_port,
            b"ine-vmess-reality-half-close",
            half_close=True,
            label="half-close",
        )
        return {
            "config": config_validation(binary, scratch / "config-cases"),
            "product-outbound-small": small,
            "product-outbound-large": large,
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
        "product-outbound-small": observations["product-outbound-small"],
        "product-outbound-large": observations["product-outbound-large"],
        "product-outbound-half-close": observations["product-outbound-half-close"],
        "process-alive": observations["process-alive"],
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-ine-vmess-reality-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE_INE_VMESS_REALITY_CARGO_TARGET", "phase-ine-vmess-reality"
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

        assert_rust_only_rejections(
            binaries["rust"], root / "rust-only-rejections"
        )

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
            raise SystemExit("IN-E VMess REALITY Go/Rust differential mismatch")

        if not all(
            [
                rust_view["product-outbound-small"],
                rust_view["product-outbound-large"],
                rust_view["product-outbound-half-close"],
                rust_view["config"]["accept-named-reality"],
                rust_view["process-alive"],
            ]
        ):
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps({"observations": observations}, indent=2, sort_keys=True)
            )
            raise SystemExit("IN-E VMess REALITY evidence failed")

    print(json.dumps({"phase-ine-vmess-reality": rust_view}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

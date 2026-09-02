#!/usr/bin/env python3
"""Go/Rust differential for Phase 6D-B explicit VMess AEAD framing."""

from __future__ import annotations

import ipaddress
import json
import pathlib
import socket
import subprocess
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, connect_proxy, recv_exact, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files
from phase6d_vmess_tcp import (
    build_authority,
    start_authority,
    vmess_record,
    wait_authority_destinations,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6d-vmess-aead-diff.json"


def connect_socks5_ip(proxy_port: int, host: str, port: int) -> socket.socket:
    stream = connect_proxy(proxy_port)
    stream.sendall(b"\x05\x01\x00")
    if recv_exact(stream, 2) != b"\x05\x00":
        stream.close()
        raise AssertionError("SOCKS5 method negotiation failed")
    address = ipaddress.ip_address(host)
    atyp = b"\x01" if address.version == 4 else b"\x04"
    stream.sendall(b"\x05\x01\x00" + atyp + address.packed + port.to_bytes(2, "big"))
    head = recv_exact(stream, 4)
    if head[:2] != b"\x05\x00":
        stream.close()
        raise AssertionError(f"SOCKS5 CONNECT failed: {head!r}")
    if head[3] == 1:
        recv_exact(stream, 4)
    elif head[3] == 4:
        recv_exact(stream, 16)
    elif head[3] == 3:
        recv_exact(stream, recv_exact(stream, 1)[0])
    else:
        stream.close()
        raise AssertionError(f"unexpected SOCKS5 reply address type: {head[3]}")
    recv_exact(stream, 2)
    return stream


def exchange(
    mixed_port: int,
    host: str,
    port: int,
    payload: bytes,
    *,
    half_close: bool,
) -> bool:
    # Domain targets use HTTP CONNECT; literal targets use SOCKS5 so IPv6
    # authority encoding is unambiguous.
    try:
        ipaddress.ip_address(host)
        stream = connect_socks5_ip(mixed_port, host, port)
    except ValueError:
        stream = connect_domain(mixed_port, host, port)
    with stream:
        stream.settimeout(IO_DEADLINE)
        stream.sendall(payload)
        if half_close:
            stream.shutdown(socket.SHUT_WR)
        return recv_exact(stream, len(payload)) == payload


def wait_exchange(
    process: subprocess.Popen[bytes], mixed_port: int, host: str, port: int
) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during VMess readiness: {process.returncode}")
        try:
            if exchange(mixed_port, host, port, b"ready", half_close=False):
                return
        except (AssertionError, EOFError, OSError):
            pass
        time.sleep(0.02)
    raise TimeoutError("explicit VMess AEAD route did not become ready")


def exercise(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    mixed_port = reserve_port()
    authority_port = reserve_port()
    authority, authority_stdout, authority_stderr, authority_stdout_path = (
        start_authority(authority_binary, scratch, authority_port)
    )
    combinations = [
        (cipher, global_padding, authenticated_length)
        for cipher in ["aes-128-gcm", "chacha20-poly1305"]
        for global_padding, authenticated_length in [
            (False, False),
            (True, False),
            (False, True),
            (True, True),
        ]
    ]
    destinations = [
        "aead.phase6d",
        "192.0.2.31",
        "2001:db8::31",
        "padding.phase6d",
        "192.0.2.32",
        "2001:db8::32",
        "auth-length.phase6d",
        "combined.phase6d",
    ]
    records = []
    rules = []
    expected_destinations: set[str] = set()
    for index, ((cipher, padding, authenticated), destination) in enumerate(
        zip(combinations, destinations, strict=True), start=1
    ):
        name = f"vmess-{index}"
        port = 22000 + index
        records.append(
            vmess_record(
                name,
                authority_port,
                cipher=cipher,
                global_padding=padding,
                authenticated_length=authenticated,
            )
        )
        rules.append(f"  - DST-PORT,{port},{name}")
        expected_destinations.add(f"{destination}:{port}")

    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: true
proxies:
{''.join(records)}rules:
{chr(10).join(rules)}
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_exchange(process, mixed_port, destinations[0], 22001)
        results: dict[str, bool] = {}
        payload = bytes(range(256)) * 512
        for index, ((cipher, padding, authenticated), destination) in enumerate(
            zip(combinations, destinations, strict=True), start=1
        ):
            key = f"{cipher}:padding={padding}:auth={authenticated}"
            results[key] = exchange(
                mixed_port,
                destination,
                22000 + index,
                payload,
                half_close=index in (1, 5),
            )
        observed = wait_authority_destinations(
            authority, authority_stdout_path, expected_destinations
        )
        return {
            "matrix": results,
            "destinations": observed,
            "survived": process.poll() is None,
        }
    finally:
        stop(process)
        stop(authority)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6d-vmess-aead-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE6DBVMESS_CARGO_TARGET", "phase6d-b-vmess"
        )
        authority = build_authority(root)
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, authority, scratch)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "error": f"{type(error).__name__}: {error}",
                        "observations": observations,
                        "debug": debug_files(root),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            raise
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6D-B explicit VMess AEAD differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

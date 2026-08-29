#!/usr/bin/env python3
"""Go/Rust differential for Shadowsocks UDP-over-TCP v1 and v2."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, cargo_target_path, reserve_port, wait_ready
from phase3 import UdpEchoHandler, decode_socks_udp, launch, socks_udp_packet, stop
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks import CIPHER, PASSWORD, SECRET, start_authority
from phase6c_shadowsocks_udp import domain_packet, proxy_snapshot


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-uot-diff.json"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path("PHASE6CSSUOT_CARGO_TARGET", "phase6c-shadowsocks-uot")
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def exchange(client: socket.socket, proxy_port: int, packet: bytes, expected: bytes) -> bool:
    client.sendto(packet, ("127.0.0.1", proxy_port))
    response, _ = client.recvfrom(65_535)
    address, _, payload = decode_socks_udp(response)
    return address == "127.0.0.1" and payload == expected


def wait_exchange(
    process: subprocess.Popen[bytes],
    client: socket.socket,
    proxy_port: int,
    packet: bytes,
    expected: bytes,
) -> bool:
    client.settimeout(0.2)
    deadline = time.monotonic() + (2 * IO_DEADLINE)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during UoT readiness: {process.returncode}")
        try:
            if exchange(client, proxy_port, packet, expected):
                client.settimeout(IO_DEADLINE)
                return True
        except TimeoutError:
            pass
        time.sleep(0.02)
    raise TimeoutError("Shadowsocks UoT route did not become ready")


def config_text(proxy_port: int, controller_port: int, authority_port: int, version: int) -> str:
    return f"""mixed-port: {proxy_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {CIPHER}
    password: {PASSWORD}
    udp: true
    udp-over-tcp: true
    udp-over-tcp-version: {version}
rules:
  - MATCH,local-ss
"""


def validate_versions(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    observed: dict[str, bool] = {}
    for version in [0, 1, 2, 3]:
        config = scratch / f"validate-{version}.yaml"
        config.write_text(config_text(17890, 17891, 17892, version))
        result = subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        observed[str(version)] = result.returncode == 0
    return observed


def exercise_version(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    version: int,
) -> dict[str, Any]:
    echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
    echo_thread.start()
    echo_port = int(echo.server_address[1])
    proxy_port = reserve_port()
    controller_port = reserve_port()
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority, scratch, authority_port
    )
    config = scratch / "config.yaml"
    config.write_text(config_text(proxy_port, controller_port, authority_port, version))
    process, stdout, stderr = launch(binary, config, scratch)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(IO_DEADLINE)
    try:
        wait_ready(process, proxy_port)
        first = f"uot-v{version}-first".encode()
        domain = f"uot-v{version}-domain".encode()
        reused = bytes(range(256)) * 12
        observed = {
            "ipv4": wait_exchange(
                process,
                client,
                proxy_port,
                socks_udp_packet(echo_port, first),
                first,
            ),
            "domain": exchange(
                client,
                proxy_port,
                domain_packet("localhost", echo_port, domain),
                domain,
            ),
            "same-client-session-reuse": exchange(
                client,
                proxy_port,
                socks_udp_packet(echo_port, reused),
                reused,
            ),
            "controller": proxy_snapshot(controller_port),
            "process-alive": process.poll() is None,
        }
    finally:
        client.close()
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        echo.shutdown()
        echo.server_close()
        echo_thread.join(timeout=IO_DEADLINE)
    authority_log = (scratch / "authority-stdout.log").read_text()
    observed["authority-uot-version"] = f"UOT {version}" in authority_log
    return observed


def exercise(binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    validation = scratch / "validation"
    validation.mkdir()
    observed: dict[str, Any] = {"config-versions": validate_versions(binary, validation)}
    for version in [1, 2]:
        version_scratch = scratch / f"v{version}"
        version_scratch.mkdir()
        observed[f"v{version}"] = exercise_version(
            binary, authority, version_scratch, version
        )
    return observed


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-uot-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE6CSSUOT_CARGO_TARGET", "phase6c-shadowsocks-uot"
        )
        authority = authority_binary()
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
    print("Phase 6C-F Shadowsocks UDP-over-TCP v1/v2 differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

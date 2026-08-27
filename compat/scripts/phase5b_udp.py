#!/usr/bin/env python3
"""Go/Rust differential for the complete current SOCKS5 UDP rule metadata set."""

from __future__ import annotations

import json
import pathlib
import socket
import socketserver
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import UdpEchoHandler, launch, socks_udp_packet, stop
from phase5b1a import build_binaries, debug_files


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5b-udp-diff.json"


def udp_client() -> socket.socket:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(0.3)
    return client


def udp_result(
    client: socket.socket,
    proxy_port: int,
    destination_port: int,
    payload: bytes,
) -> str:
    client.sendto(
        socks_udp_packet(destination_port, payload),
        ("127.0.0.1", proxy_port),
    )
    try:
        packet, _ = client.recvfrom(65_535)
    except TimeoutError:
        return "reject"
    if len(packet) < 10 or packet[:4] != b"\x00\x00\x00\x01":
        return "unexpected"
    return "direct" if packet[10:] == payload else "unexpected"


def wait_udp_result(
    process: Any,
    client: socket.socket,
    proxy_port: int,
    destination_port: int,
    expected: str,
    label: str,
) -> None:
    deadline = time.monotonic() + (2 * IO_DEADLINE) + 1
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during {label}: {process.returncode}")
        if udp_result(client, proxy_port, destination_port, label.encode()) == expected:
            return
        time.sleep(0.02)
    raise TimeoutError(f"{label} did not become {expected}")


def metadata_rule(source_port: int, destination_port: int, inbound_port: int) -> str:
    children = [
        "(NETWORK,UDP)",
        f"(SRC-PORT,{source_port})",
        f"(DST-PORT,{destination_port})",
        f"(IN-PORT,{inbound_port})",
        "(DSCP,0)",
        "(IN-TYPE,SOCKS5)",
        "(IN-NAME,DEFAULT-SOCKS)",
    ]
    return f"AND,({','.join(children)}),DIRECT"


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
    echo_thread.start()
    echo_port = int(echo.server_address[1])
    socks_port, mixed_port = reserve_port(), reserve_port()
    mixed_client = udp_client()
    socks_client = udp_client()
    unmatched_client = udp_client()
    config = scratch / "config.yaml"
    config.write_text(
        f"""socks-port: {socks_port}
mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
authentication:
  - alice:secret
rules:
  - IN-USER,alice,REJECT
  - {metadata_rule(mixed_client.getsockname()[1], echo_port, mixed_port)}
  - {metadata_rule(socks_client.getsockname()[1], echo_port, socks_port)}
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, socks_port)
        wait_ready(process, mixed_port)
        wait_udp_result(
            process,
            mixed_client,
            mixed_port,
            echo_port,
            "direct",
            "mixed-metadata",
        )
        wait_udp_result(
            process,
            socks_client,
            socks_port,
            echo_port,
            "direct",
            "socks-metadata",
        )
        wait_udp_result(
            process,
            unmatched_client,
            mixed_port,
            echo_port,
            "reject",
            "unmatched-source",
        )
        return {
            "mixed-metadata": udp_result(
                mixed_client, mixed_port, echo_port, b"mixed-final"
            ),
            "socks-metadata": udp_result(
                socks_client, socks_port, echo_port, b"socks-final"
            ),
            "unmatched-source": udp_result(
                unmatched_client, mixed_port, echo_port, b"reject-final"
            ),
        }
    finally:
        mixed_client.close()
        socks_client.close()
        unmatched_client.close()
        stop(process)
        stdout.close()
        stderr.close()
        echo.shutdown()
        echo.server_close()
        echo_thread.join(timeout=IO_DEADLINE)


def main() -> int:
    observations: dict[str, Any] = {}
    debug: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="phase5b-udp-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5BUDP_CARGO_TARGET", "phase5b-udp")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
            debug = debug_files(root)
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
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {"observations": observations, "debug": debug},
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5B current SOCKS5 UDP metadata differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for Phase 6D-E VMess UDP packet modes."""

from __future__ import annotations

import ipaddress
import json
import pathlib
import socket
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET
from phase6d_vmess_tcp import build_authority, start_authority, vmess_record


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6d-vmess-udp-diff.json"


def socks_udp_packet(host: str, port: int, payload: bytes) -> bytes:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("ascii")
        return (
            b"\x00\x00\x00\x03"
            + bytes([len(encoded)])
            + encoded
            + port.to_bytes(2, "big")
            + payload
        )
    if address.version == 4:
        return (
            b"\x00\x00\x00\x01"
            + address.packed
            + port.to_bytes(2, "big")
            + payload
        )
    return (
        b"\x00\x00\x00\x04"
        + address.packed
        + port.to_bytes(2, "big")
        + payload
    )


def decode_socks_udp(packet: bytes) -> tuple[str, int, bytes]:
    if len(packet) < 4 or packet[:3] != b"\x00\x00\x00":
        raise AssertionError(f"unexpected SOCKS UDP response: {packet!r}")
    address_type = packet[3]
    if address_type == 1:
        end = 8
        host = str(ipaddress.ip_address(packet[4:end]))
    elif address_type == 4:
        end = 20
        host = str(ipaddress.ip_address(packet[4:end]))
    else:
        raise AssertionError(f"unexpected SOCKS UDP address type: {address_type}")
    if len(packet) < end + 2:
        raise AssertionError("truncated SOCKS UDP response")
    port = int.from_bytes(packet[end : end + 2], "big")
    return host, port, packet[end + 2 :]


def exchange(
    client: socket.socket,
    mixed_port: int,
    host: str,
    port: int,
    payload: bytes,
) -> bool:
    client.sendto(socks_udp_packet(host, port, payload), ("127.0.0.1", mixed_port))
    response, _ = client.recvfrom(65_535)
    response_host, response_port, response_payload = decode_socks_udp(response)
    expected_host = "127.0.0.1" if host == "localhost" else str(ipaddress.ip_address(host))
    return (
        response_host == expected_host
        and response_port == port
        and response_payload == payload
    )


def wait_exchange(
    process: Any,
    client: socket.socket,
    mixed_port: int,
    host: str,
    port: int,
    payload: bytes,
) -> bool:
    client.settimeout(0.25)
    deadline = time.monotonic() + (2 * IO_DEADLINE)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during VMess UDP readiness: {process.returncode}")
        try:
            if exchange(client, mixed_port, host, port, payload):
                client.settimeout(IO_DEADLINE)
                return True
        except TimeoutError:
            pass
        time.sleep(0.02)
    raise TimeoutError("VMess UDP route did not become ready")


def snapshot(controller_port: int, name: str) -> dict[str, Any]:
    status, body = request(controller_port, "GET", f"/proxies/{name}")
    if status != 200:
        raise AssertionError((status, body))
    payload = json.loads(body)
    return {
        "name": payload["name"],
        "type": payload["type"],
        "udp": payload["udp"],
        "uot": payload["uot"],
        "xudp": payload["xudp"],
    }


def wait_packets(
    authorities: list[tuple[Any, pathlib.Path]], expected: set[str]
) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    observed: set[str] = set()
    while time.monotonic() < deadline:
        for process, output in authorities:
            if process.poll() is not None:
                raise RuntimeError("VMess UDP authority exited")
            for line in output.read_text(errors="replace").splitlines():
                if line.startswith("PACKET "):
                    fields = line.split()
                    observed.add(" ".join(fields[:3]))
        if expected <= observed:
            return sorted(expected)
        time.sleep(0.02)
    raise TimeoutError(f"missing VMess UDP observations: {sorted(expected - observed)}")


def exercise(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    mixed_port, controller_port = reserve_port(), reserve_port()
    authority_specs = [
        ("standard", 0),
        ("packetaddr", 1),
        ("xudp", 0),
    ]
    authorities = []
    authority_handles = []
    for mode, alter_id in authority_specs:
        port = reserve_port()
        process, stdout, stderr, stdout_path = start_authority(
            authority_binary,
            scratch,
            port,
            alter_id=alter_id,
            packet_mode=mode,
            log_name=f"authority-{mode}",
        )
        authorities.append((mode, port, process, stdout_path))
        authority_handles.append((process, stdout, stderr))
    authority_ports = {mode: port for mode, port, _, _ in authorities}

    standard_record = vmess_record(
        "vmess-udp-standard",
        authority_ports["standard"],
        cipher="none",
        extra="    udp: true\n",
    )
    packet_record = vmess_record(
        "vmess-udp-packet",
        authority_ports["packetaddr"],
        cipher="aes-128-cfb",
        alter_id=1,
        extra="    udp: true\n    packet-encoding: packet\n",
    )
    xudp_record = vmess_record(
        "vmess-udp-xudp",
        authority_ports["xudp"],
        cipher="aes-128-gcm",
        global_padding=True,
        authenticated_length=True,
        extra="    udp: true\n    packet-addr: true\n    packet-encoding: xudp\n",
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: true
proxies:
{standard_record}{packet_record}{xudp_record}rules:
  - DST-PORT,25001,vmess-udp-standard
  - DST-PORT,25002,vmess-udp-packet
  - DST-PORT,25012,vmess-udp-packet
  - DST-PORT,25003,vmess-udp-xudp
  - DST-PORT,25013,vmess-udp-xudp
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    clients: list[socket.socket] = []
    try:
        wait_ready(process, mixed_port)
        for _ in range(3):
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.bind(("127.0.0.1", 0))
            client.settimeout(IO_DEADLINE)
            clients.append(client)
        standard, packet, xudp = clients
        standard_ready = wait_exchange(
            process, standard, mixed_port, "localhost", 25001, b"standard-ready"
        )
        results = {
            "standard": {
                "domain-resolved": standard_ready,
                "session-reuse": exchange(
                    standard,
                    mixed_port,
                    "127.0.0.1",
                    25001,
                    bytes(range(256)) * 12,
                ),
            },
            "packetaddr": {
                "ipv4": wait_exchange(
                    process, packet, mixed_port, "192.0.2.81", 25002, b"packet-ipv4"
                ),
                "ipv6-same-association": exchange(
                    packet,
                    mixed_port,
                    "2001:db8::81",
                    25012,
                    b"packet-ipv6",
                ),
            },
            "xudp": {
                "ipv4": wait_exchange(
                    process, xudp, mixed_port, "192.0.2.82", 25003, b"xudp-ipv4"
                ),
                "ipv6-same-association": exchange(
                    xudp,
                    mixed_port,
                    "2001:db8::82",
                    25013,
                    bytes(range(256)) * 8,
                ),
            },
        }
        expected = {
            "PACKET standard 127.0.0.1:25001",
            "PACKET packetaddr 192.0.2.81:25002",
            "PACKET packetaddr 2001:db8::81:25012",
            "PACKET xudp 192.0.2.82:25003",
            "PACKET xudp 2001:db8::82:25013",
        }
        return {
            "matrix": results,
            "controller": {
                name: snapshot(controller_port, name)
                for name in [
                    "vmess-udp-standard",
                    "vmess-udp-packet",
                    "vmess-udp-xudp",
                ]
            },
            "authority": wait_packets(
                [(process, output) for _, _, process, output in authorities], expected
            ),
            "survived": process.poll() is None,
        }
    finally:
        for client in clients:
            client.close()
        stop(process)
        stdout.close()
        stderr.close()
        for authority, authority_stdout, authority_stderr in authority_handles:
            stop(authority)
            authority_stdout.close()
            authority_stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6d-vmess-udp-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6DEVMESS_CARGO_TARGET", "phase6d-e-vmess")
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
    print("Phase 6D-E VMess UDP packet-mode differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

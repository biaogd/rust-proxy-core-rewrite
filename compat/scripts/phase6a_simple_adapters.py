#!/usr/bin/env python3
"""Go/Rust differential for the remaining Phase 6A simple adapters."""

from __future__ import annotations

import json
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, recv_exact, reserve_port, start_server, wait_ready
from phase3 import (
    UdpEchoHandler,
    decode_socks_udp,
    http_request,
    launch,
    socks_udp_packet,
    status,
    stop,
)
from phase4 import dns_query, wait_dns_ready
from phase5b1a import build_binaries, debug_files
from phase5b3a import relay_result
from phase5d_proxies import normalize, request
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6a-simple-adapters-diff.json"


class UdpServer:
    def __init__(self) -> None:
        self.server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = int(self.server.server_address[1])

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=IO_DEADLINE)


def tcp_result(mixed_port: int, destination_port: int, payload: bytes) -> str:
    try:
        stream, response = http_request(mixed_port, destination_port, None)
        with stream:
            if " 200 " not in status(response):
                return status(response)
            return relay_result(stream, payload)
    except (OSError, EOFError, ConnectionResetError, BrokenPipeError):
        return "reject"


def wait_tcp_result(
    process: Any,
    mixed_port: int,
    destination_port: int,
    payload: bytes,
    expected: str,
) -> str:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited with {process.returncode}")
        result = tcp_result(mixed_port, destination_port, payload)
        if result == expected:
            return result
        time.sleep(0.02)
    raise TimeoutError(f"TCP route did not become {expected}")


def udp_exchange(
    mixed_port: int,
    destination_port: int,
    payload: bytes,
    timeout: float = 0.5,
) -> tuple[str, int, bytes] | None:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(timeout)
    try:
        client.sendto(
            socks_udp_packet(destination_port, payload),
            ("127.0.0.1", mixed_port),
        )
        try:
            packet, _ = client.recvfrom(65_535)
        except TimeoutError:
            return None
        return decode_socks_udp(packet)
    finally:
        client.close()


def wait_udp_echo(
    process: Any,
    mixed_port: int,
    destination_port: int,
    payload: bytes,
) -> dict[str, Any]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited with {process.returncode}")
        result = udp_exchange(mixed_port, destination_port, payload)
        if result is not None and result[2] == payload:
            return {
                "address": result[0],
                "destination-port": result[1] == destination_port,
                "payload": result[2].decode(),
            }
        time.sleep(0.02)
    raise TimeoutError("UDP direct route did not echo")


def dns_tcp_result(mixed_port: int, destination_port: int, query: bytes) -> dict[str, Any]:
    stream, connect_response = http_request(mixed_port, destination_port, None)
    with stream:
        stream.sendall(len(query).to_bytes(2, "big") + query)
        length = int.from_bytes(recv_exact(stream, 2), "big")
        response = recv_exact(stream, length)
    return dns_observation(connect_response, query, response)


def dns_udp_result(mixed_port: int, destination_port: int, query: bytes) -> dict[str, Any]:
    result = udp_exchange(mixed_port, destination_port, query, IO_DEADLINE)
    if result is None:
        raise TimeoutError("DNS UDP adapter did not respond")
    address, port, response = result
    observation = dns_observation(b"HTTP/1.1 200 Connection established", query, response)
    observation.update(
        {"address": address, "destination-port": port == destination_port}
    )
    return observation


def dns_observation(connect_response: bytes, query: bytes, response: bytes) -> dict[str, Any]:
    return {
        "connect-status": status(connect_response),
        "id-echoed": response[:2] == query[:2],
        "rcode": response[3] & 0x0F,
        "question-preserved": response[12:] == query[12:],
    }


def proxy_view(
    controller_port: int, name: str, path: str | None = None
) -> dict[str, Any]:
    code, body = request(controller_port, "GET", path or f"/proxies/{name}")
    if code != 200:
        raise AssertionError((code, body))
    value = normalize(json.loads(body))
    return {
        key: value[key]
        for key in (
            "name",
            "type",
            "udp",
            "uot",
            "tfo",
            "mptcp",
            "interface",
            "routing-mark",
            "dialer-proxy",
        )
    }


def global_members(controller_port: int) -> list[str]:
    code, body = request(controller_port, "GET", "/proxies/GLOBAL")
    if code != 200:
        raise AssertionError((code, body))
    return json.loads(body)["all"]


def select(controller_port: int, group: str, name: str) -> dict[str, Any]:
    code, body = request(controller_port, "PUT", f"/proxies/{group}", {"name": name})
    return {"status": code, "empty-body": body == b""}


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    tcp_direct = start_server(EchoHandler)
    tcp_rematch = start_server(EchoHandler)
    tcp_group = start_server(EchoHandler)
    tcp_group_rematch = start_server(EchoHandler)
    tcp_provider = start_server(EchoHandler)
    udp_direct = UdpServer()
    udp_rematch = UdpServer()
    udp_group = UdpServer()
    udp_group_rematch = UdpServer()
    reject_tcp_port = reserve_port()
    reject_udp_port = reserve_port()
    drop_udp_port = reserve_port()
    dns_destination_port = 53
    mixed_port, controller_port, dns_port = reserve_port(), reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  nameserver: [rcode://success]
proxies:
  - {{name: direct-custom, type: direct}}
  - {{name: reject-custom, type: reject}}
  - {{name: dns-custom, type: dns}}
  - name: rematch-custom
    type: rematch
    target-rematch-name: phase6a-rematched
proxy-providers:
  inline-simple:
    type: inline
    payload:
      - {{name: provider-direct, type: direct}}
proxy-groups:
  - {{name: simple-select, type: select, proxies: [reject-custom, direct-custom]}}
  - {{name: rematch-select, type: select, proxies: [rematch-custom]}}
  - {{name: provider-select, type: select, use: [inline-simple]}}
rules:
  - REMATCH-NAME,phase6a-rematched,DIRECT
  - DST-PORT,{tcp_direct.port},direct-custom
  - DST-PORT,{reject_tcp_port},reject-custom
  - DST-PORT,{tcp_rematch.port},rematch-custom
  - DST-PORT,{tcp_group.port},simple-select
  - DST-PORT,{tcp_group_rematch.port},rematch-select
  - DST-PORT,{tcp_provider.port},provider-select
  - DST-PORT,{dns_destination_port},dns-custom
  - DST-PORT,{udp_direct.port},direct-custom
  - DST-PORT,{reject_udp_port},reject-custom
  - DST-PORT,{drop_udp_port},REJECT-DROP
  - DST-PORT,{udp_rematch.port},rematch-custom
  - DST-PORT,{udp_group.port},simple-select
  - DST-PORT,{udp_group_rematch.port},rematch-select
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_dns_ready(process, dns_port)
        views = {
            name: proxy_view(controller_port, name)
            for name in (
                "direct-custom",
                "reject-custom",
                "dns-custom",
                "rematch-custom",
            )
        }
        views["provider-direct"] = proxy_view(
            controller_port,
            "provider-direct",
            "/providers/proxies/inline-simple/provider-direct",
        )
        direct_tcp = wait_tcp_result(
            process, mixed_port, tcp_direct.port, b"direct-custom", "direct"
        )
        reject_tcp = wait_tcp_result(
            process, mixed_port, reject_tcp_port, b"reject-custom", "reject"
        )
        rematch_tcp = wait_tcp_result(
            process, mixed_port, tcp_rematch.port, b"rematch-custom", "direct"
        )
        group_initial_tcp = wait_tcp_result(
            process, mixed_port, tcp_group.port, b"group-reject", "reject"
        )
        group_select_direct = select(controller_port, "simple-select", "direct-custom")
        group_direct_tcp = wait_tcp_result(
            process, mixed_port, tcp_group.port, b"group-direct", "direct"
        )
        group_direct_udp = wait_udp_echo(
            process, mixed_port, udp_group.port, b"group-direct-udp"
        )
        group_rematch_tcp = wait_tcp_result(
            process,
            mixed_port,
            tcp_group_rematch.port,
            b"group-rematch",
            "direct",
        )
        group_rematch_udp = wait_udp_echo(
            process, mixed_port, udp_group_rematch.port, b"group-rematch-udp"
        )
        provider_tcp = wait_tcp_result(
            process, mixed_port, tcp_provider.port, b"provider-direct", "direct"
        )
        query_tcp = dns_query("tcp.phase6a.test", 0x6A01)
        query_udp = dns_query("udp.phase6a.test", 0x6A02)
        return {
            "views": views,
            "global-members": global_members(controller_port),
            "tcp": {
                "direct": direct_tcp,
                "reject": reject_tcp,
                "rematch": rematch_tcp,
                "group-initial": group_initial_tcp,
                "group-select-direct": group_select_direct,
                "group-direct": group_direct_tcp,
                "group-rematch": group_rematch_tcp,
                "provider-direct": provider_tcp,
                "dns": dns_tcp_result(mixed_port, dns_destination_port, query_tcp),
            },
            "udp": {
                "direct": wait_udp_echo(
                    process, mixed_port, udp_direct.port, b"direct-custom-udp"
                ),
                "reject": udp_exchange(mixed_port, reject_udp_port, b"reject") is None,
                "reject-drop": udp_exchange(mixed_port, drop_udp_port, b"drop") is None,
                "rematch": wait_udp_echo(
                    process, mixed_port, udp_rematch.port, b"rematch-custom-udp"
                ),
                "group-direct": group_direct_udp,
                "group-rematch": group_rematch_udp,
                "dns": dns_udp_result(mixed_port, dns_destination_port, query_udp),
            },
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        for server in (
            tcp_direct,
            tcp_rematch,
            tcp_group,
            tcp_group_rematch,
            tcp_provider,
        ):
            server.close()
        for server in (udp_direct, udp_rematch, udp_group, udp_group_rematch):
            server.close()


def validation_cases(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    base = "mixed-port: 7890\nmode: rule\nrules: ['MATCH,DIRECT']\n"
    cases = {
        "direct": base + "proxies: [{name: local-direct, type: direct}]\n",
        "reject": base + "proxies: [{name: local-reject, type: reject}]\n",
        "dns": base + "proxies: [{name: local-dns, type: dns}]\n",
        "rematch": base
        + "proxies: [{name: local-rematch, type: rematch, target-rematch-name: next}]\n",
        "rematch-missing-target": base
        + "proxies: [{name: local-rematch, type: rematch}]\n",
        "simple-provider": base
        + "proxy-providers:\n  local:\n    type: inline\n    payload: [{name: provider-direct, type: direct}]\n",
    }
    observations = {}
    for name, source in cases.items():
        path = scratch / f"{name}.yaml"
        path.write_text(source)
        result = subprocess.run(
            [str(binary), "-t", "-f", str(path)],
            cwd=scratch,
            capture_output=True,
            timeout=IO_DEADLINE,
        )
        observations[name] = result.returncode == 0
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6a-simple-adapters-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE6ASIMPLE_CARGO_TARGET", "phase6a-simple-adapters"
        )
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                runtime = scratch / "runtime"
                validation = scratch / "validation"
                runtime.mkdir()
                validation.mkdir()
                observations[name] = {
                    "runtime": exercise(binary, runtime),
                    "validation": validation_cases(binary, validation),
                }
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
                    {"observations": observations, "debug": debug_files(root)},
                    indent=2,
                    sort_keys=True,
                )
            )
            return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6A simple adapters differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

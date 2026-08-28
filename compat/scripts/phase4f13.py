#!/usr/bin/env python3
"""Go/Rust differential suite for Phase 4F13 redir-host mapping lifecycle."""

from __future__ import annotations

import json
import os
import pathlib
import signal
import socket
import socketserver
import tempfile
import threading
import time
from typing import Any, Callable

from phase1 import IO_DEADLINE, ROOT, EchoHandler, recv_exact, recv_until, reserve_port
from phase4 import build_binaries, launch, stop, wait_dns_ready
from phase4b import (
    AllInterfacesServer,
    encode_name,
    local_interface_ip,
    make_query,
    parse_query,
    parse_response,
    socks5_connect,
    udp_query,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f13-diff.json"


class MappingAuthorityState:
    def __init__(
        self,
        address: str,
        *,
        ttl: int = 30,
        cname_target: str | None = None,
    ) -> None:
        self.address = address
        self.ttl = ttl
        self.cname_target = cname_target
        self.questions: list[str] = []
        self.lock = threading.Lock()

    def respond(self, query: bytes) -> bytes:
        name, record_type, question_end = parse_query(query)
        with self.lock:
            self.questions.append(name)
        records: list[bytes] = []
        if record_type == 1:
            if self.cname_target is not None:
                target = encode_name(self.cname_target)
                records.append(
                    b"\xc0\x0c\x00\x05\x00\x01"
                    + self.ttl.to_bytes(4, "big")
                    + len(target).to_bytes(2, "big")
                    + target
                )
                owner = encode_name(self.cname_target)
            else:
                owner = b"\xc0\x0c"
            records.append(
                owner
                + b"\x00\x01\x00\x01"
                + self.ttl.to_bytes(4, "big")
                + b"\x00\x04"
                + socket.inet_aton(self.address)
            )
        return (
            query[:2]
            + b"\x81\x80\x00\x01"
            + len(records).to_bytes(2, "big")
            + b"\x00\x00\x00\x00"
            + query[12:question_end]
            + b"".join(records)
        )

    def snapshot(self) -> list[str]:
        with self.lock:
            # Phase 4F11 owns exact cache refresh/retry counts. This gate keeps
            # the queried identity while excluding when a same-name refresh
            # races the mapping lifecycle observation.
            return sorted(set(self.questions))


class AuthorityServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class AuthorityHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, server_socket = self.request
        state: MappingAuthorityState = self.server.state  # type: ignore[attr-defined]
        server_socket.sendto(state.respond(query), self.client_address)


class UdpEchoServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        payload, server_socket = self.request
        server_socket.sendto(payload, self.client_address)


class FixtureServers:
    def __init__(self, state: MappingAuthorityState) -> None:
        self.authority = AuthorityServer(("127.0.0.1", 0), AuthorityHandler)
        self.authority.state = state  # type: ignore[attr-defined]
        self.tcp_echo = AllInterfacesServer(("0.0.0.0", 0), EchoHandler)
        self.udp_echo = UdpEchoServer(("0.0.0.0", 0), UdpEchoHandler)
        self.threads = [
            threading.Thread(target=self.authority.serve_forever, daemon=True),
            threading.Thread(target=self.tcp_echo.serve_forever, daemon=True),
            threading.Thread(target=self.udp_echo.serve_forever, daemon=True),
        ]
        for thread in self.threads:
            thread.start()

    def close(self) -> None:
        for server in (self.authority, self.tcp_echo, self.udp_echo):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=IO_DEADLINE)


def config_text(
    *,
    http_port: int | str,
    socks_port: int | str,
    mixed_port: int | str,
    dns_port: int | str,
    upstream_port: int | str,
    direct_host: str,
    hosts: str = "",
) -> str:
    hosts_section = f"hosts:\n{hosts}" if hosts else ""
    return f"""port: {http_port}
socks-port: {socks_port}
mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
{hosts_section}
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: true
  use-system-hosts: false
  enhanced-mode: redir-host
  nameserver:
    - udp://127.0.0.1:{upstream_port}
rules:
  - DOMAIN,{direct_host},DIRECT
  - MATCH,REJECT
"""


def reserve_distinct_ports(count: int) -> list[int]:
    ports: list[int] = []
    while len(ports) < count:
        port = reserve_port()
        if port not in ports:
            ports.append(port)
    return ports


def http_connect(proxy_port: int, address: str, destination_port: int) -> socket.socket:
    stream = socket.create_connection(("127.0.0.1", proxy_port), timeout=IO_DEADLINE)
    stream.settimeout(IO_DEADLINE)
    authority = f"{address}:{destination_port}"
    stream.sendall(
        f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
    )
    response = recv_until(stream, b"\r\n\r\n")
    if b" 200 " not in response.split(b"\r\n", 1)[0] + b" ":
        stream.close()
        raise AssertionError(f"HTTP CONNECT failed: {response!r}")
    return stream


def wait_tcp_echo(
    connector: Callable[[int, str, int], socket.socket],
    proxy_port: int,
    address: str,
    destination_port: int,
    marker: str,
) -> str:
    # Reload runs compete with the other differential shards on shared CI
    # hosts. Keep the per-attempt socket deadline bounded, but allow two full
    # scheduling windows for the replacement generation to publish.
    deadline = time.monotonic() + (2 * IO_DEADLINE) + 1
    last_error: BaseException | None = None
    payload = marker.encode()
    while time.monotonic() < deadline:
        try:
            with connector(proxy_port, address, destination_port) as stream:
                stream.sendall(payload)
                return recv_exact(stream, len(payload)).decode()
        except (AssertionError, EOFError, OSError, TimeoutError) as error:
            last_error = error
            time.sleep(0.02)
    raise AssertionError(f"mapped TCP route {marker} did not become ready") from last_error


def expect_tcp_rejected(proxy_port: int, address: str, destination_port: int) -> str:
    try:
        with socks5_connect(proxy_port, address, destination_port) as stream:
            stream.sendall(b"blocked")
            return "rejected" if stream.recv(1) == b"" else "unexpected-data"
    except (AssertionError, EOFError, OSError, TimeoutError):
        return "rejected"


def socks_udp_packet(address: str, destination_port: int, payload: bytes) -> bytes:
    return (
        b"\x00\x00\x00\x01"
        + socket.inet_aton(address)
        + destination_port.to_bytes(2, "big")
        + payload
    )


def wait_udp_echo(
    proxy_port: int,
    address: str,
    destination_port: int,
    marker: str,
) -> str:
    deadline = time.monotonic() + (2 * IO_DEADLINE) + 1
    payload = marker.encode()
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(min(0.5, max(0.05, deadline - time.monotonic())))
            client.sendto(
                socks_udp_packet(address, destination_port, payload),
                ("127.0.0.1", proxy_port),
            )
            try:
                response = client.recvfrom(65_535)[0]
            except TimeoutError:
                continue
        if len(response) >= 10 and response[10:] == payload:
            return marker
    raise TimeoutError(f"mapped UDP route {marker} did not become ready")


def launch_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    state: MappingAuthorityState,
    source: str,
    exercise: Callable[[Any, int, int, int, int, FixtureServers, pathlib.Path], dict[str, Any]],
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    servers = FixtureServers(state)
    http_port, socks_port, mixed_port, dns_port = reserve_distinct_ports(4)
    config = scratch / "config.yaml"
    config.write_text(
        source.format(
            http_port=http_port,
            socks_port=socks_port,
            mixed_port=mixed_port,
            dns_port=dns_port,
            upstream_port=servers.authority.server_address[1],
        )
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        result = exercise(
            process,
            http_port,
            socks_port,
            mixed_port,
            dns_port,
            servers,
            config,
        )
        time.sleep(0.1)
        result["exit-code"] = stop(process)
        return result
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        servers.close()


def render_source(
    direct_host: str,
    *,
    hosts: str = "",
) -> str:
    return config_text(
        http_port="{http_port}",
        socks_port="{socks_port}",
        mixed_port="{mixed_port}",
        dns_port="{dns_port}",
        upstream_port="{upstream_port}",
        direct_host=direct_host,
        hosts=hosts,
    )


def all_inbounds(
    _process: Any,
    http_port: int,
    socks_port: int,
    mixed_port: int,
    dns_port: int,
    servers: FixtureServers,
    _config: pathlib.Path,
    address: str,
) -> dict[str, Any]:
    response = parse_response(
        udp_query(dns_port, make_query("mapped.phase4f13.test", 1, 0x4D01)),
        0x4D01,
    )
    tcp_port = int(servers.tcp_echo.server_address[1])
    udp_port = int(servers.udp_echo.server_address[1])
    return {
        "dns": response,
        "tcp": {
            "http": wait_tcp_echo(http_connect, http_port, address, tcp_port, "http"),
            "socks": wait_tcp_echo(socks5_connect, socks_port, address, tcp_port, "socks"),
            "mixed-http": wait_tcp_echo(
                http_connect, mixed_port, address, tcp_port, "mixed-http"
            ),
            "mixed-socks": wait_tcp_echo(
                socks5_connect, mixed_port, address, tcp_port, "mixed-socks"
            ),
        },
        "udp": {
            "socks": wait_udp_echo(socks_port, address, udp_port, "socks-udp"),
            "mixed": wait_udp_echo(mixed_port, address, udp_port, "mixed-udp"),
        },
    }


def mapped_socks_case(
    _process: Any,
    _http_port: int,
    _socks_port: int,
    mixed_port: int,
    dns_port: int,
    servers: FixtureServers,
    _config: pathlib.Path,
    address: str,
    query_name: str,
) -> dict[str, Any]:
    response = parse_response(
        udp_query(dns_port, make_query(query_name, 1, 0x4D10)), 0x4D10
    )
    return {
        "dns": response,
        "tcp": wait_tcp_echo(
            socks5_connect,
            mixed_port,
            address,
            int(servers.tcp_echo.server_address[1]),
            "mapped",
        ),
    }


def reload_case(
    process: Any,
    _http_port: int,
    _socks_port: int,
    mixed_port: int,
    dns_port: int,
    servers: FixtureServers,
    config: pathlib.Path,
    address: str,
) -> dict[str, Any]:
    name = "reload.phase4f13.test"
    udp_query(dns_port, make_query(name, 1, 0x4D20))
    tcp_port = int(servers.tcp_echo.server_address[1])
    before = expect_tcp_rejected(mixed_port, address, tcp_port)
    updated = config.with_suffix(".yaml.reload")
    updated.write_text(
        config.read_text().replace(f"DOMAIN,{name},REJECT", f"DOMAIN,{name},DIRECT")
    )
    updated.replace(config)
    os.kill(process.pid, signal.SIGHUP)
    after = wait_tcp_echo(socks5_connect, mixed_port, address, tcp_port, "reloaded")
    return {"before": before, "after": after}


def ttl_case(
    _process: Any,
    _http_port: int,
    _socks_port: int,
    mixed_port: int,
    dns_port: int,
    servers: FixtureServers,
    _config: pathlib.Path,
    address: str,
) -> dict[str, Any]:
    name = "ttl.phase4f13.test"
    response = parse_response(udp_query(dns_port, make_query(name, 1, 0x4D30)), 0x4D30)
    tcp_port = int(servers.tcp_echo.server_address[1])
    immediate = wait_tcp_echo(socks5_connect, mixed_port, address, tcp_port, "immediate")
    time.sleep(2.2)
    after_ttl = wait_tcp_echo(socks5_connect, mixed_port, address, tcp_port, "after-ttl")
    return {"dns": response, "immediate": immediate, "after-ttl": after_ttl}


def exercise_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    address = local_interface_ip()
    if address is None:
        return {"available": False}
    observations: dict[str, Any] = {"available": True, "address": address}

    mapped = "mapped.phase4f13.test"
    mapped_state = MappingAuthorityState(address)
    observations["all-inbounds"] = launch_case(
        binary,
        scratch / "all-inbounds",
        mapped_state,
        render_source(mapped),
        lambda *args: all_inbounds(*args, address),
    )
    observations["all-inbounds"]["questions"] = mapped_state.snapshot()

    asked = "asked.phase4f13.test"
    canonical = "canonical.phase4f13.test"
    cname_state = MappingAuthorityState(address, cname_target=canonical)
    observations["upstream-cname"] = launch_case(
        binary,
        scratch / "upstream-cname",
        cname_state,
        render_source(asked),
        lambda *args: mapped_socks_case(*args, address, asked),
    )
    observations["upstream-cname"]["questions"] = cname_state.snapshot()

    alias = "configured-alias.phase4f13.test"
    target = "configured-target.phase4f13.test"
    host_state = MappingAuthorityState(address)
    observations["configured-cname"] = launch_case(
        binary,
        scratch / "configured-cname",
        host_state,
        render_source(target, hosts=f"  {alias}: {target}\n"),
        lambda *args: mapped_socks_case(*args, address, alias),
    )
    observations["configured-cname"]["questions"] = host_state.snapshot()

    reload_name = "reload.phase4f13.test"
    reload_state = MappingAuthorityState(address)
    observations["reload"] = launch_case(
        binary,
        scratch / "reload",
        reload_state,
        render_source(reload_name).replace(
            f"DOMAIN,{reload_name},DIRECT", f"DOMAIN,{reload_name},REJECT"
        ),
        lambda *args: reload_case(*args, address),
    )
    observations["reload"]["questions"] = reload_state.snapshot()

    ttl_name = "ttl.phase4f13.test"
    ttl_state = MappingAuthorityState(address, ttl=1)
    observations["ttl"] = launch_case(
        binary,
        scratch / "ttl",
        ttl_state,
        render_source(ttl_name),
        lambda *args: ttl_case(*args, address),
    )
    observations["ttl"]["questions"] = ttl_state.snapshot()
    return observations


def satisfies(observation: dict[str, Any]) -> bool:
    if not observation.get("available"):
        return False
    all_inbound = observation["all-inbounds"]
    upstream = observation["upstream-cname"]
    configured = observation["configured-cname"]
    reload = observation["reload"]
    ttl = observation["ttl"]
    return (
        all(section["exit-code"] == 0 for section in (all_inbound, upstream, configured, reload, ttl))
        and all_inbound["tcp"]
        == {
            "http": "http",
            "socks": "socks",
            "mixed-http": "mixed-http",
            "mixed-socks": "mixed-socks",
        }
        and all_inbound["udp"] == {"socks": "socks-udp", "mixed": "mixed-udp"}
        and all_inbound["questions"] == ["mapped.phase4f13.test"]
        and [record["type"] for record in upstream["dns"]["records"]] == [5, 1]
        and upstream["dns"]["records"][0]["data"] == "canonical.phase4f13.test"
        and upstream["tcp"] == "mapped"
        and upstream["questions"] == ["asked.phase4f13.test"]
        and configured["dns"]["records"][0]["type"] == 5
        and configured["dns"]["records"][0]["data"] == "configured-target.phase4f13.test"
        and configured["tcp"] == "mapped"
        and configured["questions"] == ["configured-target.phase4f13.test"]
        and reload["before"] == "rejected"
        and reload["after"] == "reloaded"
        and reload["questions"] == ["reload.phase4f13.test"]
        and ttl["dns"]["records"][0]["ttl"] == 1
        and ttl["immediate"] == "immediate"
        and ttl["after-ttl"] == "after-ttl"
        and ttl["questions"] == ["ttl.phase4f13.test"]
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f13-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        evidence = {
            implementation: exercise_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if (
            evidence["go"] != evidence["rust"]
            or not satisfies(evidence["go"])
            or not satisfies(evidence["rust"])
        ):
            FAILURE_ARTIFACT.write_text(json.dumps(evidence, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4F13 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F13 redir-host differential passed")


if __name__ == "__main__":
    main()

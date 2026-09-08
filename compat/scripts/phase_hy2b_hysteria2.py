#!/usr/bin/env python3
"""Go/Rust differential for HY2-B: UDP, Salamander, Brutal, hop, udp-mtu."""

from __future__ import annotations

import json
import pathlib
import select
import socket
import socketserver
import subprocess
import tempfile
import textwrap
import threading
import time
from typing import Any

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    recv_exact,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, connect_domain, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_tcp import rejected_exchange
from phase6e_vless_udp import decode_socks_udp, socks_udp_packet


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-hy2b-hysteria2-diff.json"
PASSWORD = "phase-hy2b-password"
OBFS_PASSWORD = "salamander-secret"
SNI = "dot.phase4.test"
LARGE_UDP = bytes(range(256)) * 8  # 2048 bytes → fragments under default MTU


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(data, self.client_address)


def start_udp_echo() -> tuple[socketserver.ThreadingUDPServer, int]:
    server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    server.allow_reuse_address = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, int(server.server_address[1])


class BidirectionalUdpRelay:
    """Per-client NAT-style UDP relay for hop ports → authority."""

    def __init__(
        self, listen_port: int, target_port: int, *, listen_host: str = "127.0.0.1"
    ) -> None:
        self.listen_port = listen_port
        self.target_port = target_port
        self.listen_host = listen_host
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)

    def _run(self) -> None:
        listen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen.bind((self.listen_host, self.listen_port))
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(("127.0.0.1", 0))
        listen.setblocking(False)
        upstream.setblocking(False)
        client_addr: tuple[str, int] | None = None
        try:
            while not self._stop.is_set():
                readable, _, _ = select.select([listen, upstream], [], [], 0.2)
                if listen in readable:
                    data, addr = listen.recvfrom(65535)
                    client_addr = addr
                    upstream.sendto(data, ("127.0.0.1", self.target_port))
                if upstream in readable:
                    data, _ = upstream.recvfrom(65535)
                    if client_addr is not None:
                        listen.sendto(data, client_addr)
        finally:
            listen.close()
            upstream.close()


def hy2_record(
    name: str,
    server_port: int,
    *,
    server: str = "127.0.0.1",
    password: str = PASSWORD,
    skip_verify: bool = True,
    salamander: bool = False,
    obfs_password: str = OBFS_PASSWORD,
    up: str | None = None,
    down: str | None = None,
    ports: str | None = None,
    hop_interval: str | None = None,
    udp_mtu: int | None = None,
    disable_reuse: bool = False,
) -> str:
    lines = [
        f"  - name: {name}",
        "    type: hysteria2",
        f"    server: {server}",
        f"    port: {server_port}",
        f"    password: {password}",
        f"    sni: {SNI}",
        "    alpn: [h3]",
        f"    skip-cert-verify: {'true' if skip_verify else 'false'}",
        "    udp: true",
    ]
    if disable_reuse:
        lines.append("    disable-reuse: true")
    if salamander:
        lines.append("    obfs: salamander")
        lines.append(f"    obfs-password: {obfs_password}")
    if up is not None:
        lines.append(f"    up: {up}")
    if down is not None:
        lines.append(f"    down: {down}")
    if ports is not None:
        lines.append(f"    ports: {ports}")
    if hop_interval is not None:
        lines.append(f"    hop-interval: {hop_interval}")
    if udp_mtu is not None:
        lines.append(f"    udp-mtu: {udp_mtu}")
    return "\n".join(lines) + "\n"


def start_authority(
    go_binary: pathlib.Path,
    scratch: pathlib.Path,
    listen_port: int,
    *,
    listen_host: str = "127.0.0.1",
    salamander: bool = False,
    up: str | None = None,
    down: str | None = None,
) -> tuple[subprocess.Popen[bytes], Any, Any]:
    cert_pem = textwrap.indent(SERVER_CERTIFICATE.read_text().strip(), "      ")
    key_pem = textwrap.indent(SERVER_KEY.read_text().strip(), "      ")
    extra = ""
    if salamander:
        extra += "    obfs: salamander\n"
        extra += f"    obfs-password: {OBFS_PASSWORD}\n"
    if up is not None:
        extra += f"    up: {up}\n"
    if down is not None:
        extra += f"    down: {down}\n"
    config = scratch / "authority.yaml"
    config.write_text(
        f"""mixed-port: 0
mode: rule
log-level: warning
ipv6: true
listeners:
  - name: hy2-in
    type: hysteria2
    listen: {listen_host}
    port: {listen_port}
    users:
      hy2-user: {PASSWORD}
{extra}    certificate: |-
{cert_pem}
    private-key: |-
{key_pem}
    alpn:
      - h3
rules:
  - MATCH,DIRECT
"""
    )
    return launch(go_binary, config, scratch)


def socks_udp_associate(mixed_port: int) -> tuple[socket.socket, socket.socket, int]:
    control = socket.create_connection(("127.0.0.1", mixed_port), timeout=IO_DEADLINE)
    control.sendall(b"\x05\x01\x00")
    if control.recv(2) != b"\x05\x00":
        raise AssertionError("socks auth failed")
    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    response = recv_exact(control, 10)
    if response[0:2] != b"\x05\x00" or response[3] != 1:
        raise AssertionError(f"udp associate failed: {response!r}")
    bind_port = int.from_bytes(response[8:10], "big")
    if bind_port == 0:
        bind_port = mixed_port
    datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    datagram.settimeout(IO_DEADLINE)
    return control, datagram, bind_port


def tcp_exchange(
    mixed_port: int,
    host: str,
    target_port: int,
    payload: bytes,
    *,
    attempts: int = 8,
) -> bool:
    """SOCKS TCP echo with retries under CI load (Go HY2 cold-start flake)."""
    for _ in range(attempts):
        try:
            with connect_domain(mixed_port, host, target_port) as stream:
                stream.settimeout(IO_DEADLINE)
                stream.sendall(payload)
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
            time.sleep(0.15)
    return False


def udp_exchange(
    mixed_port: int, host: str, target_port: int, payload: bytes
) -> bool:
    control, datagram, bind_port = socks_udp_associate(mixed_port)
    try:
        datagram.sendto(
            socks_udp_packet(host, target_port, payload), ("127.0.0.1", bind_port)
        )
        response, _ = datagram.recvfrom(65_535)
        _, _, body = decode_socks_udp(response)
        return body == payload
    finally:
        datagram.close()
        control.close()


def udp_exchange_retry(
    mixed_port: int, host: str, target_port: int, payload: bytes, *, attempts: int = 5
) -> bool:
    for _ in range(attempts):
        try:
            if udp_exchange(mixed_port, host, target_port, payload):
                return True
        except (
            AssertionError,
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionResetError,
            EOFError,
            OSError,
            TimeoutError,
        ):
            pass
        time.sleep(0.1)
    return False



def udp_multi_dest(mixed_port: int, ports: list[int]) -> bool:
    control, datagram, bind_port = socks_udp_associate(mixed_port)
    try:
        for index, port in enumerate(ports):
            payload = f"dest-{index}".encode()
            datagram.sendto(
                socks_udp_packet("127.0.0.1", port, payload), ("127.0.0.1", bind_port)
            )
            response, _ = datagram.recvfrom(65_535)
            _, _, body = decode_socks_udp(response)
            if body != payload:
                return False
        return True
    finally:
        datagram.close()
        control.close()


def config_validation(binary: pathlib.Path, scratch: pathlib.Path, body: str) -> bool:
    scratch.mkdir(parents=True, exist_ok=True)
    config = scratch / f"validate-{len(list(scratch.glob('validate-*')))}.yaml"
    config.write_text(
        f"""mixed-port: 0
mode: rule
log-level: info
ipv6: false
{body}
rules:
  - MATCH,DIRECT
"""
    )
    result = subprocess.run(
        [str(binary), "-t", "-f", str(config)],
        cwd=scratch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=IO_DEADLINE,
    )
    return result.returncode == 0


def exercise_profile(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    salamander: bool,
    brutal: bool,
    hop: bool,
    disable_reuse: bool = False,
) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    udp_echo, udp_port = start_udp_echo()
    udp_echo2, udp_port2 = start_udp_echo()
    authority_port = reserve_port()
    hop_ports: list[int] = []
    relays: list[BidirectionalUdpRelay] = []
    stop_relays = False
    try:
        authority_scratch = scratch / "authority"
        authority_scratch.mkdir()
        authority, a_out, a_err = start_authority(
            authority_binary,
            authority_scratch,
            authority_port,
            salamander=salamander,
            up="100 Mbps" if brutal else None,
            down="200 Mbps" if brutal else None,
        )
        time.sleep(0.4)
        if authority.poll() is not None:
            raise RuntimeError(
                "authority exited: "
                + (authority_scratch / "stdout.log").read_text(errors="replace")[-2000:]
            )

        client_port = authority_port
        ports_yaml = None
        hop_interval = None
        if hop:
            hop_ports = [reserve_port() for _ in range(3)]
            for port in hop_ports:
                relay = BidirectionalUdpRelay(port, authority_port)
                relay.start()
                relays.append(relay)
            stop_relays = True
            client_port = hop_ports[0]
            ports_yaml = ",".join(str(port) for port in hop_ports)
            hop_interval = "5"

        mixed_port, controller_port = reserve_port(), reserve_port()
        config = scratch / "config.yaml"
        config.write_text(
            f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: true
proxies:
{hy2_record(
    "inline-hy2",
    client_port,
    salamander=salamander,
    up="50 Mbps" if brutal else None,
    down="200 Mbps" if brutal else None,
    ports=ports_yaml,
    hop_interval=hop_interval,
    udp_mtu=800 if salamander else None,
    disable_reuse=disable_reuse,
)}
proxy-groups:
  - name: hy2-select
    type: select
    proxies: [inline-hy2]
    default-selected: inline-hy2
rules:
  - MATCH,hy2-select
"""
        )

        process, stdout, stderr = launch(binary, config, scratch)
        try:
            wait_ready(process, mixed_port)
            wait_controller(process, controller_port)
            # Give Go HY2 outbound a beat after controller-ready under CI load.
            time.sleep(0.3)

            tcp_ok = tcp_exchange(mixed_port, "127.0.0.1", echo.port, b"hy2b-tcp")
            udp_ok = udp_exchange_retry(mixed_port, "127.0.0.1", udp_port, b"hy2b-udp")
            udp_large = udp_exchange_retry(
                mixed_port, "127.0.0.1", udp_port, LARGE_UDP
            )
            multi = False
            for _ in range(5):
                try:
                    multi = udp_multi_dest(mixed_port, [udp_port, udp_port2])
                except (
                    AssertionError,
                    BrokenPipeError,
                    ConnectionAbortedError,
                    ConnectionResetError,
                    EOFError,
                    OSError,
                    TimeoutError,
                ):
                    multi = False
                if multi:
                    break
                time.sleep(0.1)

            # Concurrent TCP while UDP session alive.
            concurrent = False
            for _ in range(5):
                control = None
                datagram = None
                try:
                    control, datagram, bind_port = socks_udp_associate(mixed_port)
                    datagram.sendto(
                        socks_udp_packet("127.0.0.1", udp_port, b"keep-udp"),
                        ("127.0.0.1", bind_port),
                    )
                    tcp_part = tcp_exchange(
                        mixed_port, "127.0.0.1", echo.port, b"with-udp"
                    )
                    response, _ = datagram.recvfrom(65_535)
                    _, _, body = decode_socks_udp(response)
                    # Second UDP after TCP: disable-reuse must not have dropped
                    # the association when the dial Session handle was released.
                    datagram.sendto(
                        socks_udp_packet("127.0.0.1", udp_port, b"still-udp"),
                        ("127.0.0.1", bind_port),
                    )
                    response2, _ = datagram.recvfrom(65_535)
                    _, _, body2 = decode_socks_udp(response2)
                    concurrent = (
                        tcp_part and body == b"keep-udp" and body2 == b"still-udp"
                    )
                except (
                    AssertionError,
                    BrokenPipeError,
                    ConnectionAbortedError,
                    ConnectionResetError,
                    EOFError,
                    OSError,
                    TimeoutError,
                ):
                    concurrent = False
                finally:
                    if datagram is not None:
                        datagram.close()
                    if control is not None:
                        control.close()
                if concurrent:
                    break
                time.sleep(0.15)

            snapshot = request(controller_port, "GET", "/proxies/inline-hy2")
            if snapshot[0] != 200:
                raise AssertionError(snapshot)
            proxy = json.loads(snapshot[1])
            udp_advertised = bool(proxy.get("udp"))

            hop_continuity = True
            if hop:
                # Hold TCP across hop interval floor (5s) + margin.
                hop_continuity = False
                for _ in range(3):
                    try:
                        with connect_domain(mixed_port, "127.0.0.1", echo.port) as stream:
                            stream.settimeout(max(IO_DEADLINE, 12.0))
                            stream.sendall(b"pre-hop")
                            if recv_exact(stream, 7) != b"pre-hop":
                                continue
                            time.sleep(5.5)
                            stream.sendall(b"post-hop")
                            if recv_exact(stream, 8) != b"post-hop":
                                continue
                        hop_continuity = udp_exchange_retry(
                            mixed_port, "127.0.0.1", udp_port, b"after-hop-udp"
                        )
                        if hop_continuity:
                            break
                    except (
                        AssertionError,
                        BrokenPipeError,
                        ConnectionAbortedError,
                        ConnectionResetError,
                        EOFError,
                        OSError,
                        TimeoutError,
                    ):
                        hop_continuity = False
                        time.sleep(0.2)

            # disable-reuse leak pressure: many short TCP dials must succeed
            # (recv-task / connection accumulation would eventually break this).
            repeated_dials = True
            if disable_reuse:
                repeated_dials = all(
                    tcp_exchange(
                        mixed_port,
                        "127.0.0.1",
                        echo.port,
                        f"reuse-dial-{index}".encode(),
                    )
                    for index in range(12)
                )

            wrong_obfs = True
            if salamander:
                bad_port = reserve_port()
                bad_scratch = scratch / "wrong-obfs"
                bad_scratch.mkdir()
                bad_config = bad_scratch / "config.yaml"
                bad_config.write_text(
                    f"""mixed-port: {bad_port}
mode: rule
log-level: info
proxies:
{hy2_record("bad", client_port, salamander=True, obfs_password="wrong-key-xx")}
rules:
  - MATCH,bad
"""
                )
                bad_process, bad_out, bad_err = launch(binary, bad_config, bad_scratch)
                try:
                    wait_ready(bad_process, bad_port)
                    wrong_obfs = rejected_exchange(bad_port, "127.0.0.1", echo.port)
                finally:
                    stop(bad_process)
                    bad_out.close()
                    bad_err.close()

            return {
                "tcp-ok": tcp_ok,
                "udp-ok": udp_ok,
                "udp-large": udp_large,
                "udp-multi-dest": multi,
                "tcp-udp-concurrent": concurrent,
                "udp-advertised": udp_advertised,
                "hop-continuity": hop_continuity,
                "repeated-dials": repeated_dials,
                "wrong-obfs-rejected": wrong_obfs,
                "process-alive": process.poll() is None,
            }
        finally:
            stop(process)
            stdout.close()
            stderr.close()
            stop(authority)
            a_out.close()
            a_err.close()
    finally:
        if stop_relays:
            for relay in relays:
                relay.stop()
        echo.close()
        udp_echo.shutdown()
        udp_echo.server_close()
        udp_echo2.shutdown()
        udp_echo2.server_close()


DNS_HOP_HOST = "hy2-dns-hop-c9a5.test"
DNS_HOP_MARKER = f"# phase-hy2b-dns-hop {DNS_HOP_HOST}"


def _hosts_set(ip: str) -> None:
    """Point DNS_HOP_HOST at ip via /etc/hosts (requires write access)."""
    path = pathlib.Path("/etc/hosts")
    existing = path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in existing if DNS_HOP_MARKER not in line and DNS_HOP_HOST not in line]
    kept.append(f"{ip}\t{DNS_HOP_HOST} {DNS_HOP_MARKER}")
    text = "\n".join(kept) + "\n"
    try:
        path.write_text(text, encoding="utf-8")
    except PermissionError:
        subprocess.run(
            ["sudo", "tee", str(path)],
            input=text.encode(),
            check=True,
            stdout=subprocess.DEVNULL,
        )


def _hosts_clear() -> None:
    path = pathlib.Path("/etc/hosts")
    existing = path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in existing if DNS_HOP_MARKER not in line and DNS_HOP_HOST not in line]
    text = "\n".join(kept) + "\n"
    try:
        path.write_text(text, encoding="utf-8")
    except PermissionError:
        subprocess.run(
            ["sudo", "tee", str(path)],
            input=text.encode(),
            check=True,
            stdout=subprocess.DEVNULL,
        )


def exercise_dns_hop_switch(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    engine: str,
) -> dict[str, Any]:
    """After DNS flips the hop server IP, redials must use the new address.

    Regression: cached Quinn endpoint kept ObfsHopSocket hop_addrs/canonical from
    the first resolve, so post-DNS-change sends still hit the stale IP.

    Rust resolves the proxy hostname via the OS (`lookup_host` / `/etc/hosts`) and
    must rebuild the endpoint on the **same** Client (no reload). Go uses Clash
    `hosts:` and needs a controller reload to pick up the remapping.
    """
    from phase1 import reload_via_controller

    echo = start_server(EchoHandler)
    hop_ports = [reserve_port() for _ in range(3)]
    ports_yaml = ",".join(str(port) for port in hop_ports)
    mixed_port, controller_port = reserve_port(), reserve_port()

    def bring_up(ip: str, label: str) -> tuple[Any, Any, Any, list[BidirectionalUdpRelay]]:
        auth_port = reserve_port()
        auth_scratch = scratch / f"authority-{label}"
        auth_scratch.mkdir(parents=True, exist_ok=True)
        # Authority stays on 127.0.0.1; only the hop-facing relays move with DNS
        # so a stale ObfsHopSocket (still sending to the old IP) cannot succeed.
        authority, a_out, a_err = start_authority(
            authority_binary, auth_scratch, auth_port, listen_host="127.0.0.1"
        )
        time.sleep(0.4)
        if authority.poll() is not None:
            raise RuntimeError(f"authority {label} exited early")
        relays = [
            BidirectionalUdpRelay(port, auth_port, listen_host=ip) for port in hop_ports
        ]
        for relay in relays:
            relay.start()
        return authority, a_out, a_err, relays

    def write_config(mapped_ip: str) -> pathlib.Path:
        config = scratch / "config.yaml"
        hosts_block = ""
        if engine == "go":
            hosts_block = f"hosts:\n  {DNS_HOP_HOST}: {mapped_ip}\n"
        config.write_text(
            f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: true
{hosts_block}proxies:
{hy2_record(
    "hy2",
    hop_ports[0],
    server=DNS_HOP_HOST,
    ports=ports_yaml,
    hop_interval="5",
    disable_reuse=True,
)}
proxy-groups:
  - name: hy2-select
    type: select
    proxies: [hy2]
    default-selected: hy2
rules:
  - MATCH,hy2-select
"""
        )
        return config

    authority = a_out = a_err = None
    relays: list[BidirectionalUdpRelay] = []
    process = stdout = stderr = None
    try:
        _hosts_set("127.0.0.1")
        resolved = socket.getaddrinfo(DNS_HOP_HOST, hop_ports[0], type=socket.SOCK_DGRAM)
        if not any(item[4][0] == "127.0.0.1" for item in resolved):
            raise RuntimeError(f"hosts map failed: {resolved!r}")

        authority, a_out, a_err, relays = bring_up("127.0.0.1", "a")
        config = write_config("127.0.0.1")
        process, stdout, stderr = launch(binary, config, scratch)
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        time.sleep(0.3)
        before = tcp_exchange(mixed_port, "127.0.0.1", echo.port, b"dns-before")

        for relay in relays:
            relay.stop()
        relays = []
        stop(authority)
        a_out.close()
        a_err.close()
        authority = a_out = a_err = None

        _hosts_set("127.0.0.2")
        resolved = socket.getaddrinfo(DNS_HOP_HOST, hop_ports[0], type=socket.SOCK_DGRAM)
        if not any(item[4][0] == "127.0.0.2" for item in resolved):
            raise RuntimeError(f"hosts remap failed: {resolved!r}")

        authority, a_out, a_err, relays = bring_up("127.0.0.2", "b")
        if engine == "go":
            config = write_config("127.0.0.2")
            reload_via_controller(process, controller_port, config, secret=SECRET)
            time.sleep(0.3)
        after = tcp_exchange(mixed_port, "127.0.0.1", echo.port, b"dns-after")
        return {
            "before-ok": before,
            "after-ok": after,
            "process-alive": process.poll() is None,
        }
    finally:
        if process is not None:
            stop(process)
        if stdout is not None:
            stdout.close()
        if stderr is not None:
            stderr.close()
        for relay in relays:
            relay.stop()
        if authority is not None:
            stop(authority)
        if a_out is not None:
            a_out.close()
        if a_err is not None:
            a_err.close()
        _hosts_clear()
        echo.close()

def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-hy2b-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE_HY2B_CARGO_TARGET", "phase-hy2b")
        try:
            for engine in ("rust", "go"):
                profiles: dict[str, Any] = {}
                for name, kwargs in (
                    ("plain", {"salamander": False, "brutal": False, "hop": False}),
                    ("salamander", {"salamander": True, "brutal": False, "hop": False}),
                    ("brutal", {"salamander": False, "brutal": True, "hop": False}),
                    ("hop", {"salamander": False, "brutal": False, "hop": True}),
                    (
                        "salamander-brutal",
                        {"salamander": True, "brutal": True, "hop": False},
                    ),
                    (
                        "disable-reuse",
                        {
                            "salamander": False,
                            "brutal": False,
                            "hop": False,
                            "disable_reuse": True,
                        },
                    ),
                ):
                    scratch = root / engine / name
                    scratch.mkdir(parents=True)
                    profiles[name] = exercise_profile(
                        binaries[engine], binaries["go"], scratch, **kwargs
                    )
                observations[engine] = profiles

            for engine in ("rust", "go"):
                scratch = root / engine / "dns-hop-switch"
                scratch.mkdir(parents=True)
                dns = exercise_dns_hop_switch(
                    binaries[engine],
                    binaries["go"],
                    scratch,
                    engine=engine,
                )
                if not (dns.get("before-ok") and dns.get("after-ok")):
                    raise AssertionError(
                        f"{engine} dns-hop-switch failed: {dns}"
                    )
                observations[engine]["dns-hop-switch"] = dns

            observations["rust-rejects-gecko"] = not config_validation(
                binaries["rust"],
                root / "reject-gecko",
                "proxies:\n"
                "  - name: bad\n"
                "    type: hysteria2\n"
                "    server: 127.0.0.1\n"
                "    port: 443\n"
                "    password: x\n"
                "    obfs: gecko\n"
                "    obfs-password: abcd\n",
            )
            observations["rust-rejects-cwnd"] = not config_validation(
                binaries["rust"],
                root / "reject-cwnd",
                "proxies:\n"
                "  - name: bad\n"
                "    type: hysteria2\n"
                "    server: 127.0.0.1\n"
                "    port: 443\n"
                "    password: x\n"
                "    cwnd: 32\n",
            )
            observations["rust-rejects-bbr-profile"] = not config_validation(
                binaries["rust"],
                root / "reject-bbr",
                "proxies:\n"
                "  - name: bad\n"
                "    type: hysteria2\n"
                "    server: 127.0.0.1\n"
                "    port: 443\n"
                "    password: x\n"
                "    bbr-profile: aggressive\n",
            )
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

    if (
        observations["go"] != observations["rust"]
        or not observations.get("rust-rejects-gecko")
        or not observations.get("rust-rejects-cwnd")
        or not observations.get("rust-rejects-bbr-profile")
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("HY2-B Hysteria2 differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

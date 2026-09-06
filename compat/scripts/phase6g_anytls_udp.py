#!/usr/bin/env python3
"""Go/Rust differential for Phase 6G-C AnyTLS UDP via UoT v2 and destination reuse."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import pathlib
import socket
import socketserver
import ssl
import tempfile
import textwrap
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_udp import decode_socks_udp, socks_udp_packet, wait_exchange


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6g-anytls-udp-diff.json"
PASSWORD = "phase6g-udp-password"
PASSWORD_HASH = hashlib.sha256(PASSWORD.encode()).digest()
UOT_MAGIC = "sp.v2.udp-over-tcp.arpa"

CMD_WASTE = 0
CMD_SYN = 1
CMD_PSH = 2
CMD_FIN = 3
CMD_SETTINGS = 4
CMD_SYNACK = 7
CMD_SERVER_SETTINGS = 10


def read_frame(stream: socket.socket) -> tuple[int, int, bytes]:
    header = recv_exact(stream, 7)
    cmd = header[0]
    sid = int.from_bytes(header[1:5], "big")
    length = int.from_bytes(header[5:7], "big")
    data = recv_exact(stream, length) if length else b""
    return cmd, sid, data


def write_frame(stream: socket.socket, cmd: int, sid: int, data: bytes = b"") -> None:
    stream.sendall(bytes([cmd]) + sid.to_bytes(4, "big") + len(data).to_bytes(2, "big") + data)


def socks_address_size(payload: bytes) -> int:
    atyp = payload[0]
    if atyp == 1:
        return 7
    if atyp == 3:
        return 1 + 1 + payload[1] + 2
    if atyp == 4:
        return 19
    raise ValueError(f"unsupported socks atyp {atyp}")


def read_socks_address(payload: bytes) -> tuple[str, int, int]:
    size = socks_address_size(payload)
    atyp = payload[0]
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, payload[1:5])
        port = int.from_bytes(payload[5:7], "big")
    elif atyp == 3:
        length = payload[1]
        host = payload[2 : 2 + length].decode()
        port = int.from_bytes(payload[2 + length : 4 + length], "big")
    else:
        host = socket.inet_ntop(socket.AF_INET6, payload[1:17])
        port = int.from_bytes(payload[17:19], "big")
    return host, port, size


def read_uot_address(payload: bytes) -> tuple[str, int, int]:
    kind = payload[0]
    if kind == 0:
        host = socket.inet_ntop(socket.AF_INET, payload[1:5])
        port = int.from_bytes(payload[5:7], "big")
        return host, port, 7
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET6, payload[1:17])
        port = int.from_bytes(payload[17:19], "big")
        return host, port, 19
    if kind == 2:
        length = payload[1]
        host = payload[2 : 2 + length].decode()
        port = int.from_bytes(payload[2 + length : 4 + length], "big")
        return host, port, 1 + 1 + length + 2
    raise ValueError(f"unsupported uot address kind {kind}")


def encode_uot_address(host: str, port: int) -> bytes:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("ascii")
        return bytes([2, len(encoded)]) + encoded + port.to_bytes(2, "big")
    if address.version == 4:
        return bytes([0]) + address.packed + port.to_bytes(2, "big")
    return bytes([1]) + address.packed + port.to_bytes(2, "big")


def process_uot(
    stream: socket.socket,
    sid: int,
    state: dict[str, Any],
    authority: "AnyTlsUdpAuthority",
) -> None:
    buf: bytearray = state["buf"]
    while True:
        if not state["request_done"]:
            if len(buf) < 2:
                return
            is_connect = buf[0]
            try:
                host, port, size = read_socks_address(bytes(buf[1:]))
            except (IndexError, ValueError, UnicodeError, OSError):
                return
            if len(buf) < 1 + size:
                return
            authority.observe(f"UOT-REQUEST {is_connect} {host}:{port}")
            del buf[: 1 + size]
            state["request_done"] = True
            continue
        if len(buf) < 1:
            return
        try:
            host, port, size = read_uot_address(bytes(buf))
        except (IndexError, ValueError, UnicodeError, OSError):
            return
        if len(buf) < size + 2:
            return
        length = int.from_bytes(buf[size : size + 2], "big")
        if len(buf) < size + 2 + length:
            return
        payload = bytes(buf[size + 2 : size + 2 + length])
        del buf[: size + 2 + length]
        authority.observe(f"PACKET {host}:{port} {len(payload)}")
        reply = encode_uot_address(host, port) + len(payload).to_bytes(2, "big") + payload
        write_frame(stream, CMD_PSH, sid, reply)


class AnyTlsUdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        stream: socket.socket = self.request
        authority: AnyTlsUdpAuthority = self.server.authority
        try:
            digest = recv_exact(stream, 32)
            padding_len = int.from_bytes(recv_exact(stream, 2), "big")
            if padding_len:
                recv_exact(stream, padding_len)
            if digest != PASSWORD_HASH:
                authority.observe("AUTH reject")
                return
            authority.observe("AUTH accept")
            streams: dict[int, Any] = {}
            while True:
                cmd, sid, data = read_frame(stream)
                if cmd == CMD_WASTE:
                    continue
                if cmd == CMD_SETTINGS:
                    authority.observe("SETTINGS")
                    write_frame(stream, CMD_SERVER_SETTINGS, 0, b"v=2")
                    continue
                if cmd == CMD_SYN:
                    streams[sid] = bytearray()
                    authority.observe(f"SYN {sid}")
                    continue
                if cmd == CMD_PSH:
                    state = streams.get(sid)
                    if state is None:
                        continue
                    if isinstance(state, bytearray):
                        state.extend(data)
                        try:
                            host, port, size = read_socks_address(bytes(state))
                        except (IndexError, ValueError, UnicodeError, OSError):
                            continue
                        if len(state) < size:
                            continue
                        authority.observe(f"CONNECT {host}:{port}")
                        write_frame(stream, CMD_SYNACK, sid)
                        remainder = bytes(state[size:])
                        if host == UOT_MAGIC and port == 0:
                            streams[sid] = {
                                "buf": bytearray(remainder),
                                "request_done": False,
                            }
                            process_uot(stream, sid, streams[sid], authority)
                        else:
                            streams[sid] = bytearray(b"\x00")
                        continue
                    if isinstance(state, dict):
                        state["buf"].extend(data)
                        process_uot(stream, sid, state, authority)
                    continue
                if cmd == CMD_FIN:
                    authority.observe(f"FIN {sid}")
                    write_frame(stream, CMD_FIN, sid)
                    streams.pop(sid, None)
                    continue
        except (EOFError, OSError, ValueError, UnicodeError):
            return


class AnyTlsUdpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, authority: "AnyTlsUdpAuthority") -> None:
        self.authority = authority
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        self.context.set_alpn_protocols(["h2", "http/1.1"])
        self.context.set_servername_callback(
            lambda stream, name, _context: authority.observe(f"TLS {name or '<none>'}")
        )
        super().__init__(("127.0.0.1", 0), AnyTlsUdpHandler)

    def get_request(self) -> tuple[socket.socket, Any]:
        stream, address = super().get_request()
        try:
            tls = self.context.wrap_socket(stream, server_side=True)
            self.authority.observe(f"ALPN {tls.selected_alpn_protocol() or '<none>'}")
            return tls, address
        except Exception:
            stream.close()
            raise


class AnyTlsUdpAuthority:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.lock = threading.Lock()
        self.server = AnyTlsUdpServer(self)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def observe(self, value: str) -> None:
        with self.lock:
            self.counts[value] = self.counts.get(value, 0) + 1

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return dict(sorted(self.counts.items()))

    def reset(self) -> None:
        with self.lock:
            self.counts.clear()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def roots() -> str:
    root = pathlib.Path(ROOT_CERTIFICATE).read_text().strip()
    return "tls:\n  custom-certifactes:\n    - |-\n" + textwrap.indent(root, "      ") + "\n"


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
    expected = str(ipaddress.ip_address(host))
    return response_host == expected and response_port == port and response_payload == payload


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority = AnyTlsUdpAuthority()
    authority.start()
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        roots()
        + f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: anytls-udp
    type: anytls
    server: 127.0.0.1
    port: {authority.port}
    password: {PASSWORD}
    sni: dot.phase4.test
    alpn: [h2, http/1.1]
    udp: true
    disable-reuse: false
rules:
  - MATCH,anytls-udp
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(IO_DEADLINE)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)

        first = wait_exchange(process, client, mixed_port, "127.0.0.1", 28401, b"ready")
        second = exchange(client, mixed_port, "192.0.2.91", 28402, bytes(range(256)) * 12)
        multi_wire = authority.snapshot()
        multi_destination = (
            first
            and second
            and multi_wire.get("AUTH accept", 0) == 1
            and multi_wire.get(f"CONNECT {UOT_MAGIC}:0", 0) >= 1
            and any(key.startswith("UOT-REQUEST 0 ") for key in multi_wire)
            and multi_wire.get("PACKET 127.0.0.1:28401 5", 0) >= 1
            and multi_wire.get("PACKET 192.0.2.91:28402 3072", 0) >= 1
            and sum(1 for key in multi_wire if key.startswith("SYN ")) == 1
        )

        client.close()
        time.sleep(0.25)
        authority.reset()

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        client.settimeout(IO_DEADLINE)
        reused = wait_exchange(process, client, mixed_port, "127.0.0.1", 28403, b"reuse")
        time.sleep(0.2)
        reuse_wire = authority.snapshot()
        session_reuse = (
            reused
            and reuse_wire.get("AUTH accept", 0) == 0
            and reuse_wire.get(f"CONNECT {UOT_MAGIC}:0", 0) >= 1
            and sum(1 for key in reuse_wire if key.startswith("SYN ")) >= 1
            and reuse_wire.get("PACKET 127.0.0.1:28403 5", 0) >= 1
        )

        status, body = request(controller_port, "GET", "/proxies/anytls-udp")
        snapshot = json.loads(body)
        return {
            "multi-destination": multi_destination,
            "session-reuse": session_reuse,
            "controller": {
                "status": status,
                "type": snapshot["type"],
                "udp": snapshot["udp"],
                "uot": snapshot["uot"],
                "xudp": snapshot["xudp"],
            },
            "process-alive": process.poll() is None,
            "debug": {
                "multi-wire": multi_wire,
                "reuse-wire": reuse_wire,
            },
        }
    finally:
        client.close()
        stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def public_view(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "multi-destination": entry["multi-destination"],
        "session-reuse": entry["session-reuse"],
        "controller": entry["controller"],
        "process-alive": entry["process-alive"],
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6g-anytls-udp-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6GANYTLSUDP_CARGO_TARGET", "phase6g-anytls-udp")
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
                        "error": f"{type(error).__name__}: {error}",
                        "observations": observations,
                        "debug": debug_files(root),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            raise

    go_view = public_view(observations["go"])
    rust_view = public_view(observations["rust"])
    if go_view != rust_view or not all(
        [
            go_view["multi-destination"],
            go_view["session-reuse"],
            go_view["process-alive"],
            go_view["controller"]["udp"],
            go_view["controller"]["uot"],
        ]
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6G-C AnyTLS UDP/UoT differential passed")
    print(json.dumps({"go": go_view, "rust": rust_view}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

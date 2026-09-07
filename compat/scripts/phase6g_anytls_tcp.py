#!/usr/bin/env python3
"""Go/Rust differential for Phase 6G-A AnyTLS native TLS TCP outbound."""

from __future__ import annotations

import hashlib
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
from phase5b1a import build_binaries, connect_domain, debug_files
from phase6e_vless_tcp import rejected_exchange


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6g-anytls-tcp-diff.json"
PASSWORD = "phase6g-password"
PASSWORD_HASH = hashlib.sha256(PASSWORD.encode()).digest()
LARGE_PAYLOAD = bytes(range(256)) * 512

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


def read_socks_address(payload: bytes) -> tuple[str, int]:
    atyp = payload[0]
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, payload[1:5])
        port = int.from_bytes(payload[5:7], "big")
    elif atyp == 3:
        length = payload[1]
        host = payload[2 : 2 + length].decode()
        port = int.from_bytes(payload[2 + length : 4 + length], "big")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, payload[1:17])
        port = int.from_bytes(payload[17:19], "big")
    else:
        raise ValueError(f"unsupported atyp {atyp}")
    return host, port


class AnyTlsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        stream: socket.socket = self.request
        authority: AnyTlsAuthority = self.server.authority
        try:
            digest = recv_exact(stream, 32)
            padding_len = int.from_bytes(recv_exact(stream, 2), "big")
            if padding_len:
                recv_exact(stream, padding_len)
            if digest != PASSWORD_HASH:
                authority.observe("AUTH reject")
                return
            authority.observe("AUTH accept")
            streams: dict[int, bytearray] = {}
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
                    if sid not in streams:
                        continue
                    buf = streams[sid]
                    if not buf and data:
                        # First payload is SocksAddr destination.
                        host, port = read_socks_address(data)
                        authority.observe(f"CONNECT {host}:{port}")
                        write_frame(stream, CMD_SYNACK, sid)
                        streams[sid] = bytearray(b"\x00")  # mark opened
                        continue
                    if data:
                        stream.sendall(
                            bytes([CMD_PSH])
                            + sid.to_bytes(4, "big")
                            + len(data).to_bytes(2, "big")
                            + data
                        )
                    continue
                if cmd == CMD_FIN:
                    authority.observe(f"FIN {sid}")
                    write_frame(stream, CMD_FIN, sid)
                    streams.pop(sid, None)
                    continue
        except (EOFError, OSError, ValueError, UnicodeError):
            return


class AnyTlsServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, authority: "AnyTlsAuthority") -> None:
        self.authority = authority
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        self.context.set_alpn_protocols(["h2", "http/1.1"])
        self.context.set_servername_callback(
            lambda stream, name, _context: authority.observe(f"TLS {name or '<none>'}")
        )
        super().__init__(("127.0.0.1", 0), AnyTlsHandler)

    def get_request(self) -> tuple[socket.socket, Any]:
        stream, address = super().get_request()
        try:
            tls = self.context.wrap_socket(stream, server_side=True)
            self.authority.observe(f"ALPN {tls.selected_alpn_protocol() or '<none>'}")
            return tls, address
        except Exception:
            stream.close()
            raise


class AnyTlsAuthority:
    def __init__(self) -> None:
        self.observations: set[str] = set()
        self.lock = threading.Lock()
        self.server = AnyTlsServer(self)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def observe(self, value: str) -> None:
        with self.lock:
            self.observations.add(value)

    def snapshot(self) -> list[str]:
        with self.lock:
            return sorted(self.observations)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def roots() -> str:
    root = pathlib.Path(ROOT_CERTIFICATE).read_text().strip()
    return "tls:\n  custom-certifactes:\n    - |-\n" + textwrap.indent(root, "      ") + "\n"


def exchange(port: int, host: str, target_port: int, payload: bytes, half_close: bool) -> bool:
    with connect_domain(port, host, target_port) as stream:
        stream.settimeout(IO_DEADLINE)
        stream.sendall(payload)
        if half_close:
            stream.shutdown(socket.SHUT_WR)
        return recv_exact(stream, len(payload)) == payload


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority = AnyTlsAuthority()
    authority.start()
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        roots()
        + f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: anytls-native
    type: anytls
    server: 127.0.0.1
    port: {authority.port}
    password: {PASSWORD}
    sni: dot.phase4.test
    alpn: [h2, http/1.1]
    disable-reuse: true
  - name: anytls-wrong-password
    type: anytls
    server: 127.0.0.1
    port: {authority.port}
    password: wrong-password
    sni: dot.phase4.test
    alpn: [h2, http/1.1]
    disable-reuse: true
rules:
  - DST-PORT,28003,anytls-wrong-password
  - MATCH,anytls-native
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        deadline = time.monotonic() + IO_DEADLINE
        while True:
            try:
                small = exchange(mixed_port, "anytls.phase6g", 28001, b"anytls", False)
                break
            except (AssertionError, EOFError, OSError):
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
        large = exchange(mixed_port, "large.phase6g", 28002, LARGE_PAYLOAD, False)
        # Half-close is deferred to Phase 6G-B: Go AnyTLS Stream has no CloseWrite,
        # so SOCKS write-shutdown races with echo delivery under Relay's closeWrite.
        wrong_password = rejected_exchange(mixed_port, "wrong.phase6g", 28003)
        return {
            "small": small,
            "large": large,
            "wrong-password-rejected": wrong_password,
            "process-alive": process.poll() is None,
            "wire": authority.snapshot(),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6g-anytls-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6GANYTLS_CARGO_TARGET", "phase6g-anytls")
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], scratch)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(json.dumps({
                "error": f"{type(error).__name__}: {error}",
                "observations": observations,
                "debug": debug_files(root),
            }, indent=2, sort_keys=True))
            raise
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6G-A AnyTLS native-TLS differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

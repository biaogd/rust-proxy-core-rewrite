#!/usr/bin/env python3
"""Go/Rust differential for Phase 6G-B AnyTLS session reuse, concurrent dials, half-close."""

from __future__ import annotations

import concurrent.futures
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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6g-anytls-mux-diff.json"
PASSWORD = "phase6g-password"
PASSWORD_HASH = hashlib.sha256(PASSWORD.encode()).digest()

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
                        host, port = read_socks_address(data)
                        authority.observe(f"CONNECT {host}:{port}")
                        write_frame(stream, CMD_SYNACK, sid)
                        streams[sid] = bytearray(b"\x00")
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
        self.counts: dict[str, int] = {}
        self.lock = threading.Lock()
        self.server = AnyTlsServer(self)
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



def exchange(port: int, host: str, target_port: int, payload: bytes) -> bool:
    with connect_domain(port, host, target_port) as stream:
        stream.settimeout(IO_DEADLINE)
        stream.sendall(payload)
        return recv_exact(stream, len(payload)) == payload


def wait_exchange(
    process: Any,
    mixed_port: int,
    host: str,
    target_port: int,
    payload: bytes,
) -> bool:
    deadline = time.monotonic() + IO_DEADLINE
    while True:
        try:
            return exchange(mixed_port, host, target_port, payload)
        except (AssertionError, EOFError, OSError):
            if process.poll() is not None or time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


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
  - name: anytls-reuse
    type: anytls
    server: 127.0.0.1
    port: {authority.port}
    password: {PASSWORD}
    sni: dot.phase4.test
    alpn: [h2, http/1.1]
    disable-reuse: false
rules:
  - MATCH,anytls-reuse
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)

        first = wait_exchange(process, mixed_port, "seq1.phase6g", 28011, b"seq-one")
        # Settle so Rust Drop returns the session to the idle pool before the next
        # dial. Go Stream.Close runs dieHook synchronously, so this delay does not
        # change Go's reuse contract.
        time.sleep(0.2)
        second = wait_exchange(process, mixed_port, "seq2.phase6g", 28012, b"seq-two")
        time.sleep(0.2)
        sequential_wire = authority.snapshot()
        sequential_reuse = (
            first
            and second
            and sequential_wire.get("AUTH accept", 0) == 1
            and sequential_wire.get("SYN 1", 0) >= 1
            and sequential_wire.get("SYN 2", 0) >= 1
        )

        authority.reset()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(exchange, mixed_port, "c1.phase6g", 28021, b"c-one"),
                pool.submit(exchange, mixed_port, "c2.phase6g", 28022, b"c-two"),
            ]
            concurrent_ok = [future.result(timeout=IO_DEADLINE) for future in futures]
        time.sleep(0.2)
        concurrent_success = all(concurrent_ok)

        # Half-close oracle (Go-observable): stream Close emits FIN; session stays
        # reusable. SOCKS SHUT_WR is not compared — Go Stream has no CloseWrite.
        authority.reset()
        third = wait_exchange(process, mixed_port, "fin.phase6g", 28031, b"fin-check")
        time.sleep(0.2)
        fourth = wait_exchange(process, mixed_port, "reuse.phase6g", 28032, b"reuse-check")
        half_close_wire = authority.snapshot()
        session_alive_after_fin = (
            third
            and fourth
            and any(key.startswith("FIN ") for key in half_close_wire)
            and half_close_wire.get("AUTH accept", 0) <= 1
            and sum(1 for key in half_close_wire if key.startswith("SYN ")) >= 1
        )

        return {
            "sequential-reuse": sequential_reuse,
            "concurrent-success": concurrent_success,
            "session-alive-after-fin": session_alive_after_fin,
            "process-alive": process.poll() is None,
            "debug": {
                "sequential-wire": sequential_wire,
                "concurrent-ok": concurrent_ok,
                "half-close-wire": half_close_wire,
            },
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def public_view(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "sequential-reuse": entry["sequential-reuse"],
        "concurrent-success": entry["concurrent-success"],
        "session-alive-after-fin": entry["session-alive-after-fin"],
        "process-alive": entry["process-alive"],
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6g-anytls-mux-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6GANYTLSMUX_CARGO_TARGET", "phase6g-anytls-mux")
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

    go_view = public_view(observations["go"])
    rust_view = public_view(observations["rust"])
    if go_view != rust_view or not all(go_view.values()):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6G-B AnyTLS mux/reuse/half-close differential passed")
    print(json.dumps({"go": go_view, "rust": rust_view}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

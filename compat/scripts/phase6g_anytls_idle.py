#!/usr/bin/env python3
"""Go/Rust differential for Phase 6G-D AnyTLS idle cleanup, heartbeat, recovery."""

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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6g-anytls-idle-diff.json"
PASSWORD = "phase6g-idle-password"
PASSWORD_HASH = hashlib.sha256(PASSWORD.encode()).digest()

# Go floors intervals <=5s to 30s; 6s keeps cleanup observable in CI.
IDLE_CHECK = 6
IDLE_TIMEOUT = 6
IDLE_WAIT = IDLE_CHECK + IDLE_TIMEOUT + 2

CMD_WASTE = 0
CMD_SYN = 1
CMD_PSH = 2
CMD_FIN = 3
CMD_SETTINGS = 4
CMD_SYNACK = 7
CMD_HEART_REQUEST = 8
CMD_HEART_RESPONSE = 9
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
        authority.register_stream(stream)
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
                    if authority.send_heartbeat_after_fin:
                        write_frame(stream, CMD_HEART_REQUEST, 0)
                        authority.observe("HEART request")
                    continue
                if cmd == CMD_HEART_RESPONSE:
                    authority.observe("HEART response")
                    continue
                if cmd == CMD_HEART_REQUEST:
                    write_frame(stream, CMD_HEART_RESPONSE, sid)
                    continue
        except (EOFError, OSError, ValueError, UnicodeError):
            return
        finally:
            authority.unregister_stream(stream)


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
    def __init__(self, *, send_heartbeat_after_fin: bool = False) -> None:
        self.counts: dict[str, int] = {}
        self.lock = threading.Lock()
        self.streams: set[socket.socket] = set()
        self.send_heartbeat_after_fin = send_heartbeat_after_fin
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

    def register_stream(self, stream: socket.socket) -> None:
        with self.lock:
            self.streams.add(stream)

    def unregister_stream(self, stream: socket.socket) -> None:
        with self.lock:
            self.streams.discard(stream)

    def drop_sessions(self) -> int:
        with self.lock:
            streams = list(self.streams)
            self.streams.clear()
        closed = 0
        for stream in streams:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                stream.close()
            except OSError:
                pass
            closed += 1
        return closed

    def close(self) -> None:
        self.drop_sessions()
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


def write_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    server_port: int,
    check: int,
    timeout: int,
    min_idle: int,
    disable_reuse: bool = False,
) -> None:
    reuse = "true" if disable_reuse else "false"
    path.write_text(
        roots()
        + f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: anytls-idle
    type: anytls
    server: 127.0.0.1
    port: {server_port}
    password: {PASSWORD}
    sni: dot.phase4.test
    alpn: [h2, http/1.1]
    disable-reuse: {reuse}
    idle-session-check-interval: {check}
    idle-session-timeout: {timeout}
    min-idle-session: {min_idle}
rules:
  - MATCH,anytls-idle
"""
    )


def run_proxy(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    check: int,
    timeout: int,
    min_idle: int,
    heartbeat: bool = False,
):
    authority = AnyTlsAuthority(send_heartbeat_after_fin=heartbeat)
    authority.start()
    scratch.mkdir(parents=True, exist_ok=True)
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    write_config(
        config,
        mixed_port=mixed_port,
        server_port=authority.port,
        check=check,
        timeout=timeout,
        min_idle=min_idle,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        yield process, mixed_port, authority
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def case_idle_evict(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    gen = run_proxy(
        binary,
        scratch / "evict",
        check=IDLE_CHECK,
        timeout=IDLE_TIMEOUT,
        min_idle=0,
    )
    process, mixed_port, authority = next(gen)
    try:
        first = wait_exchange(process, mixed_port, "evict1.phase6g", 28101, b"evict-one")
        time.sleep(IDLE_WAIT)
        second = wait_exchange(process, mixed_port, "evict2.phase6g", 28102, b"evict-two")
        wire = authority.snapshot()
        ok = first and second and wire.get("AUTH accept", 0) == 2
        return {"ok": ok, "auth_accept": wire.get("AUTH accept", 0), "wire": wire}
    finally:
        try:
            next(gen)
        except StopIteration:
            pass


def case_min_idle_keep(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    gen = run_proxy(
        binary,
        scratch / "keep",
        check=IDLE_CHECK,
        timeout=IDLE_TIMEOUT,
        min_idle=1,
    )
    process, mixed_port, authority = next(gen)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(exchange, mixed_port, "keep1.phase6g", 28111, b"keep-one"),
                pool.submit(exchange, mixed_port, "keep2.phase6g", 28112, b"keep-two"),
            ]
            concurrent_ok = [future.result(timeout=IO_DEADLINE) for future in futures]
        time.sleep(0.3)
        time.sleep(IDLE_WAIT)
        third = wait_exchange(process, mixed_port, "keep3.phase6g", 28113, b"keep-three")
        wire = authority.snapshot()
        # Two sessions created; cleanup keeps one; third dial reuses → still 2 AUTH.
        ok = all(concurrent_ok) and third and wire.get("AUTH accept", 0) == 2
        return {"ok": ok, "auth_accept": wire.get("AUTH accept", 0), "wire": wire}
    finally:
        try:
            next(gen)
        except StopIteration:
            pass


def case_disconnect_recovery(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    gen = run_proxy(
        binary,
        scratch / "disc",
        check=30,
        timeout=30,
        min_idle=0,
    )
    process, mixed_port, authority = next(gen)
    try:
        first = wait_exchange(process, mixed_port, "disc1.phase6g", 28121, b"disc-one")
        time.sleep(0.2)
        dropped = authority.drop_sessions()
        time.sleep(0.2)
        second = wait_exchange(process, mixed_port, "disc2.phase6g", 28122, b"disc-two")
        wire = authority.snapshot()
        ok = first and second and dropped >= 1 and wire.get("AUTH accept", 0) >= 2
        return {
            "ok": ok,
            "auth_accept": wire.get("AUTH accept", 0),
            "dropped": dropped,
            "wire": wire,
        }
    finally:
        try:
            next(gen)
        except StopIteration:
            pass


def case_heartbeat(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    gen = run_proxy(
        binary,
        scratch / "hb",
        check=30,
        timeout=30,
        min_idle=0,
        heartbeat=True,
    )
    process, mixed_port, authority = next(gen)
    try:
        first = wait_exchange(process, mixed_port, "hb1.phase6g", 28131, b"hb-one")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and authority.snapshot().get("HEART response", 0) < 1:
            time.sleep(0.05)
        time.sleep(0.2)
        second = wait_exchange(process, mixed_port, "hb2.phase6g", 28132, b"hb-two")
        wire = authority.snapshot()
        ok = (
            first
            and second
            and wire.get("HEART request", 0) >= 1
            and wire.get("HEART response", 0) >= 1
            and wire.get("AUTH accept", 0) == 1
        )
        return {
            "ok": ok,
            "auth_accept": wire.get("AUTH accept", 0),
            "heart_request": wire.get("HEART request", 0),
            "heart_response": wire.get("HEART response", 0),
            "wire": wire,
        }
    finally:
        try:
            next(gen)
        except StopIteration:
            pass


def case_stress(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    gen = run_proxy(
        binary,
        scratch / "stress",
        check=30,
        timeout=30,
        min_idle=4,
    )
    process, mixed_port, authority = next(gen)
    try:
        def stress_one(index: int) -> bool:
            try:
                return exchange(
                    mixed_port,
                    f"s{index}.phase6g",
                    28200 + index,
                    f"stress-{index}".encode(),
                )
            except Exception:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(stress_one, i) for i in range(8)]
            results = [future.result(timeout=IO_DEADLINE) for future in futures]
        wire = authority.snapshot()
        ok_count = sum(1 for item in results if item)
        auth_accept = wire.get("AUTH accept", 0)
        # Concurrent dials race session reuse: Go/Rust may land between 1..8 AUTH
        # accepts for the same 8 successful exchanges. Compare outcome counts only.
        ok = (
            ok_count == 8
            and process.poll() is None
            and 1 <= auth_accept <= 8
        )
        return {
            "ok": ok,
            "ok_count": ok_count,
            "auth_accept": auth_accept,
            "wire": wire,
        }
    finally:
        try:
            next(gen)
        except StopIteration:
            pass


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    return {
        "idle-evict": case_idle_evict(binary, scratch),
        "min-idle-keep": case_min_idle_keep(binary, scratch),
        "disconnect-recovery": case_disconnect_recovery(binary, scratch),
        "heartbeat-response": case_heartbeat(binary, scratch),
        "stress-8": case_stress(binary, scratch),
    }


def public_view(entry: dict[str, Any]) -> dict[str, Any]:
    # stress-8 auth_accept is timing-dependent under parallel dials; keep it in
    # raw observations for debug but out of the Go/Rust equality surface.
    comparable_keys = {
        "idle-evict": ("auth_accept",),
        "min-idle-keep": ("auth_accept",),
        "disconnect-recovery": ("auth_accept", "dropped"),
        "heartbeat-response": ("auth_accept", "heart_request", "heart_response"),
        "stress-8": ("ok_count",),
    }
    return {
        name: {
            "ok": case["ok"],
            **{
                key: case[key]
                for key in comparable_keys.get(name, ())
                if key in case
            },
        }
        for name, case in entry.items()
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6g-anytls-idle-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6GANYTLSIDLE_CARGO_TARGET", "phase6g-anytls-idle")
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
    matched = go_view == rust_view and all(
        case["ok"] for case in go_view.values()
    )
    if not matched:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6G-D AnyTLS idle/heartbeat/recovery differential passed")
    print(json.dumps({"go": go_view, "rust": rust_view}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

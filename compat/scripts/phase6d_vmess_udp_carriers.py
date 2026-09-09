#!/usr/bin/env python3
"""Go/Rust differential for VMess UDP over TLS, WS/WSS and Gun/gRPC carriers.

Covers ordinary UDP, packet-address and XUDP across the four carriers (12
combinations), plus a silent WebSocket handshake hang regression (immediate and
early-data deferred) that asserts the DefaultUDPTimeout disconnect and a prompt
SIGTERM exit.
"""

from __future__ import annotations

import json
import pathlib
import select
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, recv_exact, request_graceful_shutdown, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase6d_vmess_tcp import build_authority, start_authority, vmess_record
from phase6d_vmess_udp import exchange, socks_udp_packet
from phase6d_vmess_websocket import trusted_roots


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6d-vmess-udp-carriers-diff.json"
UDP_SETUP_TIMEOUT = 5.0
SIGTERM_EXIT_BUDGET = 3.0

PACKET_MODES = (
    ("standard", "", "standard"),
    ("packetaddr", "    packet-encoding: packet\n", "packetaddr"),
    ("xudp", "    packet-encoding: xudp\n", "xudp"),
)

CARRIERS = (
    (
        "tls",
        "tcp",
        True,
        "",
        dict(
            transport="tcp",
            certificate=pathlib.Path(SERVER_CERTIFICATE),
            private_key=pathlib.Path(SERVER_KEY),
        ),
        "TLS dot.phase4.test",
    ),
    (
        "ws",
        "ws",
        False,
        "    ws-opts:\n      path: /udp\n      headers:\n        Host: udp-ws.phase6d\n",
        dict(
            transport="ws",
            expected_ws_host="udp-ws.phase6d",
            expected_ws_path="/udp",
        ),
        "WS udp-ws.phase6d /udp",
    ),
    (
        "wss",
        "ws",
        True,
        "    ws-opts:\n      path: /udp-wss\n      headers:\n        Host: udp-wss.phase6d\n",
        dict(
            transport="ws",
            certificate=pathlib.Path(SERVER_CERTIFICATE),
            private_key=pathlib.Path(SERVER_KEY),
            expected_ws_host="udp-wss.phase6d",
            expected_ws_path="/udp-wss",
        ),
        "WS udp-wss.phase6d /udp-wss",
    ),
    (
        "grpc",
        "grpc",
        True,
        "    grpc-opts:\n      grpc-service-name: udp\n      grpc-user-agent: phase6d-udp/1.0\n",
        dict(
            transport="grpc",
            certificate=pathlib.Path(SERVER_CERTIFICATE),
            private_key=pathlib.Path(SERVER_KEY),
            expected_http_host="dot.phase4.test",
            expected_http_path="/udp/Tun",
            expected_grpc_user_agent="phase6d-udp/1.0",
        ),
        "GRPC POST dot.phase4.test /udp/Tun application/grpc phase6d-udp/1.0",
    ),
)

PAYLOADS = {
    "tls": b"udp-tls",
    "ws": bytes(range(256)) * 5,
    "wss": bytes(range(256)) * 3,
    "grpc": bytes(range(256)) * 8,
}


def wait_exchange(
    process: Any,
    client: socket.socket,
    mixed_port: int,
    host: str,
    port: int,
    payload: bytes,
) -> bool:
    deadline = time.monotonic() + IO_DEADLINE
    client.settimeout(0.25)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"proxy exited during VMess UDP carrier readiness: {process.returncode}"
            )
        try:
            if exchange(client, mixed_port, host, port, payload):
                client.settimeout(IO_DEADLINE)
                return True
        except TimeoutError:
            pass
        time.sleep(0.02)
    raise TimeoutError("VMess UDP carrier did not become ready")


def wait_observations(authorities: list[tuple[Any, pathlib.Path]], expected: set[str]) -> list[str]:
    deadline = time.monotonic() + (2 * IO_DEADLINE)
    while time.monotonic() < deadline:
        observed: set[str] = set()
        for process, output in authorities:
            if process.poll() is not None:
                raise RuntimeError("VMess UDP carrier authority exited")
            observed.update(
                line.strip()
                for line in output.read_text(errors="replace").splitlines()
                if line.startswith(("TLS ", "ALPN ", "WS ", "GRPC ", "PACKET "))
            )
        if expected <= observed:
            return sorted(expected)
        time.sleep(0.02)
    raise TimeoutError(f"missing VMess UDP carrier observations: {sorted(expected - observed)}")


def record(
    name: str,
    port: int,
    network: str,
    *,
    tls: bool,
    packet_encoding: str,
    options: str = "",
) -> str:
    tls_fields = ""
    if tls:
        tls_fields = "    tls: true\n    servername: dot.phase4.test\n"
    text = vmess_record(
        name,
        port,
        cipher="aes-128-gcm",
        extra=f"    udp: true\n{packet_encoding}{tls_fields}{options}",
    )
    return text.replace("    network: tcp\n", f"    network: {network}\n")


def combo_destination(index: int) -> tuple[str, int]:
    return f"192.0.2.{81 + index}", 27401 + index


def exercise(binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authorities: list[tuple[Any, pathlib.Path]] = []
    handles: list[tuple[Any, Any, Any]] = []
    proxy_yaml: list[str] = []
    rules: list[str] = []
    matrix_keys: list[tuple[str, str, int, bytes]] = []
    expected: set[str] = set()
    index = 0
    for mode_name, packet_encoding, authority_mode in PACKET_MODES:
        for carrier_name, network, tls, options, authority_opts, carrier_observation in CARRIERS:
            listen_port = reserve_port()
            host, destination_port = combo_destination(index)
            payload = PAYLOADS[carrier_name]
            proxy_name = f"vmess-udp-{mode_name}-{carrier_name}"
            process, stdout, stderr, output = start_authority(
                authority_binary,
                scratch,
                listen_port,
                log_name=f"authority-{mode_name}-{carrier_name}",
                packet_mode=authority_mode,
                **authority_opts,
            )
            authorities.append((process, output))
            handles.append((process, stdout, stderr))
            proxy_yaml.append(
                record(
                    proxy_name,
                    listen_port,
                    network,
                    tls=tls,
                    packet_encoding=packet_encoding,
                    options=options,
                )
            )
            rules.append(f"  - DST-PORT,{destination_port},{proxy_name}")
            matrix_keys.append((f"{mode_name}/{carrier_name}", host, destination_port, payload))
            expected.add(carrier_observation)
            if carrier_name == "grpc":
                expected.add("ALPN h2")
            expected.add(f"PACKET {authority_mode} {host}:{destination_port} {len(payload)}")
            index += 1

    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        trusted_roots()
        + f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
{"".join(proxy_yaml)}rules:
{chr(10).join(rules)}
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    clients: list[socket.socket] = []
    try:
        wait_ready(process, mixed_port)
        matrix: dict[str, bool] = {}
        for key, host, destination_port, payload in matrix_keys:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.bind(("127.0.0.1", 0))
            clients.append(client)
            matrix[key] = wait_exchange(
                process, client, mixed_port, host, destination_port, payload
            )
        authority = wait_observations(authorities, expected)
        process_alive = process.poll() is None
    finally:
        for client in clients:
            client.close()
        stop(process)
        stdout.close()
        stderr.close()
        for authority_proc, authority_stdout, authority_stderr in handles:
            stop(authority_proc)
            authority_stdout.close()
            authority_stderr.close()

    return {
        "matrix": matrix,
        "authority": authority,
        "process-alive": process_alive,
        "grpc-cancel": pooled_grpc_cancellation(binary, authority_binary, scratch / "grpc-cancel"),
        "silent-ws": silent_ws_handshake_cases(
            binary,
            scratch / "silent",
            # Go cancels the ListenPacket ctx before deferred early-data Write,
            # so the underlay may stay open; Rust bounds the association write.
            expect_early_disconnect="rewrite-core" in binary.name,
        ),
    }

def pooled_grpc_cancellation(
    binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    """Delay only stream 3's response headers; stream 1 must survive cancellation.

    The relay forwards unchanged HTTP/2 frames except the deliberately stalled
    response. VMess/Gun parsing and echo remain in the independent Go authority.
    """
    scratch.mkdir(parents=True)
    authority_port = reserve_port()
    authority, aout, aerr, _ = start_authority(
        authority_binary, scratch, authority_port, transport="grpc", packet_mode="xudp"
    )
    acceptor = socket.socket()
    acceptor.bind(("127.0.0.1", 0))
    acceptor.listen(8)
    acceptor.settimeout(0.2)
    stopping = threading.Event()
    blocked = threading.Event()
    first_closed = threading.Event()
    held: list[socket.socket] = []
    connections: list[socket.socket] = []
    workers: list[threading.Thread] = []

    def relay(source: socket.socket, target: socket.socket, framed: bool, first: bool) -> None:
        try:
            while not stopping.is_set():
                if framed:
                    header = recv_exact(source, 9)
                    payload = recv_exact(source, int.from_bytes(header[:3], "big"))
                    stream_id = int.from_bytes(header[5:9], "big") & 0x7fff_ffff
                    if stream_id == 3:
                        if header[3] == 1:  # HEADERS; deliberately omit only this response
                            blocked.set()
                        continue
                    target.sendall(header + payload)
                else:
                    data = source.recv(65_535)
                    if not data:
                        break
                    target.sendall(data)
        except (OSError, EOFError):
            pass
        finally:
            if first:
                first_closed.set()

    def accept_loop() -> None:
        while not stopping.is_set():
            try:
                downstream, _ = acceptor.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            upstream = socket.create_connection(("127.0.0.1", authority_port), timeout=2)
            upstream.settimeout(None)
            held.extend((downstream, upstream))
            connections.append(downstream)
            for source, target, framed in [(downstream, upstream, False), (upstream, downstream, True)]:
                worker = threading.Thread(
                    target=relay, args=(source, target, framed, len(connections) == 1), daemon=True
                )
                workers.append(worker)
                worker.start()

    accepting = threading.Thread(target=accept_loop, daemon=True)
    accepting.start()
    mixed = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"mixed-port: {mixed}\nmode: rule\nlog-level: info\nipv6: false\nproxies:\n"
        + record("pooled", acceptor.getsockname()[1], "grpc", tls=False,
                 packet_encoding="    packet-encoding: xudp\n",
                 options="    grpc-opts:\n      grpc-service-name: udp\n      max-connections: 1\n      min-streams: 1\n")
        + "rules:\n  - MATCH,pooled\n"
    )
    process, stdout, stderr = launch(binary, config, scratch)
    clients = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
    for client in clients:
        client.bind(("127.0.0.1", 0))
    try:
        wait_ready(process, mixed)
        assert wait_exchange(process, clients[0], mixed, "192.0.2.81", 27401, b"before-cancel")
        clients[1].sendto(socks_udp_packet("192.0.2.82", 27402, b"stalled"), ("127.0.0.1", mixed))
        assert blocked.wait(IO_DEADLINE), "second logical stream was not observed"
        assert not first_closed.wait(UDP_SETUP_TIMEOUT + 1), "cancelling stream 3 killed shared connection"
        clients[0].settimeout(IO_DEADLINE)
        assert exchange(clients[0], mixed, "192.0.2.81", 27401, b"after-cancel"), "healthy stream stopped echoing"
        assert len(connections) == 1, "healthy association silently redialed"
        assert process.poll() is None
        return {"healthy-stream-survives": True, "physical-connections": 1}
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stopping.set()
        acceptor.close()
        accepting.join(timeout=3)
        for stream in held + clients:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.close()
        for worker in workers:
            worker.join(timeout=1)
        stop(authority)
        aout.close()
        aerr.close()


def peer_closed(conn: socket.socket, deadline: float) -> bool:
    while time.monotonic() < deadline:
        readable, _, _ = select.select([conn], [], [], 0.05)
        if not readable:
            continue
        try:
            chunk = conn.recv(4096)
        except ConnectionResetError:
            return True
        if not chunk:
            return True
    return False


def hold_silent_accept(
    acceptor: socket.socket,
    accepted: list[tuple[socket.socket, float]],
    stop_event: threading.Event,
) -> None:
    acceptor.settimeout(0.2)
    while not stop_event.is_set():
        try:
            conn, _ = acceptor.accept()
        except TimeoutError:
            continue
        except OSError:
            return
        accepted.append((conn, time.monotonic()))


def expected_sigterm_exit_code() -> int:
    # Both Go and Rust handle SIGTERM through their signal loops and exit 0.
    return 0


def silent_ws_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    label: str,
    early_data: bool,
    require_disconnect: bool,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    acceptor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    acceptor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    acceptor.bind(("127.0.0.1", 0))
    acceptor.listen(8)
    listen_port = acceptor.getsockname()[1]
    accepted: list[tuple[socket.socket, float]] = []
    stop_event = threading.Event()
    thread = threading.Thread(
        target=hold_silent_accept,
        args=(acceptor, accepted, stop_event),
        daemon=True,
    )
    thread.start()

    mixed_port = reserve_port()
    early_opts = ""
    if early_data:
        early_opts = (
            "      max-early-data: 2048\n"
            "      early-data-header-name: Sec-WebSocket-Protocol\n"
        )
    home = scratch / f"home-{label}"
    home.mkdir(parents=True, exist_ok=True)
    config = scratch / f"config-{label}.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
{record(
    "vmess-silent-ws",
    listen_port,
    "ws",
    tls=False,
    packet_encoding="    packet-encoding: xudp\n",
    options=(
        "    ws-opts:\n"
        "      path: /silent\n"
        + early_opts
        + "      headers:\n"
        "        Host: silent-ws.phase6d\n"
    ),
)}rules:
  - DST-PORT,27901,vmess-silent-ws
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, home)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    try:
        wait_ready(process, mixed_port)
        deadline = time.monotonic() + UDP_SETUP_TIMEOUT + 1.0
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"{label}: proxy exited before silent WS dial: {process.returncode}"
                )
            client.sendto(
                socks_udp_packet("192.0.2.99", 27901, b"silent-hang"),
                ("127.0.0.1", mixed_port),
            )
            if accepted:
                break
            time.sleep(0.05)
        if not accepted:
            raise TimeoutError(f"{label}: silent acceptor never received a TCP dial")
        conn, accepted_at = accepted[0]
        disconnect_deadline = accepted_at + UDP_SETUP_TIMEOUT + 0.75
        disconnected = peer_closed(conn, disconnect_deadline)
        disconnect_elapsed = time.monotonic() - accepted_at
        if require_disconnect and not disconnected:
            raise AssertionError(
                f"{label}: peer did not drop silent WS handshake within "
                f"{UDP_SETUP_TIMEOUT}s (waited {disconnect_elapsed:.2f}s)"
            )

        # Fresh source → new UDP session so SIGTERM lands during an in-flight dial,
        # even if the first association is still holding its underlay.
        before_second = len(accepted)
        second_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        second_client.bind(("127.0.0.1", 0))
        try:
            second_deadline = time.monotonic() + UDP_SETUP_TIMEOUT
            while time.monotonic() < second_deadline:
                if process.poll() is not None:
                    raise RuntimeError(
                        f"{label}: proxy exited before second silent WS dial: "
                        f"{process.returncode}"
                    )
                second_client.sendto(
                    socks_udp_packet("192.0.2.99", 27901, b"silent-sigterm"),
                    ("127.0.0.1", mixed_port),
                )
                if len(accepted) > before_second:
                    break
                time.sleep(0.05)
        finally:
            second_client.close()
        if len(accepted) <= before_second:
            raise TimeoutError(f"{label}: second silent WS dial never started")
        time.sleep(0.3)
        request_graceful_shutdown(process)
        exit_started = time.monotonic()
        expected_exit = expected_sigterm_exit_code()
        try:
            exit_code = process.wait(timeout=SIGTERM_EXIT_BUDGET)
        except subprocess.TimeoutExpired as error:
            raise AssertionError(
                f"{label}: SIGTERM did not exit within {SIGTERM_EXIT_BUDGET}s"
            ) from error
        if exit_code != expected_exit:
            raise AssertionError(
                f"{label}: unexpected SIGTERM exit code {exit_code}, expected {expected_exit}"
            )
        exit_elapsed = time.monotonic() - exit_started
        return {
            "disconnect-within-timeout": disconnected,
            "disconnect-required": require_disconnect,
            "disconnect-elapsed": round(disconnect_elapsed, 3),
            "second-dial-started": True,
            "sigterm-exit-code": exit_code,
            "sigterm-exit-elapsed": round(exit_elapsed, 3),
            "early-data": early_data,
        }
    finally:
        client.close()
        stop_event.set()
        try:
            acceptor.close()
        except OSError:
            pass
        for held, _ in accepted:
            try:
                held.close()
            except OSError:
                pass
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        thread.join(timeout=1.0)


def silent_ws_handshake_cases(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    expect_early_disconnect: bool,
) -> dict[str, Any]:
    return {
        "immediate": silent_ws_case(
            binary,
            scratch / "immediate",
            label="immediate",
            early_data=False,
            require_disconnect=True,
        ),
        "early-data": silent_ws_case(
            binary,
            scratch / "early-data",
            label="early-data",
            early_data=True,
            require_disconnect=expect_early_disconnect,
        ),
    }


def comparable_observations(observations: dict[str, Any]) -> dict[str, Any]:
    def silent_case(details: dict[str, Any]) -> dict[str, Any]:
        # Immediate handshake disconnect is compared Go/Rust. Early-data disconnect is
        # Rust-only (enforced by require_disconnect during the case) because Go cancels
        # the ListenPacket ctx before the deferred upgrade Write.
        out: dict[str, Any] = {
            "early-data": details["early-data"],
            "second-dial-started": details["second-dial-started"],
            "sigterm-exit-code": details["sigterm-exit-code"],
        }
        if not details["early-data"]:
            out["disconnect-within-timeout"] = details["disconnect-within-timeout"]
        return out

    return {
        runtime: {
            "matrix": payload["matrix"],
            "authority": payload["authority"],
            "process-alive": payload["process-alive"],
            "grpc-cancel": payload["grpc-cancel"],
            "silent-ws": {
                case: silent_case(details) for case, details in payload["silent-ws"].items()
            },
        }
        for runtime, payload in observations.items()
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6d-vmess-udp-carriers-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6DVMESSUDPCARRIERS_CARGO_TARGET", "phase6d-udp-carriers")
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
    if comparable_observations(observations)["go"] != comparable_observations(observations)["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6D VMess UDP carrier differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

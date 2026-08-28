#!/usr/bin/env python3
"""Local Go/Rust differential suite for the Phase 3A TCP gate."""

from __future__ import annotations

import base64
import http.client
import json
import os
import pathlib
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import (
    BASELINE,
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    RUST_ROOT,
    assert_go_oracle_baseline,
    cargo_target_path,
    connect_proxy,
    recv_all,
    recv_exact,
    recv_until,
    reserve_port,
    start_server,
    wait_ready,
)


FIXTURES = ROOT / "compat" / "fixtures" / "phase3"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase3-diff.json"


def build_binaries(output: pathlib.Path) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()

    go_override = os.environ.get("PHASE3_GO_BINARY")
    go_binary = pathlib.Path(go_override) if go_override else output / "go-oracle"
    if not go_override:
        subprocess.run(
            ["go", "build", "-trimpath", "-o", str(go_binary), "."],
            cwd=ROOT,
            check=True,
        )
    rust_target = cargo_target_path("PHASE3_CARGO_TARGET", "phase3-rust")
    rust_override = os.environ.get("PHASE3_RUST_BINARY")
    rust_binary = (
        pathlib.Path(rust_override)
        if rust_override
        else rust_target / "debug" / "rewrite-core"
    )
    if not rust_override:
        subprocess.run(
            ["cargo", "build", "--workspace", "--target-dir", str(rust_target)],
            cwd=RUST_ROOT,
            check=True,
        )
    return {"go": go_binary, "rust": rust_binary}


def launch(binary: pathlib.Path, config: pathlib.Path, scratch: pathlib.Path) -> tuple[subprocess.Popen[bytes], Any, Any]:
    stdout = (scratch / "stdout.log").open("wb")
    stderr = (scratch / "stderr.log").open("wb")
    config_home = scratch / ".config"
    profile_home = config_home / "mihomo"
    process = subprocess.Popen(
        [str(binary), "-f", str(config)],
        cwd=scratch,
        env={
            **os.environ,
            "HOME": str(scratch),
            "XDG_CONFIG_HOME": str(config_home),
            "CLASH_HOME_DIR": str(profile_home),
        },
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    return process, stdout, stderr


def stop(process: subprocess.Popen[bytes]) -> int:
    if process.poll() is None:
        if os.name == "nt":
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGTERM)
    try:
        return process.wait(timeout=IO_DEADLINE)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        return process.wait(timeout=IO_DEADLINE)


def closed(stream: socket.socket) -> bool:
    try:
        return stream.recv(1) == b""
    except (ConnectionResetError, BrokenPipeError):
        return True


def http_request(
    port: int, destination_port: int, authorization: str | None
) -> tuple[socket.socket, bytes]:
    stream = connect_proxy(port)
    header = ""
    if authorization is not None:
        header = f"Proxy-Authorization: {authorization}\r\n"
    stream.sendall(
        (
            f"CONNECT 127.0.0.1:{destination_port} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{destination_port}\r\n"
            f"{header}\r\n"
        ).encode()
    )
    return stream, recv_until(stream, b"\r\n\r\n")


def status(response: bytes) -> str:
    return response.split(b"\r\n", 1)[0].decode()


def wait_authenticated_ready(
    process: subprocess.Popen[bytes], proxy_port: int, destination_port: int
) -> None:
    credential = base64.b64encode(b"alice:secret").decode()
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during readiness with {process.returncode}")
        try:
            stream, response = http_request(
                proxy_port, destination_port, f"Basic {credential}"
            )
            with stream:
                if " 200 " not in status(response):
                    raise AssertionError(response)
                stream.sendall(b"ready")
                if recv_exact(stream, 5) == b"ready":
                    return
        except (OSError, EOFError, AssertionError):
            time.sleep(0.02)
    raise TimeoutError("authenticated DIRECT path did not become ready")


def read_socks5_reply(stream: socket.socket) -> None:
    head = recv_exact(stream, 4)
    if head[:2] != b"\x05\x00":
        raise AssertionError(f"SOCKS5 CONNECT failed: {head!r}")
    if head[3] == 1:
        length = 4
    elif head[3] == 4:
        length = 16
    elif head[3] == 3:
        length = recv_exact(stream, 1)[0]
    else:
        raise AssertionError(f"unexpected SOCKS5 reply address: {head!r}")
    recv_exact(stream, length + 2)


def socks5_authenticated(
    proxy_port: int, destination_port: int, username: bytes, password: bytes
) -> tuple[socket.socket, bytes, bytes]:
    stream = connect_proxy(proxy_port)
    stream.sendall(b"\x05\x01\x00")
    method = recv_exact(stream, 2)
    stream.sendall(
        b"\x01"
        + bytes([len(username)])
        + username
        + bytes([len(password)])
        + password
    )
    auth = recv_exact(stream, 2)
    if auth == b"\x01\x00":
        stream.sendall(
            b"\x05\x01\x00\x01"
            + socket.inet_aton("127.0.0.1")
            + destination_port.to_bytes(2, "big")
        )
        read_socks5_reply(stream)
    return stream, method, auth


def socks4_connect(
    proxy_port: int,
    destination_port: int,
    username: bytes,
    domain: bytes | None = None,
) -> tuple[socket.socket, bytes]:
    stream = connect_proxy(proxy_port)
    address = b"\x00\x00\x00\x01" if domain is not None else socket.inet_aton("127.0.0.1")
    request = (
        b"\x04\x01"
        + destination_port.to_bytes(2, "big")
        + address
        + username
        + b"\x00"
    )
    if domain is not None:
        request += domain + b"\x00"
    stream.sendall(request)
    return stream, recv_exact(stream, 8)


def exercise_direct(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    http_port, socks_port, mixed_port = reserve_port(), reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        (FIXTURES / "phase3a.yaml.tmpl")
        .read_text()
        .replace("${HTTP_PORT}", str(http_port))
        .replace("${SOCKS_PORT}", str(socks_port))
        .replace("${MIXED_PORT}", str(mixed_port))
    )
    process, stdout, stderr = launch(binary, config, scratch)
    observation: dict[str, Any] = {}
    try:
        for port in (http_port, socks_port, mixed_port):
            wait_ready(process, port)
        wait_authenticated_ready(process, http_port, echo.port)

        stream, response = http_request(http_port, echo.port, None)
        with stream:
            observation["http-missing-auth"] = {
                "status": status(response),
                "challenge": b"Proxy-Authenticate: Basic" in response,
            }

        stream, response = http_request(http_port, echo.port, "Bearer token")
        with stream:
            observation["http-wrong-scheme"] = status(response)

        wrong = base64.b64encode(b"alice:wrong").decode()
        stream, response = http_request(http_port, echo.port, f"Basic {wrong}")
        with stream:
            observation["http-wrong-password"] = status(response)

        good = base64.b64encode(b"alice:secret").decode()
        stream, response = http_request(http_port, echo.port, f"Basic {good}")
        with stream:
            if " 200 " not in status(response):
                raise AssertionError(response)
            stream.sendall(b"http-auth")
            observation["http-authenticated-fixed"] = recv_exact(stream, 9).decode()

        stream, method, auth = socks5_authenticated(
            socks_port, echo.port, b"alice", b"wrong"
        )
        with stream:
            observation["socks5-wrong-auth"] = {
                "method": method.hex(),
                "auth": auth.hex(),
                "closed": closed(stream),
            }

        stream, method, auth = socks5_authenticated(
            mixed_port, echo.port, b"alice", b"secret"
        )
        with stream:
            stream.sendall(b"socks5")
            observation["socks5-authenticated-mixed"] = {
                "method": method.hex(),
                "auth": auth.hex(),
                "echo": recv_exact(stream, 6).decode(),
            }

        stream, reply = socks4_connect(socks_port, echo.port, b"socks4")
        with stream:
            stream.sendall(b"socks4")
            observation["socks4-userid"] = {
                "reply": reply[1],
                "echo": recv_exact(stream, 6).decode(),
            }

        stream, reply = socks4_connect(
            mixed_port, echo.port, b"socks4", b"localhost"
        )
        with stream:
            stream.sendall(b"socks4a")
            observation["socks4a-domain"] = {
                "reply": reply[1],
                "echo": recv_exact(stream, 7).decode(),
            }

        stream, reply = socks4_connect(socks_port, echo.port, b"wrong")
        with stream:
            observation["socks4-wrong-user"] = {
                "reply": reply[1],
                "closed": closed(stream),
            }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()
    return observation


def exercise_reject(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    target_port = reserve_port()
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        (FIXTURES / "reject.yaml.tmpl")
        .read_text()
        .replace("${MIXED_PORT}", str(mixed_port))
    )
    process, stdout, stderr = launch(binary, config, scratch)
    observation: dict[str, Any] = {}
    try:
        wait_ready(process, mixed_port)
        stream, response = http_request(mixed_port, target_port, None)
        with stream:
            observation["http-reject"] = {
                "status": status(response),
                "closed": closed(stream),
            }

        stream = connect_proxy(mixed_port)
        with stream:
            stream.sendall(b"\x05\x01\x00")
            method = recv_exact(stream, 2)
            stream.sendall(
                b"\x05\x01\x00\x01"
                + socket.inet_aton("127.0.0.1")
                + target_port.to_bytes(2, "big")
            )
            read_socks5_reply(stream)
            observation["socks5-reject"] = {
                "method": method.hex(),
                "closed": closed(stream),
            }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
    return observation


def controller_request(
    port: int, path: str, *, authorized: bool = True
) -> tuple[int, dict[str, Any]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    headers = {"Authorization": "Bearer phase3-secret"} if authorized else {}
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    body = response.read()
    status_code = response.status
    connection.close()
    return status_code, json.loads(body)


def wait_controller(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during controller startup: {process.returncode}")
        try:
            status_code, _ = controller_request(port, "/version", authorized=False)
            if status_code == 401:
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("controller did not become ready")


def normalized_connection(snapshot: dict[str, Any], destination_port: int) -> dict[str, Any]:
    connections = snapshot["connections"]
    if len(connections) != 1:
        raise AssertionError(f"wanted one active connection: {snapshot}")
    connection = connections[0]
    metadata = connection["metadata"]
    return {
        "count": len(connections),
        "network": metadata["network"],
        "type": metadata["type"],
        "destinationIP": metadata["destinationIP"],
        "destinationPort": metadata["destinationPort"].replace(
            str(destination_port), "<ECHO_PORT>"
        ),
        "chains": connection["chains"],
        "providerChains": connection["providerChains"],
        "rule": connection["rule"],
        "rulePayload": connection["rulePayload"],
        "upload-is-int": isinstance(connection["upload"], int),
        "download-is-int": isinstance(connection["download"], int),
        "id-is-string": isinstance(connection["id"], str),
        "start-is-string": isinstance(connection["start"], str),
    }


def first_stream_json(
    port: int, path: str
) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse, dict[str, Any]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    connection.request(
        "GET", path, headers={"Authorization": "Bearer phase3-secret"}
    )
    response = connection.getresponse()
    if response.status != 200:
        raise AssertionError(f"stream status {response.status}")
    line = response.readline()
    return connection, response, json.loads(line)


def exercise_controller(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        (FIXTURES / "controller.yaml.tmpl")
        .read_text()
        .replace("${MIXED_PORT}", str(mixed_port))
        .replace("${CONTROLLER_PORT}", str(controller_port))
    )
    process, stdout, stderr = launch(binary, config, scratch)
    observation: dict[str, Any] = {}
    idle: socket.socket | None = None
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)

        unauthorized_status, unauthorized = controller_request(
            controller_port, "/version", authorized=False
        )
        observation["unauthorized"] = {
            "status": unauthorized_status,
            "message": unauthorized.get("message"),
        }

        version_status, version = controller_request(controller_port, "/version")
        observation["version"] = {
            "status": version_status,
            "meta": version.get("meta"),
            "version-is-string": isinstance(version.get("version"), str),
        }

        configs_status, configs = controller_request(controller_port, "/configs")
        observation["configs"] = {
            "status": configs_status,
            "port": configs.get("port"),
            "socks-port": configs.get("socks-port"),
            "mixed-port": "<MIXED_PORT>"
            if configs.get("mixed-port") == mixed_port
            else configs.get("mixed-port"),
            "mode": configs.get("mode"),
            "log-level": configs.get("log-level"),
            "ipv6": configs.get("ipv6"),
        }

        idle, response = http_request(mixed_port, echo.port, None)
        if " 200 " not in status(response):
            raise AssertionError(response)
        # The Go CONNECT listener acknowledges the tunnel before its worker
        # necessarily finishes routing and tracker registration. Force one
        # successful payload round-trip so the connection is observable before
        # polling the controller, independent of runner scheduling pressure.
        idle.sendall(b"ready")
        if recv_exact(idle, 5) != b"ready":
            raise AssertionError("controller readiness echo mismatch")
        deadline = time.monotonic() + IO_DEADLINE
        while True:
            _, snapshot = controller_request(controller_port, "/connections")
            if snapshot["connections"]:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("connection did not enter controller snapshot")
            time.sleep(0.02)
        observation["active-connection"] = normalized_connection(snapshot, echo.port)

        idle.sendall(b"counted")
        if recv_exact(idle, 7) != b"counted":
            raise AssertionError("echo mismatch")
        idle.close()
        idle = None
        deadline = time.monotonic() + IO_DEADLINE
        while True:
            _, after = controller_request(controller_port, "/connections")
            if after["connections"] is None and after["uploadTotal"] >= 7:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError(f"connection totals did not settle: {after}")
            time.sleep(0.02)
        observation["completed-totals"] = {
            "connections-is-null": after["connections"] is None,
            "upload-positive": after["uploadTotal"] >= 7,
            "download-positive": after["downloadTotal"] >= 7,
            "memory-is-int": isinstance(after["memory"], int),
        }

        traffic_connection, traffic_response, traffic = first_stream_json(
            controller_port, "/traffic"
        )
        observation["traffic"] = {
            "keys": sorted(traffic),
            "upTotal-positive": traffic["upTotal"] >= 7,
            "downTotal-positive": traffic["downTotal"] >= 7,
        }
        traffic_response.close()
        traffic_connection.close()

        invalid_status, invalid = controller_request(
            controller_port, "/logs?level=invalid"
        )
        observation["logs-invalid-level"] = {
            "status": invalid_status,
            "message": invalid.get("message"),
        }

        log_connection = http.client.HTTPConnection(
            "127.0.0.1", controller_port, timeout=IO_DEADLINE
        )
        log_connection.request(
            "GET",
            "/logs?level=info",
            headers={"Authorization": "Bearer phase3-secret"},
        )
        log_delivered = threading.Event()

        def trigger_log() -> None:
            while not log_delivered.wait(0.05):
                try:
                    probe, probe_response = http_request(mixed_port, echo.port, None)
                    with probe:
                        if " 200 " not in status(probe_response):
                            return
                except OSError:
                    return

        trigger = threading.Thread(target=trigger_log, daemon=True)
        trigger.start()
        log_response = log_connection.getresponse()
        event = json.loads(log_response.readline())
        log_delivered.set()
        trigger.join(timeout=IO_DEADLINE)
        observation["logs"] = {
            "status": log_response.status,
            "type": event.get("type"),
            "tcp-event": "[TCP]" in event.get("payload", ""),
        }
        log_response.close()
        log_connection.close()
    finally:
        if idle is not None:
            idle.close()
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()
    return observation


def write_reload_config(path: pathlib.Path, port: int, target: str) -> None:
    path.write_text(
        (FIXTURES / "reload.yaml.tmpl")
        .read_text()
        .replace("${MIXED_PORT}", str(port))
        .replace("${TARGET}", target)
    )


def route_behavior(port: int, destination_port: int) -> str:
    stream, response = http_request(port, destination_port, None)
    with stream:
        if " 200 " not in status(response):
            raise AssertionError(response)
        try:
            stream.sendall(b"route")
            return "direct" if recv_exact(stream, 5) == b"route" else "unexpected"
        except (EOFError, ConnectionResetError, BrokenPipeError):
            return "reject"


def wait_route(
    process: subprocess.Popen[bytes], port: int, destination_port: int, expected: str
) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during reload: {process.returncode}")
        try:
            if route_behavior(port, destination_port) == expected:
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError(f"port {port} did not switch to {expected}")


def wait_closed_port(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited while retiring listener: {process.returncode}")
        try:
            with connect_proxy(port):
                pass
        except OSError:
            return
        time.sleep(0.02)
    raise TimeoutError(f"retired listener {port} remained open")


def exercise_reload(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    first_port, second_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    write_reload_config(config, first_port, "DIRECT")
    process, stdout, stderr = launch(binary, config, scratch)
    observation: dict[str, Any] = {}
    try:
        wait_ready(process, first_port)
        wait_route(process, first_port, echo.port, "direct")
        observation["initial"] = "direct"

        write_reload_config(config, first_port, "REJECT")
        os.kill(process.pid, signal.SIGHUP)
        wait_route(process, first_port, echo.port, "reject")
        observation["same-port-rule"] = "reject"

        config.write_text("mixed-port: [")
        os.kill(process.pid, signal.SIGHUP)
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            if route_behavior(first_port, echo.port) != "reject":
                raise AssertionError("invalid reload changed active rules")
        observation["invalid-config-rollback"] = "reject"

        write_reload_config(config, second_port, "DIRECT")
        os.kill(process.pid, signal.SIGHUP)
        wait_route(process, second_port, echo.port, "direct")
        wait_closed_port(process, first_port)
        observation["port-move"] = {
            "new": "direct",
            "old": "closed",
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()
    return observation


def exercise_transactional_bind_rollback(
    binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    active_port, occupied_port = reserve_port(), reserve_port()
    blocker = socket.socket()
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker.bind(("127.0.0.1", occupied_port))
    blocker.listen()
    config = scratch / "config.yaml"
    write_reload_config(config, active_port, "DIRECT")
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, active_port)
        wait_route(process, active_port, echo.port, "direct")
        write_reload_config(config, occupied_port, "REJECT")
        os.kill(process.pid, signal.SIGHUP)
        deadline = time.monotonic() + IO_DEADLINE
        while time.monotonic() < deadline:
            text = (scratch / "stderr.log").read_text(errors="replace")
            if "configuration reload failed" in text:
                break
            time.sleep(0.02)
        else:
            raise TimeoutError("Rust runtime did not report failed transactional bind")
        return {
            "old-generation": route_behavior(active_port, echo.port),
            "occupied-port-preserved": blocker.getsockname()[1] == occupied_port,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        blocker.close()
        echo.close()


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, stream = self.request
        stream.sendto(data, self.client_address)


def socks_udp_packet(destination_port: int, payload: bytes, *, fragment: int = 0) -> bytes:
    return (
        b"\x00\x00"
        + bytes([fragment, 1])
        + socket.inet_aton("127.0.0.1")
        + destination_port.to_bytes(2, "big")
        + payload
    )


def decode_socks_udp(packet: bytes) -> tuple[str, int, bytes]:
    if len(packet) < 10 or packet[:4] != b"\x00\x00\x00\x01":
        raise AssertionError(f"unexpected SOCKS UDP response: {packet!r}")
    address = socket.inet_ntoa(packet[4:8])
    port = int.from_bytes(packet[8:10], "big")
    return address, port, packet[10:]


def udp_round_trip(proxy_port: int, destination_port: int, payload: bytes) -> tuple[str, int, bytes]:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(IO_DEADLINE)
    try:
        client.sendto(
            socks_udp_packet(destination_port, payload),
            ("127.0.0.1", proxy_port),
        )
        packet, _ = client.recvfrom(65_535)
        return decode_socks_udp(packet)
    finally:
        client.close()


def wait_udp_route(
    process: subprocess.Popen[bytes], proxy_port: int, destination_port: int
) -> None:
    # The Go oracle initializes its UDP workers on the first datagram. Give a
    # timed-out cold attempt room to retry without weakening per-I/O deadlines.
    deadline = time.monotonic() + (2 * IO_DEADLINE) + 1
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during UDP startup: {process.returncode}")
        try:
            _, _, payload = udp_round_trip(proxy_port, destination_port, b"ready")
            if payload == b"ready":
                return
        except (OSError, AssertionError):
            time.sleep(0.02)
    raise TimeoutError("SOCKS UDP path did not become ready")


def udp_associate(proxy_port: int) -> tuple[socket.socket, str, int]:
    stream = connect_proxy(proxy_port)
    stream.sendall(b"\x05\x01\x00")
    if recv_exact(stream, 2) != b"\x05\x00":
        raise AssertionError("UDP associate method negotiation failed")
    stream.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    head = recv_exact(stream, 4)
    if head != b"\x05\x00\x00\x01":
        raise AssertionError(f"UDP associate reply failed: {head!r}")
    address = socket.inet_ntoa(recv_exact(stream, 4))
    port = int.from_bytes(recv_exact(stream, 2), "big")
    return stream, address, port


def exercise_udp(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
    echo_thread.start()
    echo_port = int(echo.server_address[1])
    socks_port, mixed_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        (FIXTURES / "udp.yaml.tmpl")
        .read_text()
        .replace("${SOCKS_PORT}", str(socks_port))
        .replace("${MIXED_PORT}", str(mixed_port))
    )
    process, stdout, stderr = launch(binary, config, scratch)
    observation: dict[str, Any] = {}
    association: socket.socket | None = None
    try:
        wait_ready(process, socks_port)
        wait_ready(process, mixed_port)
        wait_udp_route(process, mixed_port, echo_port)

        association, bound_address, bound_port = udp_associate(mixed_port)
        observation["associate"] = {
            "address": bound_address,
            "port-is-listener": bound_port == mixed_port,
            "control-open": association.fileno() >= 0,
        }

        address, source_port, payload = udp_round_trip(
            mixed_port, echo_port, b"mixed-udp"
        )
        observation["mixed-write-back"] = {
            "address": address,
            "source-port-is-echo": source_port == echo_port,
            "payload": payload.decode(),
        }
        address, source_port, payload = udp_round_trip(
            socks_port, echo_port, b"socks-udp"
        )
        observation["fixed-socks-write-back"] = {
            "address": address,
            "source-port-is-echo": source_port == echo_port,
            "payload": payload.decode(),
        }

        fragmented = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fragmented.settimeout(0.3)
        try:
            fragmented.sendto(
                socks_udp_packet(echo_port, b"drop", fragment=1),
                ("127.0.0.1", mixed_port),
            )
            try:
                fragmented.recvfrom(1024)
                dropped = False
            except TimeoutError:
                dropped = True
        finally:
            fragmented.close()
        observation["fragment"] = "dropped" if dropped else "responded"
    finally:
        if association is not None:
            association.close()
        stop(process)
        stdout.close()
        stderr.close()
        echo.shutdown()
        echo.server_close()
        echo_thread.join(timeout=IO_DEADLINE)
    return observation


def debug_files(root: pathlib.Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): path.read_text(errors="replace")
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.suffix in {".yaml", ".log"}
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="phase3-compat-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations: dict[str, Any] = {}
        try:
            for name, binary in binaries.items():
                direct = root / name / "direct"
                reject = root / name / "reject"
                controller = root / name / "controller"
                reload = root / name / "reload"
                udp = root / name / "udp"
                direct.mkdir(parents=True)
                reject.mkdir()
                controller.mkdir()
                reload.mkdir()
                udp.mkdir()
                observations[name] = {
                    "direct": exercise_direct(binary, direct),
                    "reject": exercise_reject(binary, reject),
                    "controller": exercise_controller(binary, controller),
                    "reload": exercise_reload(binary, reload),
                    "udp": exercise_udp(binary, udp),
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
            print(f"Phase 3 differential mismatch: {FAILURE_ARTIFACT}")
            return 1

        rust_contract_root = root / "rust" / "transactional-rollback"
        rust_contract_root.mkdir()
        rust_contract = exercise_transactional_bind_rollback(
            binaries["rust"], rust_contract_root
        )
        if rust_contract != {
            "old-generation": "direct",
            "occupied-port-preserved": True,
        }:
            raise AssertionError(f"transactional rollback failed: {rust_contract}")

    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 3 Go/Rust differential suite passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    print("Rust-only transactional bind rollback contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

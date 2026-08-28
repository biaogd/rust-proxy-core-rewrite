#!/usr/bin/env python3
"""Aggregate Go/Rust differential for controller observability streams."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import pathlib
import re
import socket
import tempfile
import threading
import time
from typing import Any

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    connect_proxy,
    recv_exact,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import http_request, launch, status, stop
from phase5b1a import build_binaries, debug_files


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5d-streams-diff.json"
SECRET = "phase5d-streams-secret"


def wait_controller(process: Any, port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"controller exited during readiness: {process.returncode}")
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
            connection.request(
                "GET", "/version", headers={"Authorization": f"Bearer {SECRET}"}
            )
            response = connection.getresponse()
            if response.status == 200:
                response.read()
                connection.close()
                return
            connection.close()
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("controller did not become ready")


def websocket_open(
    port: int, path: str, *, authorization: bool = False
) -> tuple[socket.socket, int, dict[str, str]]:
    stream = connect_proxy(port)
    nonce = b"phase5d-ws-key!!"
    key = base64.b64encode(nonce).decode()
    auth = f"Authorization: Bearer {SECRET}\r\n" if authorization else ""
    stream.sendall(
        (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"{auth}\r\n"
        ).encode()
    )
    head_buffer = bytearray()
    while not head_buffer.endswith(b"\r\n\r\n"):
        byte = stream.recv(1)
        if not byte:
            raise EOFError("websocket response closed before headers")
        head_buffer.extend(byte)
    head = bytes(head_buffer)
    lines = head.decode("iso-8859-1").split("\r\n")
    code = int(lines[0].split()[1])
    headers = {
        name.lower(): value.strip()
        for line in lines[1:]
        if ":" in line
        for name, value in [line.split(":", 1)]
    }
    if code == 101:
        expected = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
        ).decode()
        if headers.get("sec-websocket-accept") != expected:
            stream.close()
            raise AssertionError(f"invalid websocket accept: {headers}")
    return stream, code, headers


def websocket_json(stream: socket.socket) -> dict[str, Any]:
    first, second = recv_exact(stream, 2)
    if first & 0x0F != 1:
        raise AssertionError(f"expected text frame, opcode={first & 0x0F}")
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(recv_exact(stream, 2), "big")
    elif length == 127:
        length = int.from_bytes(recv_exact(stream, 8), "big")
    mask = recv_exact(stream, 4) if masked else b""
    payload = bytearray(recv_exact(stream, length))
    if masked:
        for index in range(length):
            payload[index] ^= mask[index % 4]
    return json.loads(payload)


def http_stream_json(port: int, path: str) -> tuple[int, list[dict[str, Any]], float]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    connection.request(
        "GET", path, headers={"Authorization": f"Bearer {SECRET}"}
    )
    response = connection.getresponse()
    try:
        first = json.loads(response.readline())
        started = time.monotonic()
        second = json.loads(response.readline())
        return response.status, [first, second], time.monotonic() - started
    finally:
        response.close()
        connection.close()


def trigger_tcp_log(mixed_port: int, echo_port: int, delivered: threading.Event) -> None:
    while not delivered.wait(0.05):
        try:
            stream, response = http_request(mixed_port, echo_port, None)
            with stream:
                if " 200 " in status(response):
                    stream.sendall(b"controller-stream-log")
                    recv_exact(stream, 21)
        except (OSError, EOFError):
            return


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    streams: list[socket.socket] = []
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)

        rejected, rejected_status, rejected_headers = websocket_open(
            controller_port, "/traffic?token=wrong"
        )
        streams.append(rejected)

        memory_status, memory_http, memory_cadence = http_stream_json(controller_port, "/memory")

        traffic, traffic_status, traffic_headers = websocket_open(
            controller_port, f"/traffic?token={SECRET}"
        )
        streams.append(traffic)
        traffic_frame = websocket_json(traffic)
        traffic_started = time.monotonic()
        traffic_second = websocket_json(traffic)
        traffic_cadence = time.monotonic() - traffic_started
        traffic.close()
        streams.remove(traffic)

        memory, memory_ws_status, memory_headers = websocket_open(
            controller_port, f"/memory?token={SECRET}"
        )
        streams.append(memory)
        memory_frame = websocket_json(memory)
        memory_second = websocket_json(memory)
        memory.close()
        streams.remove(memory)

        connections, connections_status, connections_headers = websocket_open(
            controller_port, f"/connections?interval=25&token={SECRET}"
        )
        streams.append(connections)
        connection_frame = websocket_json(connections)
        connections.close()
        streams.remove(connections)

        bearer, bearer_status, bearer_headers = websocket_open(
            controller_port, "/connections", authorization=True
        )
        streams.append(bearer)
        bearer_frame = websocket_json(bearer)

        logs, logs_status, logs_headers = websocket_open(
            controller_port, f"/logs?level=info&token={SECRET}"
        )
        streams.append(logs)
        delivered = threading.Event()
        trigger = threading.Thread(
            target=trigger_tcp_log,
            args=(mixed_port, echo.port, delivered),
            daemon=True,
        )
        trigger.start()
        log_frame = websocket_json(logs)
        delivered.set()
        trigger.join(timeout=IO_DEADLINE)

        structured, structured_status, structured_headers = websocket_open(
            controller_port, f"/logs?level=info&format=structured&token={SECRET}"
        )
        streams.append(structured)
        structured_delivered = threading.Event()
        structured_trigger = threading.Thread(
            target=trigger_tcp_log,
            args=(mixed_port, echo.port, structured_delivered),
            daemon=True,
        )
        structured_trigger.start()
        structured_frame = websocket_json(structured)
        structured_delivered.set()
        structured_trigger.join(timeout=IO_DEADLINE)

        return {
            "invalid-query-token": {
                "status": rejected_status,
                "content-type-json": rejected_headers.get("content-type", "").startswith(
                    "application/json"
                ),
            },
            "memory-http": {
                "status": memory_status,
                "keys": sorted(memory_http[0]),
                "first-zero": memory_http[0] == {"inuse": 0, "oslimit": 0},
                "second-rss-positive": memory_http[1]["inuse"] > 0,
                "second-oslimit-zero": memory_http[1]["oslimit"] == 0,
                "cadence-bounded": 0.5 <= memory_cadence <= 1.8,
            },
            "traffic-websocket": {
                "status": traffic_status,
                "upgrade": traffic_headers.get("upgrade", "").lower(),
                "keys": sorted(traffic_frame),
                "second-keys": sorted(traffic_second),
                "totals-monotonic": traffic_second["upTotal"] >= traffic_frame["upTotal"]
                and traffic_second["downTotal"] >= traffic_frame["downTotal"],
                "cadence-bounded": 0.5 <= traffic_cadence <= 1.8,
            },
            "memory-websocket": {
                "status": memory_ws_status,
                "upgrade": memory_headers.get("upgrade", "").lower(),
                "keys": sorted(memory_frame),
                "first-zero": memory_frame == {"inuse": 0, "oslimit": 0},
                "second-rss-positive": memory_second["inuse"] > 0,
                "second-oslimit-zero": memory_second["oslimit"] == 0,
            },
            "connections-websocket": {
                "status": connections_status,
                "upgrade": connections_headers.get("upgrade", "").lower(),
                "keys": sorted(connection_frame),
                "connections-null-or-list": connection_frame.get("connections") is None
                or isinstance(connection_frame.get("connections"), list),
            },
            "bearer-websocket": {
                "status": bearer_status,
                "upgrade": bearer_headers.get("upgrade", "").lower(),
                "keys": sorted(bearer_frame),
            },
            "logs-websocket": {
                "status": logs_status,
                "upgrade": logs_headers.get("upgrade", "").lower(),
                "keys": sorted(log_frame),
                "type": log_frame.get("type"),
                "tcp-event": "[TCP]" in log_frame.get("payload", ""),
            },
            "logs-structured-websocket": {
                "status": structured_status,
                "upgrade": structured_headers.get("upgrade", "").lower(),
                "keys": sorted(structured_frame),
                "level": structured_frame.get("level"),
                "time-shape": bool(re.fullmatch(r"\d\d:\d\d:\d\d", structured_frame.get("time", ""))),
                "empty-fields": structured_frame.get("fields") == [],
                "tcp-event": "[TCP]" in structured_frame.get("message", ""),
            },
        }
    finally:
        for stream in streams:
            stream.close()
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-streams-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5DSTREAMS_CARGO_TARGET", "phase5d-streams")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
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
            json.dumps({"observations": observations}, indent=2, sort_keys=True)
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5D aggregate controller stream differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

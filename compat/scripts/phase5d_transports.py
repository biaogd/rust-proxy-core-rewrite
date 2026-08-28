#!/usr/bin/env python3
"""Controller TCP/TLS/Unix/UI/debug differential for the Phase 5D gate."""

from __future__ import annotations

import http.client
import json
import os
import pathlib
import shutil
import signal
import socket
import ssl
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5d_streams import SECRET, wait_controller


ROOT_CERT = ROOT / "compat/fixtures/phase4/phase4e2-root.pem"
SERVER_CERT = ROOT / "compat/fixtures/phase4/phase4e2-server.pem"
SERVER_KEY = ROOT / "compat/fixtures/phase4/phase4e2-server-key.pem"
FAILURE_ARTIFACT = ROOT / "compat/artifacts/phase5d-transports-diff.json"


def parse_http(payload: bytes) -> tuple[int, dict[str, str], bytes]:
    head, body = payload.split(b"\r\n\r\n", 1)
    lines = head.decode("latin1").split("\r\n")
    headers = {
        key.lower(): value.strip()
        for key, value in (line.split(":", 1) for line in lines[1:] if ":" in line)
    }
    length = int(headers.get("content-length", len(body)))
    return int(lines[0].split()[1]), headers, body[:length]


def stream_request(stream: socket.socket, request: bytes) -> tuple[int, dict[str, str], bytes]:
    stream.settimeout(IO_DEADLINE)
    stream.sendall(request)
    chunks: list[bytes] = []
    while True:
        chunk = stream.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
        payload = b"".join(chunks)
        if b"\r\n\r\n" in payload:
            head, body = payload.split(b"\r\n\r\n", 1)
            for line in head.decode("latin1").split("\r\n")[1:]:
                if line.lower().startswith("content-length:"):
                    if len(body) >= int(line.split(":", 1)[1]):
                        return parse_http(payload)
    return parse_http(b"".join(chunks))


def tcp_request(port: int, method: str, path: str, auth: bool) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    headers = {"Authorization": f"Bearer {SECRET}"} if auth else {}
    connection.request(method, path, headers=headers)
    response = connection.getresponse()
    try:
        return response.status, {key.lower(): value for key, value in response.getheaders()}, response.read()
    finally:
        response.close()
        connection.close()


def wait_unix(path: pathlib.Path) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise TimeoutError(f"Unix controller was not created: {path}")


def wait_tcp_closed(port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                pass
        except OSError:
            return
        time.sleep(0.02)
    raise TimeoutError(f"old controller remained open: {port}")


def summarize(result: tuple[int, dict[str, str], bytes]) -> dict[str, Any]:
    status, headers, body = result
    return {
        "status": status,
        "content-type": headers.get("content-type"),
        "location": headers.get("location"),
        "body": body.decode(errors="replace"),
    }


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    mixed_port, tcp_port, tls_port = reserve_port(), reserve_port(), reserve_port()
    profile = scratch / ".config/mihomo"
    ui = profile / "ui"
    ui.mkdir(parents=True)
    (ui / "index.html").write_text("phase5d-ui-index\n")
    (ui / "asset.txt").write_text("phase5d-ui-asset\n")
    certificate = profile / "server.pem"
    private_key = profile / "server-key.pem"
    shutil.copyfile(SERVER_CERT, certificate)
    shutil.copyfile(SERVER_KEY, private_key)
    unix_path = scratch / "c.sock"
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{tcp_port}
external-controller-tls: 127.0.0.1:{tls_port}
external-controller-unix: {unix_path}
external-ui: {ui}
secret: {SECRET}
mode: rule
log-level: debug
ipv6: false
tls:
  certificate: {certificate}
  private-key: {private_key}
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, tcp_port)
        wait_unix(unix_path)

        tls_context = ssl.create_default_context(cafile=str(ROOT_CERT))
        with socket.create_connection(("127.0.0.1", tls_port), timeout=IO_DEADLINE) as raw:
            with tls_context.wrap_socket(raw, server_hostname="dot.phase4.test") as tls:
                tls_result = stream_request(
                    tls,
                    (
                        b"GET / HTTP/1.1\r\nHost: controller\r\n"
                        + f"Authorization: Bearer {SECRET}\r\n".encode()
                        + b"Connection: close\r\n\r\n"
                    ),
                )

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unix:
            unix.connect(str(unix_path))
            unix_result = stream_request(
                unix,
                b"GET / HTTP/1.1\r\nHost: controller\r\nConnection: close\r\n\r\n",
            )

        observations = {
            "tcp-auth": summarize(tcp_request(tcp_port, "GET", "/", True)),
            "tcp-no-auth": summarize(tcp_request(tcp_port, "GET", "/", False)),
            "tls-auth": summarize(tls_result),
            "unix-no-auth": summarize(unix_result),
            "ui-redirect": summarize(tcp_request(tcp_port, "GET", "/ui", False)),
            "ui-index": summarize(tcp_request(tcp_port, "GET", "/ui/", False)),
            "ui-asset": summarize(tcp_request(tcp_port, "GET", "/ui/asset.txt", False)),
            "debug-gc": summarize(tcp_request(tcp_port, "PUT", "/debug/gc", False)),
            "unix-mode": oct(unix_path.stat().st_mode & 0o777),
        }
        replacement_tcp, replacement_tls = reserve_port(), reserve_port()
        replacement_unix = scratch / "n.sock"
        replacement_ui = profile / "ui-next"
        replacement_ui.mkdir()
        (replacement_ui / "index.html").write_text("phase5d-ui-next\n")
        replacement = (
            config.read_text()
            .replace(f"127.0.0.1:{tcp_port}", f"127.0.0.1:{replacement_tcp}")
            .replace(f"127.0.0.1:{tls_port}", f"127.0.0.1:{replacement_tls}")
            .replace(str(unix_path), str(replacement_unix))
            .replace(f"external-ui: {ui}", f"external-ui: {replacement_ui}")
        )
        config.write_text(replacement)
        os.killpg(process.pid, signal.SIGHUP)
        wait_controller(process, replacement_tcp)
        wait_unix(replacement_unix)
        wait_tcp_closed(tcp_port)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unix:
            unix.connect(str(replacement_unix))
            replaced_unix = stream_request(
                unix,
                b"GET / HTTP/1.1\r\nHost: controller\r\nConnection: close\r\n\r\n",
            )
        observations["replacement"] = {
            "new-tcp": summarize(tcp_request(replacement_tcp, "GET", "/", True)),
            "new-unix": summarize(replaced_unix),
            "new-ui": summarize(tcp_request(replacement_tcp, "GET", "/ui/", False)),
            "old-tcp-closed": True,
            "old-unix-removed": not unix_path.exists(),
        }
        return observations
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def main() -> int:
    if os.name == "nt":
        print("Phase 5D POSIX controller transport differential skipped on Windows")
        return 0
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-transports-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5DTRANSPORT_CARGO_TARGET", "phase5d-transports")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
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
        FAILURE_ARTIFACT.write_text(json.dumps({"observations": observations}, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5D controller transport/UI/debug differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

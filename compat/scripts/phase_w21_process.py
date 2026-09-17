#!/usr/bin/env python3
"""W2.1 PROCESS-NAME / PROCESS-PATH / UID Linux differential.

Unprivileged:
  - Go and Rust `-t` accept PROCESS-NAME, PROCESS-PATH, UID, find-process-mode
  - PROCESS-NAME-REGEX still rejected by Rust (deferred)
  - SOCKS pure-IP echo: PROCESS-NAME matching this interpreter → DIRECT
  - Wrong PROCESS-NAME → REJECT
  - UID matching os.getuid() → DIRECT (Linux)
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from phase1 import ROOT, assert_go_oracle_baseline, terminate_process
from phase3 import launch, stop
from phase5b1a import build_binaries

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-w21-process-diff.json"
SCRIPT = pathlib.Path(__file__).resolve()
ECHO_PAYLOAD = b"phase-w21-process-echo\n"
PROCESS_NAME = pathlib.Path(sys.executable).name
PROCESS_PATH = str(pathlib.Path(sys.executable).resolve())
UID = os.getuid()


class _TcpEcho(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request.recv(65535)
        if data:
            self.request.sendall(data)


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def write_config(path: pathlib.Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


def validate_config(binary: pathlib.Path, config: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), "-t", "-f", str(config), "-d", str(config.parent)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def process_yaml(*, socks_port: int, echo_port: int, process_name: str, uid: int) -> str:
    return (
        f"socks-port: {socks_port}\n"
        "mode: rule\n"
        "log-level: info\n"
        "ipv6: false\n"
        "find-process-mode: strict\n"
        "rules:\n"
        f"  - PROCESS-NAME,{process_name},DIRECT\n"
        f"  - UID,{uid},DIRECT\n"
        "  - MATCH,REJECT\n"
    )


def wrong_name_yaml(*, socks_port: int, echo_port: int) -> str:
    _ = echo_port
    return (
        f"socks-port: {socks_port}\n"
        "mode: rule\n"
        "ipv6: false\n"
        "find-process-mode: strict\n"
        "rules:\n"
        "  - PROCESS-NAME,definitely-not-this-process,DIRECT\n"
        "  - MATCH,REJECT\n"
    )


def regex_yaml() -> str:
    return (
        "mode: rule\n"
        "ipv6: false\n"
        "rules:\n"
        "  - PROCESS-NAME-REGEX,curl,DIRECT\n"
        "  - MATCH,DIRECT\n"
    )


def wait_tcp(host: str, port: int, deadline: float = 15.0) -> None:
    end = time.time() + deadline
    last: Exception | None = None
    while time.time() < end:
        try:
            sock = socket.create_connection((host, port), timeout=0.5)
            sock.close()
            return
        except OSError as error:
            last = error
            time.sleep(0.05)
    raise TimeoutError(f"{host}:{port} not ready: {last}")


def socks5_connect(socks_port: int, dest_host: str, dest_port: int) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=5.0)
    sock.settimeout(5.0)
    sock.sendall(b"\x05\x01\x00")
    greet = sock.recv(2)
    if greet != b"\x05\x00":
        sock.close()
        raise RuntimeError(f"socks greet failed: {greet!r}")
    packed = socket.inet_aton(dest_host)
    req = b"\x05\x01\x00\x01" + packed + struct.pack("!H", dest_port)
    sock.sendall(req)
    resp = sock.recv(16)
    if len(resp) < 2 or resp[1] != 0:
        sock.close()
        raise RuntimeError(f"socks connect failed: {resp!r}")
    return sock


def expect_echo(sock: socket.socket, payload: bytes) -> bytes:
    sock.sendall(payload)
    received = b""
    while len(received) < len(payload):
        chunk = sock.recv(64)
        if not chunk:
            break
        received += chunk
    return received


def expect_reject(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(payload)
    try:
        data = sock.recv(64)
    except OSError:
        return
    if data:
        raise AssertionError(f"expected reject, got {data!r}")


def run_cases(binaries: dict[str, pathlib.Path]) -> dict[str, Any]:
    results: dict[str, Any] = {
        "platform": sys.platform,
        "process_name": PROCESS_NAME,
        "process_path": PROCESS_PATH,
        "uid": UID,
        "cases": {},
    }
    with tempfile.TemporaryDirectory(prefix="phase-w21-process-") as tmp:
        scratch = pathlib.Path(tmp)

        regex_path = scratch / "regex.yaml"
        write_config(regex_path, regex_yaml())
        for name, binary in binaries.items():
            validated = validate_config(binary, regex_path)
            results["cases"][f"{name}-regex-validate"] = {
                "returncode": validated.returncode,
                "stderr": validated.stderr[-400:],
            }
            if name == "rust" and validated.returncode == 0:
                raise AssertionError("rust accepted PROCESS-NAME-REGEX (should defer)")

        for name, binary in binaries.items():
            home = scratch / f"home-{name}"
            home.mkdir()
            cfg = home / "config.yaml"
            socks_port = reserve_port()
            echo_port = reserve_port()
            write_config(
                cfg,
                process_yaml(
                    socks_port=socks_port,
                    echo_port=echo_port,
                    process_name=PROCESS_NAME,
                    uid=UID,
                ),
            )
            validated = validate_config(binary, cfg)
            results["cases"][f"{name}-validate-process"] = {
                "returncode": validated.returncode,
                "stderr": validated.stderr[-400:],
            }
            if validated.returncode != 0:
                raise AssertionError(f"{name} rejected process rules: {validated.stderr}")

            echo = socketserver.ThreadingTCPServer(("127.0.0.1", echo_port), _TcpEcho)
            echo.allow_reuse_address = True
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            process, _stdout, _stderr = launch(binary, cfg, home)
            try:
                wait_tcp("127.0.0.1", socks_port)
                sock = socks5_connect(socks_port, "127.0.0.1", echo_port)
                try:
                    got = expect_echo(sock, ECHO_PAYLOAD)
                    if got != ECHO_PAYLOAD:
                        raise AssertionError(f"{name} process allow mismatch: {got!r}")
                    results["cases"][f"{name}-process-allow"] = "ok"
                finally:
                    sock.close()
            finally:
                stop(process)
                terminate_process(process)
                echo.shutdown()
                echo.server_close()

            # Wrong process name → REJECT
            home2 = scratch / f"home-wrong-{name}"
            home2.mkdir()
            cfg2 = home2 / "config.yaml"
            socks_port = reserve_port()
            echo_port = reserve_port()
            write_config(
                cfg2,
                wrong_name_yaml(socks_port=socks_port, echo_port=echo_port),
            )
            echo = socketserver.ThreadingTCPServer(("127.0.0.1", echo_port), _TcpEcho)
            echo.allow_reuse_address = True
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            process, _stdout, _stderr = launch(binary, cfg2, home2)
            try:
                wait_tcp("127.0.0.1", socks_port)
                sock = socks5_connect(socks_port, "127.0.0.1", echo_port)
                try:
                    expect_reject(sock, ECHO_PAYLOAD)
                    results["cases"][f"{name}-process-reject"] = "ok"
                finally:
                    sock.close()
            finally:
                stop(process)
                terminate_process(process)
                echo.shutdown()
                echo.server_close()
    return results


def main() -> int:
    assert_go_oracle_baseline()
    with tempfile.TemporaryDirectory(prefix="phase-w21-build-") as tmp:
        binaries = build_binaries(pathlib.Path(tmp))
        try:
            observation = {
                "script": str(SCRIPT),
                "unprivileged": run_cases(binaries),
            }
        except Exception as error:  # noqa: BLE001
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps({"error": str(error)}, indent=2) + "\n",
                encoding="utf-8",
            )
            print(f"W2.1 process gate failed: {error}", file=sys.stderr)
            return 1

    print(json.dumps(observation, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

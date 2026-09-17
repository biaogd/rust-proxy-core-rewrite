#!/usr/bin/env python3
"""W2.2 sniffer config + TLS SNI / HTTP Host TCP differential.

Unprivileged:
  - Go and Rust `-t` accept `sniffer:` HTTP/TLS (and QUIC config keys)
  - Unknown sniff protocol is rejected
  - SOCKS → pure-IP target: TLS ClientHello SNI matching DOMAIN-SUFFIX,REJECT
    is refused by both; a non-matching SNI still echoes via MATCH,DIRECT
  - SOCKS → pure-IP target: HTTP Host matching DOMAIN-SUFFIX,REJECT is refused;
    a non-matching Host still echoes
"""

from __future__ import annotations

import json
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

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-w22-sniffer-diff.json"
SCRIPT = pathlib.Path(__file__).resolve()
ECHO_PAYLOAD = b"phase-w22-sniffer-echo\n"


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


def sniffer_yaml(*, socks_port: int, tls_port: int, http_port: int) -> str:
    return (
        f"socks-port: {socks_port}\n"
        "mode: rule\n"
        "log-level: info\n"
        "ipv6: false\n"
        "sniffer:\n"
        "  enable: true\n"
        "  parse-pure-ip: true\n"
        "  force-dns-mapping: true\n"
        "  override-destination: false\n"
        "  sniff:\n"
        "    TLS:\n"
        f"      ports: [{tls_port}]\n"
        "    HTTP:\n"
        f"      ports: [{http_port}]\n"
        "    QUIC:\n"
        "rules:\n"
        "  - DOMAIN-SUFFIX,blocked.sniff.test,REJECT\n"
        "  - MATCH,DIRECT\n"
    )


def bad_sniffer_yaml() -> str:
    return (
        "mode: rule\n"
        "ipv6: false\n"
        "sniffer:\n"
        "  enable: true\n"
        "  sniff:\n"
        "    FTP:\n"
        "rules:\n"
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
    host_bytes = dest_host.encode("ascii")
    req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", dest_port)
    # Use IPv4 form for pure-IP destinations so metadata.host stays empty.
    try:
        packed = socket.inet_aton(dest_host)
        req = b"\x05\x01\x00\x01" + packed + struct.pack("!H", dest_port)
    except OSError:
        pass
    sock.sendall(req)
    resp = sock.recv(16)
    if len(resp) < 2 or resp[1] != 0:
        sock.close()
        raise RuntimeError(f"socks connect failed: {resp!r}")
    return sock


def tls_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode("ascii")
    server_name = struct.pack("!H", len(sni_bytes) + 3) + b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    extensions = struct.pack("!HH", 0, len(server_name)) + server_name
    body = bytearray()
    body.extend(b"\x03\x03")
    body.extend(b"\x00" * 32)
    body.append(0)  # session id
    body.extend(struct.pack("!H", 2))
    body.extend(struct.pack("!H", 0x1301))
    body.append(1)
    body.append(0)
    body.extend(struct.pack("!H", len(extensions)))
    body.extend(extensions)
    handshake = bytes([0x01]) + struct.pack("!I", len(body))[1:] + body
    return bytes([0x16, 0x03, 0x01]) + struct.pack("!H", len(handshake)) + handshake


def expect_reject_after_payload(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(payload)
    try:
        data = sock.recv(64)
    except OSError:
        return
    if data:
        raise AssertionError(f"expected reject, got payload echo {data!r}")


def expect_echo(sock: socket.socket, payload: bytes) -> bytes:
    sock.sendall(payload)
    received = b""
    while len(received) < len(payload):
        chunk = sock.recv(64)
        if not chunk:
            break
        received += chunk
    return received


def run_cases(binaries: dict[str, pathlib.Path]) -> dict[str, Any]:
    results: dict[str, Any] = {"platform": sys.platform, "cases": {}}
    with tempfile.TemporaryDirectory(prefix="phase-w22-sniffer-") as tmp:
        scratch = pathlib.Path(tmp)

        bad_path = scratch / "bad-sniffer.yaml"
        write_config(bad_path, bad_sniffer_yaml())
        for name, binary in binaries.items():
            validated = validate_config(binary, bad_path)
            results["cases"][f"{name}-reject-unknown-protocol"] = {
                "returncode": validated.returncode,
                "stderr": validated.stderr[-400:],
            }
            if validated.returncode == 0:
                raise AssertionError(f"{name} accepted unknown sniffer protocol")

        for name, binary in binaries.items():
            home = scratch / f"home-{name}"
            home.mkdir()
            cfg = home / "config.yaml"
            socks_port = reserve_port()
            tls_port = reserve_port()
            http_port = reserve_port()
            write_config(
                cfg,
                sniffer_yaml(socks_port=socks_port, tls_port=tls_port, http_port=http_port),
            )
            validated = validate_config(binary, cfg)
            results["cases"][f"{name}-validate-sniffer"] = {
                "returncode": validated.returncode,
                "stderr": validated.stderr[-400:],
            }
            if validated.returncode != 0:
                raise AssertionError(f"{name} rejected sniffer: {validated.stderr}")

            tls_echo = socketserver.ThreadingTCPServer(("127.0.0.1", tls_port), _TcpEcho)
            tls_echo.allow_reuse_address = True
            threading.Thread(target=tls_echo.serve_forever, daemon=True).start()
            http_echo = socketserver.ThreadingTCPServer(("127.0.0.1", http_port), _TcpEcho)
            http_echo.allow_reuse_address = True
            threading.Thread(target=http_echo.serve_forever, daemon=True).start()

            process, _stdout, _stderr = launch(binary, cfg, home)
            try:
                wait_tcp("127.0.0.1", socks_port)

                # TLS SNI blocked
                sock = socks5_connect(socks_port, "127.0.0.1", tls_port)
                try:
                    expect_reject_after_payload(sock, tls_client_hello("app.blocked.sniff.test"))
                    results["cases"][f"{name}-tls-sni-reject"] = "ok"
                finally:
                    sock.close()

                # Non-TLS payload: sniff fails, pure-IP DIRECT still echoes.
                sock = socks5_connect(socks_port, "127.0.0.1", tls_port)
                try:
                    got = expect_echo(sock, ECHO_PAYLOAD)
                    if got != ECHO_PAYLOAD:
                        raise AssertionError(f"{name} tls-port allow mismatch: {got!r}")
                    results["cases"][f"{name}-tls-port-allow"] = "ok"
                finally:
                    sock.close()

                blocked_http = (
                    b"GET / HTTP/1.1\r\nHost: app.blocked.sniff.test\r\n\r\n"
                )
                sock = socks5_connect(socks_port, "127.0.0.1", http_port)
                try:
                    expect_reject_after_payload(sock, blocked_http)
                    results["cases"][f"{name}-http-host-reject"] = "ok"
                finally:
                    sock.close()

                sock = socks5_connect(socks_port, "127.0.0.1", http_port)
                try:
                    got = expect_echo(sock, ECHO_PAYLOAD)
                    if got != ECHO_PAYLOAD:
                        raise AssertionError(f"{name} http-port allow mismatch: {got!r}")
                    results["cases"][f"{name}-http-port-allow"] = "ok"
                finally:
                    sock.close()
            finally:
                stop(process)
                terminate_process(process)
                tls_echo.shutdown()
                http_echo.shutdown()
                tls_echo.server_close()
                http_echo.server_close()
    return results


def main() -> int:
    assert_go_oracle_baseline()
    with tempfile.TemporaryDirectory(prefix="phase-w22-build-") as tmp:
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
            print(f"W2.2 sniffer gate failed: {error}", file=sys.stderr)
            return 1

    print(json.dumps(observation, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

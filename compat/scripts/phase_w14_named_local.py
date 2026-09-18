#!/usr/bin/env python3
"""W1.4 named http/socks/mixed listeners Go/Rust differential.

Unprivileged:
  - Config `-t` accepts named `type: mixed` (+ optional socks/http)
  - Rejects deferred TLS/Reality/ECH fields on named local listeners
  - Named mixed TCP: HTTP CONNECT + SOCKS5 echo through MATCH,DIRECT
  - Named mixed with `users:` requires matching credentials on both sides
"""

from __future__ import annotations

import base64
import json
import pathlib
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from phase1 import ROOT, assert_go_oracle_baseline, connect_proxy, recv_exact, terminate_process
from phase3 import http_request, launch, read_socks5_reply, socks5_authenticated, status, stop
from phase5b1a import build_binaries

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-w14-named-local-diff.json"
SCRIPT = pathlib.Path(__file__).resolve()
TCP_PAYLOAD = b"phase-w14-named-mixed-echo\n"


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


def named_mixed_yaml(*, mixed_port: int, with_users: bool) -> str:
    users = ""
    if with_users:
        users = (
            "    users:\n"
            "      - username: alice\n"
            "        password: secret\n"
        )
    return (
        "mode: rule\n"
        "log-level: info\n"
        "ipv6: false\n"
        "listeners:\n"
        "  - name: named-mixed\n"
        "    type: mixed\n"
        "    listen: 127.0.0.1\n"
        f"    port: {mixed_port}\n"
        f"{users}"
        "rules:\n"
        "  - MATCH,DIRECT\n"
    )


def deferred_tls_yaml(*, listen_port: int) -> str:
    return (
        "mode: rule\n"
        "ipv6: false\n"
        "listeners:\n"
        "  - name: named-http-tls\n"
        "    type: http\n"
        "    listen: 127.0.0.1\n"
        f"    port: {listen_port}\n"
        "    certificate: ./server.crt\n"
        "    private-key: ./server.key\n"
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


def http_echo(proxy_port: int, destination_port: int, authorization: str | None) -> bytes:
    stream, response = http_request(proxy_port, destination_port, authorization)
    with stream:
        if " 200 " not in status(response):
            raise AssertionError(f"HTTP CONNECT failed: {response!r}")
        stream.sendall(TCP_PAYLOAD)
        received = b""
        while len(received) < len(TCP_PAYLOAD):
            chunk = stream.recv(64)
            if not chunk:
                break
            received += chunk
        return received


def socks5_echo(
    proxy_port: int, destination_port: int, username: bytes | None, password: bytes | None
) -> bytes:
    if username is None:
        stream = connect_proxy(proxy_port)
        stream.sendall(b"\x05\x01\x00")
        method = recv_exact(stream, 2)
        if method != b"\x05\x00":
            stream.close()
            raise AssertionError(f"SOCKS5 no-auth method: {method!r}")
        stream.sendall(
            b"\x05\x01\x00\x01\x7f\x00\x00\x01" + destination_port.to_bytes(2, "big")
        )
        read_socks5_reply(stream)
    else:
        stream, _method, _auth = socks5_authenticated(
            proxy_port, destination_port, username, password or b""
        )
    with stream:
        stream.sendall(TCP_PAYLOAD)
        received = b""
        while len(received) < len(TCP_PAYLOAD):
            chunk = stream.recv(64)
            if not chunk:
                break
            received += chunk
        return received


def run_cases(binaries: dict[str, pathlib.Path]) -> dict[str, Any]:
    results: dict[str, Any] = {"platform": sys.platform, "cases": {}}
    with tempfile.TemporaryDirectory(prefix="phase-w14-named-local-") as tmp:
        scratch = pathlib.Path(tmp)

        deferred = scratch / "deferred-tls.yaml"
        write_config(deferred, deferred_tls_yaml(listen_port=reserve_port()))
        for name, binary in binaries.items():
            validated = validate_config(binary, deferred)
            results["cases"][f"{name}-reject-tls"] = {
                "returncode": validated.returncode,
                "stderr": validated.stderr[-400:],
            }
            if validated.returncode == 0:
                raise AssertionError(f"{name} accepted named http TLS fields")

        for auth_label, with_users in (("plain", False), ("auth", True)):
            for name, binary in binaries.items():
                home = scratch / f"home-{name}-{auth_label}"
                home.mkdir()
                cfg = home / "config.yaml"
                echo_port = reserve_port()
                mixed_port = reserve_port()
                write_config(cfg, named_mixed_yaml(mixed_port=mixed_port, with_users=with_users))
                validated = validate_config(binary, cfg)
                results["cases"][f"{name}-validate-{auth_label}"] = {
                    "returncode": validated.returncode,
                    "stderr": validated.stderr[-400:],
                }
                if validated.returncode != 0:
                    raise AssertionError(
                        f"{name} rejected named mixed ({auth_label}): {validated.stderr}"
                    )

                server = socketserver.ThreadingTCPServer(("127.0.0.1", echo_port), _TcpEcho)
                server.allow_reuse_address = True
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                process, _stdout, _stderr = launch(binary, cfg, home)
                try:
                    wait_tcp("127.0.0.1", mixed_port)
                    if with_users:
                        credential = base64.b64encode(b"alice:secret").decode()
                        http_got = http_echo(
                            mixed_port, echo_port, f"Basic {credential}"
                        )
                        socks_got = socks5_echo(
                            mixed_port, echo_port, b"alice", b"secret"
                        )
                        # Wrong password must fail closed.
                        bad_stream, bad_response = http_request(
                            mixed_port, echo_port, "Basic " + base64.b64encode(b"alice:nope").decode()
                        )
                        bad_stream.close()
                        results["cases"][f"{name}-http-wrong-auth"] = status(bad_response)
                        if " 407 " not in status(bad_response) and " 401 " not in status(
                            bad_response
                        ):
                            # Go returns 407 Proxy Authentication Required.
                            raise AssertionError(
                                f"{name} wrong auth not rejected: {bad_response!r}"
                            )
                    else:
                        http_got = http_echo(mixed_port, echo_port, None)
                        socks_got = socks5_echo(mixed_port, echo_port, None, None)
                    results["cases"][f"{name}-http-{auth_label}"] = http_got.decode(
                        "utf-8", errors="replace"
                    )
                    results["cases"][f"{name}-socks5-{auth_label}"] = socks_got.decode(
                        "utf-8", errors="replace"
                    )
                    if http_got != TCP_PAYLOAD:
                        raise AssertionError(f"{name} HTTP echo mismatch: {http_got!r}")
                    if socks_got != TCP_PAYLOAD:
                        raise AssertionError(f"{name} SOCKS5 echo mismatch: {socks_got!r}")
                finally:
                    stop(process)
                    terminate_process(process)
                    server.shutdown()
                    server.server_close()
    return results


def main() -> int:
    assert_go_oracle_baseline()
    with tempfile.TemporaryDirectory(prefix="phase-w14-build-") as tmp:
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
            print(f"W1.4 named local listeners gate failed: {error}", file=sys.stderr)
            return 1

    print(json.dumps(observation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

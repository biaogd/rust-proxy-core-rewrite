#!/usr/bin/env python3
"""Go/Rust differential for the Phase 6B1b TLS HTTP CONNECT outbound."""

from __future__ import annotations

import base64
import json
import pathlib
import selectors
import socket
import socketserver
import ssl
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, EchoHandler, ROOT, recv_exact, recv_until, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, connect_domain, debug_files


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6b-http-tls-diff.json"
AUTHORIZATION = "Basic " + base64.b64encode(b"proxy-user:proxy-pass").decode()


class TlsConnectHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            request = recv_until(self.request, b"\r\n\r\n")
        except (EOFError, OSError):
            return
        lines = request.decode("latin1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = {
            name.lower(): value.strip()
            for line in lines[1:]
            if ":" in line
            for name, value in [line.split(":", 1)]
        }
        self.server.observations.append(
            {
                "method": method,
                "target": target.rsplit(":", 1)[0] + ":<port>",
                "host": headers.get("host", "").rsplit(":", 1)[0] + ":<port>",
                "authorization": headers.get("proxy-authorization"),
            }
        )
        if self.server.status != 200:
            reason = "Bad Gateway" if self.server.status == 502 else "Rejected"
            self.request.sendall(
                f"HTTP/1.1 {self.server.status} {reason}\r\nContent-Length: 0\r\n\r\n".encode()
            )
            return
        if method != "CONNECT" or headers.get("proxy-authorization") != AUTHORIZATION:
            self.request.sendall(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"
            )
            return
        host, port = target.rsplit(":", 1)
        with socket.create_connection((host.strip("[]"), int(port)), timeout=5) as upstream:
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            relay(self.request, upstream)


class TlsConnectServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, status: int = 200, expected_sni: str = "dot.phase4.test") -> None:
        self.status = status
        self.expected_sni = expected_sni
        self.observations: list[dict[str, Any]] = []
        self.server_names: list[str | None] = []
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        self.context.set_servername_callback(self._record_server_name)
        super().__init__(("127.0.0.1", 0), TlsConnectHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def _record_server_name(self, _socket, server_name, _context) -> None:
        self.server_names.append(server_name)
        if server_name != self.expected_sni:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None

    def get_request(self):
        stream, address = super().get_request()
        try:
            return self.context.wrap_socket(stream, server_side=True), address
        except Exception:
            stream.close()
            raise

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)


def relay(left: socket.socket, right: socket.socket) -> None:
    poller = selectors.DefaultSelector()
    poller.register(left, selectors.EVENT_READ, right)
    poller.register(right, selectors.EVENT_READ, left)
    while True:
        events = poller.select(timeout=5)
        if not events:
            return
        for key, _ in events:
            data = key.fileobj.recv(65_536)
            if not data:
                return
            key.data.sendall(data)


def render_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    proxy_port: int,
    sni: str,
    skip_certificate_verification: bool,
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-https
    type: http
    server: 127.0.0.1
    port: {proxy_port}
    username: proxy-user
    password: proxy-pass
    tls: true
    sni: {sni}
    skip-cert-verify: {str(skip_certificate_verification).lower()}
rules:
  - MATCH,local-https
"""
    )


def try_route(mixed_port: int, echo_port: int) -> bool:
    try:
        with connect_domain(mixed_port, "localhost", echo_port) as stream:
            stream.sendall(b"tls-http")
            return recv_exact(stream, 8) == b"tls-http"
    except (EOFError, OSError):
        return False


def wait_route(process, mixed_port: int, echo_port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during TLS route readiness with {process.returncode}")
        if try_route(mixed_port, echo_port):
            return
        time.sleep(0.02)
    raise TimeoutError("TLS HTTP outbound did not become ready")


def collapse_retries(values: list[Any]) -> list[Any]:
    if values and all(value == values[0] for value in values):
        return values[:1]
    return values


def wait_tls_observation(
    process,
    proxy: TlsConnectServer,
    mixed_port: int,
    echo_port: int,
    *,
    require_connect: bool,
) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed = proxy.observations if require_connect else proxy.server_names
        if observed:
            return
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during TLS failure observation with {process.returncode}")
        try_route(mixed_port, echo_port)
        time.sleep(0.02)
    raise TimeoutError("TLS HTTP failure was not observed by the authority")


def exercise_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    sni: str,
    skip_certificate_verification: bool,
    status: int,
    expected_sni: str,
    expect_route: bool,
) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    proxy = TlsConnectServer(status, expected_sni)
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        proxy_port=proxy.port,
        sni=sni,
        skip_certificate_verification=skip_certificate_verification,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        if expect_route:
            wait_route(process, mixed_port, echo.port)
            proxy.server_names.clear()
            proxy.observations.clear()
        routed = try_route(mixed_port, echo.port)
        if not expect_route:
            wait_tls_observation(
                process,
                proxy,
                mixed_port,
                echo.port,
                require_connect=status != 200,
            )
        return {
            "routed": routed,
            "process-alive": process.poll() is None,
            # The tunnel retry count and backoff are owned by their existing
            # runtime gate. This slice preserves a distinct TLS/CONNECT frame
            # but collapses only byte-identical attempts.
            "server-names": collapse_retries(proxy.server_names),
            "connect": collapse_retries(proxy.observations),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        proxy.close()
        echo.close()


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    cases = {
        "tls-connect": ("dot.phase4.test", True, 200, "dot.phase4.test", True),
        "untrusted": ("dot.phase4.test", False, 200, "dot.phase4.test", False),
        "sni-rejected": ("wrong.phase4.test", True, 200, "dot.phase4.test", False),
        "connect-status": ("dot.phase4.test", True, 502, "dot.phase4.test", False),
    }
    observations = {}
    for name, (sni, skip, status, expected_sni, expect_route) in cases.items():
        case = scratch / name
        case.mkdir(parents=True)
        observations[name] = exercise_case(
            binary,
            case,
            sni=sni,
            skip_certificate_verification=skip,
            status=status,
            expected_sni=expected_sni,
            expect_route=expect_route,
        )
    return observations


def satisfies_contract(observation: dict[str, Any]) -> bool:
    connected = observation["tls-connect"]
    untrusted = observation["untrusted"]
    wrong_sni = observation["sni-rejected"]
    status = observation["connect-status"]
    return (
        connected["routed"] is True
        and connected["server-names"] == ["dot.phase4.test"]
        and connected["connect"]
        == [
            {
                "method": "CONNECT",
                "target": "127.0.0.1:<port>",
                "host": "127.0.0.1:<port>",
                "authorization": AUTHORIZATION,
            }
        ]
        and untrusted["routed"] is False
        and untrusted["server-names"] == ["dot.phase4.test"]
        and untrusted["connect"] == []
        and wrong_sni["routed"] is False
        and wrong_sni["server-names"] == ["wrong.phase4.test"]
        and wrong_sni["connect"] == []
        and status["routed"] is False
        and status["server-names"] == ["dot.phase4.test"]
        and len(status["connect"]) == 1
        and all(case["process-alive"] for case in observation.values())
    )


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6b-http-tls-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6BHTTPTLS_CARGO_TARGET", "phase6b-http-tls")
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
    if observations["go"] != observations["rust"] or not satisfies_contract(observations["go"]):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6B1b TLS HTTP CONNECT outbound differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

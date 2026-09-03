#!/usr/bin/env python3
"""Go/Rust differential for HTTP and SOCKS5 TLS identity options."""

from __future__ import annotations

import base64
import hashlib
import json
import selectors
import shutil
import socket
import socketserver
import ssl
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, recv_exact, recv_until, reload_via_controller, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5e_tls_client_auth import certificates, command
from phase6b_socks5_contract import connect_target


FAILURE_ARTIFACT = ROOT / "compat/artifacts/phase6b-tls-identity-diff.json"
AUTHORIZATION = "Basic " + base64.b64encode(b"tls-user:tls-pass").decode()


def relay(left: socket.socket, right: socket.socket) -> None:
    poller = selectors.DefaultSelector()
    poller.register(left, selectors.EVENT_READ, right)
    poller.register(right, selectors.EVENT_READ, left)
    try:
        while True:
            events = poller.select(timeout=IO_DEADLINE)
            if not events:
                return
            for key, _ in events:
                data = key.fileobj.recv(65_536)
                if not data:
                    return
                key.data.sendall(data)
    finally:
        poller.close()


def read_socks_address(stream: socket.socket, address_type: int) -> tuple[str, int]:
    if address_type == 1:
        host = socket.inet_ntoa(recv_exact(stream, 4))
    elif address_type == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(stream, 16))
    elif address_type == 3:
        host = recv_exact(stream, recv_exact(stream, 1)[0]).decode()
    else:
        raise ValueError(address_type)
    return host, int.from_bytes(recv_exact(stream, 2), "big")


class ProtocolHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client_cert = bool(self.request.getpeercert(binary_form=True))
        if self.server.protocol == "http":
            request = recv_until(self.request, b"\r\n\r\n")
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
                    "protocol": "http",
                    "client-cert": client_cert,
                    "method": method,
                    "authorization": headers.get("proxy-authorization"),
                }
            )
        else:
            version, count = recv_exact(self.request, 2)
            methods = list(recv_exact(self.request, count))
            method = 2 if 2 in methods else 0
            self.request.sendall(bytes((5, method)))
            username = password = ""
            if method == 2:
                _, username_length = recv_exact(self.request, 2)
                username = recv_exact(self.request, username_length).decode()
                password_length = recv_exact(self.request, 1)[0]
                password = recv_exact(self.request, password_length).decode()
                self.request.sendall(b"\x01\x00")
            request_version, command, reserved, address_type = recv_exact(self.request, 4)
            target, _ = read_socks_address(self.request, address_type)
            self.server.observations.append(
                {
                    "protocol": "socks5",
                    "client-cert": client_cert,
                    "version": version,
                    "methods": methods,
                    "credentials": [username, password],
                    "request": [request_version, command, reserved],
                    "address-type": address_type,
                }
            )
        with socket.create_connection(self.server.echo_address, timeout=IO_DEADLINE) as upstream:
            if self.server.protocol == "http":
                if method != "CONNECT":
                    return
                self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            else:
                self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            relay(self.request, upstream)


class TlsProtocolServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        protocol: str,
        echo_address: tuple[str, int],
        material: dict[str, Path],
        require_client: bool,
    ) -> None:
        self.protocol = protocol
        self.echo_address = echo_address
        self.observations: list[dict[str, Any]] = []
        self.server_names: list[str | None] = []
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(material["server"], material["server-key"])
        if require_client:
            self.context.verify_mode = ssl.CERT_REQUIRED
            self.context.load_verify_locations(material["client-ca"])
        self.context.set_servername_callback(self._record_server_name)
        super().__init__(("127.0.0.1", 0), ProtocolHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def _record_server_name(self, _socket, server_name, _context) -> None:
        self.server_names.append(server_name)

    def get_request(self):
        stream, address = super().get_request()
        try:
            return self.context.wrap_socket(stream, server_side=True), address
        except Exception:
            stream.close()
            raise

    def handle_error(self, _request, _client_address) -> None:
        pass

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=IO_DEADLINE)


def route(mixed_port: int, port: int, payload: bytes) -> bool:
    try:
        with connect_target(mixed_port, "target.example", port) as stream:
            stream.sendall(payload)
            return recv_exact(stream, len(payload)) == payload
    except (EOFError, OSError, TimeoutError):
        return False


def wait_route(process: Any, mixed_port: int, port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during TLS readiness with {process.returncode}")
        if route(mixed_port, port, b"ready"):
            return
        time.sleep(0.02)
    raise TimeoutError("TLS outbound did not become ready")


def indent_pem(pem: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line for line in pem.strip().splitlines())


def server_certificates(root: Path) -> dict[str, Path]:
    ca_key, ca = root / "phase6b-server-ca.key", root / "phase6b-server-ca.pem"
    server_key = root / "phase6b-server.key"
    server_csr = root / "phase6b-server.csr"
    server = root / "phase6b-server.pem"
    command(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-subj", "/CN=phase6b-server-root", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(ca_key),
        "-out", str(ca),
    )
    command(
        "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-subj", "/CN=dot.phase4.test", "-keyout", str(server_key),
        "-out", str(server_csr),
    )
    extension = root / "phase6b-server.ext"
    extension.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:dot.phase4.test\n"
    )
    command(
        "x509", "-req", "-in", str(server_csr), "-CA", str(ca), "-CAkey", str(ca_key),
        "-CAcreateserial", "-days", "2", "-extfile", str(extension), "-out", str(server),
    )
    return {"ca": ca, "server": server, "server-key": server_key}


def exercise(binary: Path, scratch: Path, source_material: dict[str, Path]) -> dict[str, Any]:
    profile = scratch / ".config/mihomo"
    profile.mkdir(parents=True)
    material: dict[str, Path] = {}
    for name, source in source_material.items():
        target = profile / source.name
        shutil.copyfile(source, target)
        material[name] = target
    echo = start_server(EchoHandler)
    echo_address = ("127.0.0.1", int(echo.server.server_address[1]))
    servers = {
        "http-full": TlsProtocolServer("http", echo_address, material, True),
        "http-pin": TlsProtocolServer("http", echo_address, material, False),
        "socks-full": TlsProtocolServer("socks5", echo_address, material, True),
        "socks-pin": TlsProtocolServer("socks5", echo_address, material, False),
    }
    destination = {
        "http-full": 33_001,
        "http-no-client": 33_002,
        "http-pin": 33_003,
        "http-bad-pin": 33_004,
        "socks-full": 33_005,
        "socks-no-client": 33_006,
        "socks-pin": 33_007,
        "socks-bad-pin": 33_008,
    }
    server_pem = material["server"].read_text()
    server_der = ssl.PEM_cert_to_DER_cert(server_pem)
    if isinstance(server_der, str):
        server_der = server_der.encode("latin1")
    fingerprint = hashlib.sha256(server_der).hexdigest()
    bad_fingerprint = "00" * 32
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
tls:
  custom-certifactes:
    - |-
{indent_pem(material['ca'].read_text(), 6)}
proxies:
  - name: http-full
    type: http
    server: 127.0.0.1
    port: {servers['http-full'].port}
    username: tls-user
    password: tls-pass
    tls: true
    sni: front.phase6b.test
    name-cert-verify: dot.phase4.test
    certificate: {material['trusted'].name}
    private-key: {material['trusted-key'].name}
  - name: http-no-client
    type: http
    server: 127.0.0.1
    port: {servers['http-full'].port}
    tls: true
    sni: front.phase6b.test
    name-cert-verify: dot.phase4.test
  - name: http-pin
    type: http
    server: 127.0.0.1
    port: {servers['http-pin'].port}
    tls: true
    sni: pin.phase6b.test
    fingerprint: "{fingerprint}"
  - name: http-bad-pin
    type: http
    server: 127.0.0.1
    port: {servers['http-pin'].port}
    tls: true
    sni: pin.phase6b.test
    fingerprint: "{bad_fingerprint}"
  - name: socks-full
    type: socks5
    server: 127.0.0.1
    port: {servers['socks-full'].port}
    username: tls-user
    password: tls-pass
    tls: true
    name-cert-verify: dot.phase4.test
    certificate: {material['trusted'].name}
    private-key: {material['trusted-key'].name}
  - name: socks-no-client
    type: socks5
    server: 127.0.0.1
    port: {servers['socks-full'].port}
    tls: true
    name-cert-verify: dot.phase4.test
  - name: socks-pin
    type: socks5
    server: 127.0.0.1
    port: {servers['socks-pin'].port}
    tls: true
    fingerprint: "{fingerprint}"
  - name: socks-bad-pin
    type: socks5
    server: 127.0.0.1
    port: {servers['socks-pin'].port}
    tls: true
    fingerprint: "{bad_fingerprint}"
rules:
"""
        + "\n".join(
            f"  - DST-PORT,{port},{name}" for name, port in destination.items()
        )
        + "\n  - MATCH,REJECT\n"
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_route(process, mixed_port, destination["http-pin"])
        # The pinned Go oracle installs global custom roots during apply, after
        # constructing the initial proxy objects. A reload reconstructs those
        # objects against the installed pool; Rust follows the same observable
        # lifecycle in this compatibility fixture.
        reload_via_controller(process, controller_port, config)
        wait_route(process, mixed_port, destination["http-full"])
        for server in servers.values():
            server.observations.clear()
            server.server_names.clear()
        outcomes = {
            name: route(mixed_port, port, name.encode())
            for name, port in destination.items()
        }
        return {
            "alive": process.poll() is None,
            "outcomes": outcomes,
            "servers": {
                name: {
                    "sni": sorted({str(value) for value in server.server_names}),
                    "observations": server.observations,
                }
                for name, server in servers.items()
            },
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        for server in servers.values():
            server.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6b-tls-identity-") as temporary:
        root = Path(temporary)
        material = certificates(root)
        material.update(server_certificates(root))
        binaries = build_binaries(root, "PHASE6BTLSIDENTITY_CARGO_TARGET", "phase6b-tls-identity")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch, material)
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
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6B HTTP/SOCKS5 TLS identity differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

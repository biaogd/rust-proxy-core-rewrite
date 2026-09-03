#!/usr/bin/env python3
"""Go/Rust differential for Phase 6E-B VLESS native TCP over TLS."""

from __future__ import annotations

import json
import pathlib
import socket
import socketserver
import ssl
import tempfile
import textwrap
import threading
import time
import urllib.parse
import uuid
from typing import Any

from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller
from phase6d_vmess_tcp import rejected_exchange
from phase6e_vless_tcp import STANDARD_UUID, config_validation, exchange, wait_exchange


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-tls-diff.json"
LARGE_PAYLOAD = bytes(range(256)) * 512


class TlsVlessHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        stream: socket.socket = self.request
        try:
            version = recv_exact(stream, 1)
            user = recv_exact(stream, 16)
            addon_size = recv_exact(stream, 1)[0]
            addons = recv_exact(stream, addon_size)
            command = recv_exact(stream, 1)[0]
            port = int.from_bytes(recv_exact(stream, 2), "big")
            address_type = recv_exact(stream, 1)[0]
            if address_type == 1:
                host = socket.inet_ntop(socket.AF_INET, recv_exact(stream, 4))
            elif address_type == 3:
                host = socket.inet_ntop(socket.AF_INET6, recv_exact(stream, 16))
            elif address_type == 2:
                host = recv_exact(stream, recv_exact(stream, 1)[0]).decode()
            else:
                return
        except (EOFError, OSError, UnicodeError):
            return
        authority: VlessTlsAuthority = self.server.authority
        authority.observe(
            f"CONNECT {host}:{port} UUID {uuid.UUID(bytes=user)} "
            f"ADDON {addon_size} COMMAND {command}"
        )
        if version != b"\0" or addons or command != 1:
            return
        stream.sendall(b"\0\0")
        if host == "health.phase6e":
            request_head = bytearray()
            while b"\r\n\r\n" not in request_head and len(request_head) <= 16 * 1024:
                chunk = stream.recv(4096)
                if not chunk:
                    return
                request_head.extend(chunk)
            authority.observe("HTTP health.phase6e")
            stream.sendall(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            return
        while True:
            payload = stream.recv(64 * 1024)
            if not payload:
                return
            stream.sendall(payload)


class TlsVlessServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, authority: "VlessTlsAuthority") -> None:
        self.authority = authority
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        self.context.set_servername_callback(
            lambda _stream, name, _context: authority.observe(f"TLS {name or '<none>'}")
        )
        super().__init__(("127.0.0.1", 0), TlsVlessHandler)

    def get_request(self) -> tuple[socket.socket, Any]:
        stream, address = super().get_request()
        try:
            return self.context.wrap_socket(stream, server_side=True), address
        except Exception:
            stream.close()
            raise


class VlessTlsAuthority:
    def __init__(self) -> None:
        self.observations: set[str] = set()
        self.lock = threading.Lock()
        self.server = TlsVlessServer(self)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def observe(self, value: str) -> None:
        with self.lock:
            self.observations.add(value)

    def wait_observations(self, expected: set[str]) -> list[str]:
        deadline = time.monotonic() + IO_DEADLINE
        while time.monotonic() < deadline:
            with self.lock:
                observed = self.observations.copy()
            if expected <= observed:
                return sorted(expected)
            time.sleep(0.02)
        raise TimeoutError(f"missing TLS VLESS observations: {sorted(expected - observed)}")

    def snapshot(self) -> list[str]:
        with self.lock:
            return sorted(self.observations)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def trusted_roots() -> str:
    root = pathlib.Path(ROOT_CERTIFICATE).read_text().strip()
    return "tls:\n  custom-certifactes:\n    - |-\n" + textwrap.indent(root, "      ") + "\n"


def record(
    name: str,
    authority_port: int,
    *,
    servername: str,
    skip: bool = False,
    verification_name: str | None = None,
) -> str:
    verification = (
        f"    name-cert-verify: {verification_name}\n" if verification_name else ""
    )
    return f"""  - name: {name}
    type: vless
    server: 127.0.0.1
    port: {authority_port}
    uuid: {STANDARD_UUID}
    encryption: none
    network: tcp
    tls: true
    servername: {servername}
    skip-cert-verify: {str(skip).lower()}
{verification}"""


def launch_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authority_port: int,
    *,
    servername: str,
    skip: bool,
    roots: bool,
) -> tuple[Any, Any, Any, int]:
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        (trusted_roots() if roots else "")
        + f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
{record("vless-case", authority_port, servername=servername, skip=skip)}rules:
  - MATCH,vless-case
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    wait_ready(process, mixed_port)
    return process, stdout, stderr, mixed_port


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority = VlessTlsAuthority()
    authority.start()
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        trusted_roots()
        + f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
proxies:
{record("vless-tls", authority.port, servername="dot.phase4.test")}{record("vless-name", authority.port, servername="front.phase6e.test", verification_name="dot.phase4.test")}proxy-groups:
  - name: vless-health
    type: url-test
    proxies: [vless-tls]
    url: http://health.phase6e:26013/probe
    interval: 3600
rules:
  - DST-PORT,26011,vless-tls
  - DST-PORT,26012,vless-name
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    opened: list[tuple[Any, Any, Any]] = []
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        try:
            trusted = wait_exchange(
                process, mixed_port, "tls.phase6e", 26011, b"vless-tls"
            )
        except Exception as error:
            raise AssertionError(
                f"trusted VLESS TLS failed; authority={authority.snapshot()}"
            ) from error
        half_close = exchange(
            mixed_port, "half-tls.phase6e", 26011, b"vless-tls-half", half_close=True
        )
        name_override = exchange(mixed_port, "name.phase6e", 26012, LARGE_PAYLOAD)
        health_query = urllib.parse.urlencode(
            {
                "url": "http://health.phase6e:26013/probe",
                "timeout": "3000",
                "expected": "200-299",
            }
        )
        health_status, health_body = request(
            controller_port, "GET", f"/group/vless-health/delay?{health_query}"
        )
        if health_status != 200:
            raise AssertionError(
                f"health delay failed: {(health_status, health_body)!r}; "
                f"authority={authority.snapshot()}"
            )

        case_results: dict[str, bool] = {}
        for case, servername, skip, roots, should_connect in [
            ("skip", "skip.phase6e.test", True, False, True),
            ("untrusted", "dot.phase4.test", False, False, False),
            ("wrong-name", "wrong.phase6e.test", False, True, False),
        ]:
            case_scratch = scratch / case
            case_scratch.mkdir()
            case_process, case_stdout, case_stderr, case_port = launch_case(
                binary,
                case_scratch,
                authority.port,
                servername=servername,
                skip=skip,
                roots=roots,
            )
            opened.append((case_process, case_stdout, case_stderr))
            if should_connect:
                case_results[case] = exchange(
                    case_port, f"{case}.phase6e", 443, case.encode()
                )
            else:
                case_results[case] = rejected_exchange(
                    case_port, f"{case}.phase6e", 443
                )
            case_results[f"{case}-survived"] = case_process.poll() is None
            stop(case_process)

        dormant = config_validation(
            binary,
            scratch,
            "proxies:\n"
            f"  - name: dormant\n    type: vless\n    server: 127.0.0.1\n    port: {authority.port}\n"
            f"    uuid: {STANDARD_UUID}\n    servername: dot.phase4.test\n",
        )
        expected = {
            "TLS dot.phase4.test",
            "TLS front.phase6e.test",
            "TLS skip.phase6e.test",
            f"CONNECT tls.phase6e:26011 UUID {STANDARD_UUID} ADDON 0 COMMAND 1",
            f"CONNECT half-tls.phase6e:26011 UUID {STANDARD_UUID} ADDON 0 COMMAND 1",
            f"CONNECT name.phase6e:26012 UUID {STANDARD_UUID} ADDON 0 COMMAND 1",
            f"CONNECT health.phase6e:26013 UUID {STANDARD_UUID} ADDON 0 COMMAND 1",
            f"CONNECT skip.phase6e:443 UUID {STANDARD_UUID} ADDON 0 COMMAND 1",
            "HTTP health.phase6e",
        }
        return {
            "trusted": trusted,
            "half-close": half_close,
            "name-override": name_override,
            "health": (health_status, bool(health_body)),
            **case_results,
            "dormant-tls-options-accepted": dormant,
            "authority": authority.wait_observations(expected),
            "process-alive": process.poll() is None,
        }
    finally:
        for case_process, case_stdout, case_stderr in opened:
            stop(case_process)
            case_stdout.close()
            case_stderr.close()
        stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def contract_errors(name: str, result: dict[str, Any]) -> list[str]:
    errors = []
    for field in [
        "trusted",
        "half-close",
        "name-override",
        "skip",
        "skip-survived",
        "untrusted",
        "untrusted-survived",
        "wrong-name",
        "wrong-name-survived",
        "dormant-tls-options-accepted",
        "process-alive",
    ]:
        if result[field] is not True:
            errors.append(f"{name}: {field} was not true")
    if result["health"][0] != 200 or not result["health"][1]:
        errors.append(f"{name}: health delay failed: {result['health']!r}")
    return errors


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6e-vless-tls-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6EVLESSTLS_CARGO_TARGET", "phase6e-vless-tls")
        try:
            for name in ["rust", "go"]:
                binary = binaries[name]
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
    errors = [
        error
        for name, result in observations.items()
        for error in contract_errors(name, result)
    ]
    if observations["go"] != observations["rust"] or errors:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {"contract-errors": errors, "observations": observations},
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6E-B VLESS native-TLS differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

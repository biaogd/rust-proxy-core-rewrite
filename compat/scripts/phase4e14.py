#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E14 domain HTTPS DoH."""

from __future__ import annotations

import base64
import json
import pathlib
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase4 import (
    AuthorityState,
    build_binaries,
    dns_query,
    launch,
    observe_response,
    stop,
    tcp_query,
    wait_dns_ready,
)
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY, rejected_query
from phase4e5 import encrypted_udp_query


TRUSTED_ENDPOINT = "dot.phase4.test"
MISMATCH_ENDPOINT = "bootstrap.doh.phase4.test"
VERIFY_NAME = "dot.phase4.test"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e14-diff.json"


def question(message: bytes) -> tuple[str, int, int]:
    offset = 12
    labels: list[str] = []
    while message[offset] != 0:
        length = message[offset]
        offset += 1
        labels.append(message[offset : offset + length].decode("ascii"))
        offset += length
    offset += 1
    return (
        ".".join(labels).lower(),
        int.from_bytes(message[offset : offset + 2], "big"),
        offset + 4,
    )


class BootstrapState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.questions: list[dict[str, Any]] = []

    def answer(self, query: bytes) -> bytes:
        name, record_type, question_end = question(query)
        with self.lock:
            self.questions.append({"name": name, "type": record_type})
        answer_count = int(
            name in {TRUSTED_ENDPOINT, MISMATCH_ENDPOINT} and record_type == 1
        )
        response = (
            query[:2]
            + b"\x81\x80"
            + b"\x00\x01"
            + answer_count.to_bytes(2, "big")
            + b"\x00\x00\x00\x00"
            + query[12:question_end]
        )
        if answer_count:
            response += (
                b"\xc0\x0c\x00\x01\x00\x01"
                + (30).to_bytes(4, "big")
                + b"\x00\x04"
                + socket.inet_aton("127.0.0.1")
            )
        return response

    def snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.questions)


class BootstrapServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class BootstrapHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query_bytes, server_socket = self.request
        server: BootstrapServer = self.server  # type: ignore[assignment]
        response = server.state.answer(query_bytes)  # type: ignore[attr-defined]
        server_socket.sendto(response, self.client_address)


class BootstrapAuthority:
    def __init__(self) -> None:
        self.state = BootstrapState()
        self.server = BootstrapServer(("127.0.0.1", 0), BootstrapHandler)
        self.server.state = self.state  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=IO_DEADLINE)


class HTTPSAuthority(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        self.state = AuthorityState()
        self.state.counts = {"https": 0}
        self.connection_count = 0
        self.server_names: list[str | None] = []
        self.requests: list[dict[str, Any]] = []
        self.observation_lock = threading.Lock()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        self.context.set_alpn_protocols(["http/1.1"])
        self.context.set_servername_callback(self.record_server_name)
        super().__init__(("127.0.0.1", 0), HTTPSHandler)

    def record_server_name(
        self,
        _stream: ssl.SSLSocket,
        server_name: str | None,
        _context: ssl.SSLContext,
    ) -> None:
        with self.observation_lock:
            self.server_names.append(server_name)

    def get_request(self) -> tuple[socket.socket, Any]:
        stream, address = super().get_request()
        try:
            tls_stream = self.context.wrap_socket(stream, server_side=True)
        except Exception:
            stream.close()
            raise
        with self.observation_lock:
            self.connection_count += 1
        return tls_stream, address

    def record_request(self, observation: dict[str, Any]) -> None:
        with self.observation_lock:
            self.requests.append(observation)

    def snapshot(self) -> dict[str, Any]:
        with self.observation_lock:
            connections = self.connection_count
            server_names = list(self.server_names)
            requests = list(self.requests)
        return {
            "connections": connections,
            "server-names": server_names,
            "queries": self.state.snapshot(),
            "requests": requests,
        }


class HTTPSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: HTTPSAuthority = self.server  # type: ignore[assignment]
        self.request.settimeout((2 * IO_DEADLINE) + 1)
        buffered = bytearray()
        while True:
            while b"\r\n\r\n" not in buffered:
                try:
                    chunk = self.request.recv(4096)
                except OSError:
                    return
                if not chunk:
                    return
                buffered.extend(chunk)
                if len(buffered) > 16_384:
                    return
            header_end = buffered.index(b"\r\n\r\n") + 4
            header_block = bytes(buffered[: header_end - 4])
            del buffered[:header_end]
            lines = header_block.decode("ascii").split("\r\n")
            method, target, version = lines[0].split(" ", 2)
            headers = {
                name.lower(): value.strip()
                for name, value in (line.split(":", 1) for line in lines[1:])
            }
            parsed = urllib.parse.urlsplit(target)
            parameters = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            encoded = parameters.get("dns", [""])
            try:
                query = base64.urlsafe_b64decode(
                    encoded[0] + "=" * (-len(encoded[0]) % 4)
                )
            except Exception:
                query = b""
            valid = (
                method == "GET"
                and version == "HTTP/1.1"
                and parsed.path == "/dns-query"
                and set(parameters) == {"dns"}
                and len(encoded) == 1
                and len(query) >= 12
                and query[:2] == b"\x00\x00"
                and headers.get("accept") == "application/dns-message"
                and not buffered
            )
            server.record_request(
                {
                    "host": headers.get("host"),
                    "path": parsed.path,
                    "dns-id-zero": len(query) >= 2 and query[:2] == b"\x00\x00",
                    "valid": valid,
                }
            )
            if not valid:
                return
            response = server.state.answer(query, "https")
            response_headers = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/dns-message\r\n"
                f"Content-Length: {len(response)}\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
            ).encode("ascii")
            try:
                self.request.sendall(response_headers + response)
            except OSError:
                return


def render_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    dns_port: int,
    bootstrap: str,
    endpoint: str,
    fragment: str,
    include_root: bool,
) -> None:
    tls = ""
    if include_root:
        root_pem = "\n".join(
            f"      {line}" for line in ROOT_CERTIFICATE.read_text().splitlines()
        )
        tls = f"tls:\n  custom-certifactes:\n    - |-\n{root_pem}\n"
    path.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
{tls}dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  default-nameserver:
    - {bootstrap}
  nameserver:
    - https://{endpoint}/dns-query{fragment}
rules:
  - MATCH,DIRECT
"""
    )


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    cases = {
        "domain-default-port": (TRUSTED_ENDPOINT, "", "udp://127.0.0.1:5354"),
        "domain-explicit-port": (
            f"{TRUSTED_ENDPOINT}:{reserve_port()}",
            "",
            "udp://127.0.0.1:5354",
        ),
        "domain-name-override": (
            f"{MISMATCH_ENDPOINT}:{reserve_port()}",
            f"#name-cert-verify={VERIFY_NAME}",
            "udp://127.0.0.1:5354",
        ),
        "domain-skip": (
            f"{MISMATCH_ENDPOINT}:{reserve_port()}",
            "#skip-cert-verify=true",
            "udp://127.0.0.1:5354",
        ),
        "ip-default-name": (
            f"127.0.0.1:{reserve_port()}",
            "",
            "udp://127.0.0.1:5354",
        ),
        "invalid-bootstrap-domain": (
            f"{TRUSTED_ENDPOINT}:{reserve_port()}",
            "",
            "udp://invalid.phase4.test:5354",
        ),
    }
    configs: dict[str, pathlib.Path] = {}
    for name, (endpoint, fragment, bootstrap) in cases.items():
        config = scratch / f"{name}.yaml"
        render_config(
            config,
            mixed_port=reserve_port(),
            dns_port=reserve_port(),
            bootstrap=bootstrap,
            endpoint=endpoint,
            fragment=fragment,
            include_root=True,
        )
        configs[name] = config
    return {
        name: subprocess.run(
            [str(binary), "-t", "-f", str(path)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        for name, path in configs.items()
    }


def exercise(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    endpoint: str,
    fragment: str,
    include_root: bool,
    accepted: bool,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    bootstrap = BootstrapAuthority()
    authority = HTTPSAuthority()
    thread = threading.Thread(target=authority.serve_forever, daemon=True)
    thread.start()
    mixed_port, dns_port = reserve_port(), reserve_port()
    upstream = f"{endpoint}:{authority.server_address[1]}"
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        bootstrap=f"udp://127.0.0.1:{bootstrap.port}",
        endpoint=upstream,
        fragment=fragment,
        include_root=include_root,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        name = f"{scratch.name}.phase4.test"
        query = dns_query(name, 0x8F10)
        if accepted:
            first = observe_response(encrypted_udp_query(dns_port, query), 0x8F10)
            cached = observe_response(
                tcp_query(dns_port, dns_query(name, 0x8F20)), 0x8F20
            )
        else:
            first = rejected_query(encrypted_udp_query, dns_port, query)
            cached = None
        authority_observation = authority.snapshot()
        for request in authority_observation["requests"]:
            request["host-matches-endpoint"] = request.pop("host") == upstream
        return {
            "first": first,
            "cached": cached,
            "bootstrap-questions": bootstrap.state.snapshot(),
            "https-authority": authority_observation,
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.shutdown()
        authority.server_close()
        thread.join(timeout=IO_DEADLINE)
        bootstrap.close()


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    config = validation(binary, scratch)
    if any(
        code != 0 for name, code in config.items() if name != "invalid-bootstrap-domain"
    ):
        return {"config": config, "runtime": "not-run"}
    return {
        "config": config,
        "runtime": {
            "trusted-default": exercise(
                binary,
                scratch / "trusted-default",
                endpoint=TRUSTED_ENDPOINT,
                fragment="",
                include_root=True,
                accepted=True,
            ),
            "system-untrusted": exercise(
                binary,
                scratch / "system-untrusted",
                endpoint=TRUSTED_ENDPOINT,
                fragment="",
                include_root=False,
                accepted=False,
            ),
            "trusted-default-name-mismatch": exercise(
                binary,
                scratch / "trusted-default-name-mismatch",
                endpoint=MISMATCH_ENDPOINT,
                fragment="",
                include_root=True,
                accepted=False,
            ),
            "trusted-name-override": exercise(
                binary,
                scratch / "trusted-name-override",
                endpoint=MISMATCH_ENDPOINT,
                fragment=f"#name-cert-verify={VERIFY_NAME}",
                include_root=True,
                accepted=True,
            ),
            "skip-untrusted": exercise(
                binary,
                scratch / "skip-untrusted",
                endpoint=MISMATCH_ENDPOINT,
                fragment="#skip-cert-verify=true",
                include_root=False,
                accepted=True,
            ),
            "name-over-skip-untrusted": exercise(
                binary,
                scratch / "name-over-skip-untrusted",
                endpoint=MISMATCH_ENDPOINT,
                fragment=(
                    f"#skip-cert-verify=true&name-cert-verify={VERIFY_NAME}"
                ),
                include_root=False,
                accepted=False,
            ),
        },
    }


def satisfies_phase_contract(observation: dict[str, Any]) -> bool:
    if observation["config"] != {
        "domain-default-port": 0,
        "domain-explicit-port": 0,
        "domain-name-override": 0,
        "domain-skip": 0,
        "ip-default-name": 0,
        "invalid-bootstrap-domain": 1,
    }:
        return False
    runtime = observation["runtime"]
    for name in ("trusted-default", "trusted-name-override", "skip-untrusted"):
        case = runtime[name]
        authority = case["https-authority"]
        endpoint = TRUSTED_ENDPOINT if name == "trusted-default" else MISMATCH_ENDPOINT
        if (
            case["first"].get("address") != "192.0.2.42"
            or case["cached"].get("address") != "192.0.2.42"
            or case["bootstrap-questions"] != [{"name": endpoint, "type": 1}]
            or authority["connections"] != 1
            or authority["server-names"] != [endpoint]
            or authority["queries"] != {"https": 1}
            or len(authority["requests"]) != 1
            or authority["requests"][0]["host-matches-endpoint"] is not True
            or authority["requests"][0]["path"] != "/dns-query"
            or authority["requests"][0]["valid"] is not True
            or case["exit-code"] != 0
        ):
            return False
    for name in (
        "system-untrusted",
        "trusted-default-name-mismatch",
        "name-over-skip-untrusted",
    ):
        case = runtime[name]
        authority = case["https-authority"]
        endpoint = (
            TRUSTED_ENDPOINT if name == "system-untrusted" else MISMATCH_ENDPOINT
        )
        if (
            case["first"].get("flags") != "8102"
            or case["cached"] is not None
            or case["bootstrap-questions"] != [{"name": endpoint, "type": 1}]
            or authority["connections"] != 0
            or authority["server-names"] != [endpoint]
            or authority["queries"] != {"https": 0}
            or authority["requests"]
            or case["exit-code"] != 0
        ):
            return False
    return True


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e14-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if observations["go"] != observations["rust"] or not satisfies_phase_contract(
            observations["go"]
        ):
            FAILURE_ARTIFACT.write_text(
                json.dumps(observations, indent=2, sort_keys=True)
            )
            raise SystemExit(f"Phase 4E14 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E14 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

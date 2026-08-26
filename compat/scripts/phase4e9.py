#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E9 domain DoT bootstrap."""

from __future__ import annotations

import json
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase4 import (
    build_binaries,
    dns_query,
    launch,
    observe_response,
    stop,
    tcp_query,
    wait_dns_ready,
)
from phase4e2 import ROOT_CERTIFICATE, TLSAuthority
from phase4e5 import encrypted_udp_query


ENDPOINT = "bootstrap.dot.phase4.test"
VERIFY_NAME = "dot.phase4.test"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e9-diff.json"


def question(message: bytes) -> tuple[str, int, int]:
    offset = 12
    labels: list[str] = []
    while message[offset] != 0:
        length = message[offset]
        offset += 1
        labels.append(message[offset : offset + length].decode("ascii"))
        offset += length
    offset += 1
    return ".".join(labels).lower(), int.from_bytes(message[offset : offset + 2], "big"), offset + 4


class BootstrapState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.questions: list[dict[str, Any]] = []

    def answer(self, query: bytes) -> bytes:
        name, record_type, question_end = question(query)
        with self.lock:
            self.questions.append({"name": name, "type": record_type})
        answer_count = int(name == ENDPOINT and record_type == 1)
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
        server_socket.sendto(server.state.answer(query_bytes), self.client_address)  # type: ignore[attr-defined]


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


def render_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    dns_port: int,
    bootstrap_port: int,
    endpoint: str,
) -> None:
    root_pem = "\n".join(f"      {line}" for line in ROOT_CERTIFICATE.read_text().splitlines())
    path.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
tls:
  custom-certifactes:
    - |-
{root_pem}
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  default-nameserver:
    - udp://127.0.0.1:{bootstrap_port}
  nameserver:
    - tls://{endpoint}#name-cert-verify={VERIFY_NAME}&disable-reuse=true
rules:
  - MATCH,DIRECT
"""
    )


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    configs: dict[str, pathlib.Path] = {}
    for name, endpoint in {
        "domain-explicit-port": f"{ENDPOINT}:{reserve_port()}",
        "domain-default-port": ENDPOINT,
        "ip-default-port": "127.0.0.1",
    }.items():
        config = scratch / f"{name}.yaml"
        render_config(
            config,
            mixed_port=reserve_port(),
            dns_port=reserve_port(),
            bootstrap_port=reserve_port(),
            endpoint=endpoint,
        )
        configs[name] = config
    invalid = scratch / "invalid-bootstrap-domain.yaml"
    render_config(
        invalid,
        mixed_port=reserve_port(),
        dns_port=reserve_port(),
        bootstrap_port=reserve_port(),
        endpoint=f"{ENDPOINT}:{reserve_port()}",
    )
    invalid.write_text(invalid.read_text().replace("udp://127.0.0.1:", "udp://invalid.test:"))
    configs["invalid-bootstrap-domain"] = invalid
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


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    bootstrap = BootstrapAuthority()
    authority = TLSAuthority()
    authority_thread = threading.Thread(target=authority.serve_forever, daemon=True)
    authority_thread.start()
    mixed_port, dns_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        bootstrap_port=bootstrap.port,
        endpoint=f"{ENDPOINT}:{authority.server_address[1]}",
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        name = "domain.dot.phase4.test"
        first = encrypted_udp_query(dns_port, dns_query(name, 0x8610))
        cached = tcp_query(dns_port, dns_query(name, 0x8620))
        return {
            "first": observe_response(first, 0x8610),
            "cached": observe_response(cached, 0x8620),
            "bootstrap-questions": bootstrap.state.snapshot(),
            "tls-authority": authority.snapshot(),
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.shutdown()
        authority.server_close()
        authority_thread.join(timeout=IO_DEADLINE)
        bootstrap.close()


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    config = validation(binary, scratch)
    required = ("domain-explicit-port", "domain-default-port", "ip-default-port")
    if any(config[name] != 0 for name in required):
        return {"config": config, "runtime": "not-run"}
    return {"config": config, "runtime": exercise(binary, scratch / "runtime")}


def satisfies_phase_contract(observation: dict[str, Any]) -> bool:
    runtime = observation["runtime"]
    return (
        observation["config"]
        == {
            "domain-explicit-port": 0,
            "domain-default-port": 0,
            "ip-default-port": 0,
            "invalid-bootstrap-domain": 1,
        }
        and runtime["first"].get("address") == "192.0.2.42"
        and runtime["first"].get("id-echoed") is True
        and runtime["cached"].get("address") == "192.0.2.42"
        and runtime["cached"].get("id-echoed") is True
        and runtime["bootstrap-questions"] == [{"name": ENDPOINT, "type": 1}]
        and runtime["tls-authority"]["connections"] == 1
        and runtime["tls-authority"]["queries"] == {"tls": 1}
        and runtime["exit-code"] == 0
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e9-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if observations["go"] != observations["rust"] or not satisfies_phase_contract(
            observations["go"]
        ):
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4E9 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E9 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E12 plaintext HTTP DoH."""

from __future__ import annotations

import base64
import json
import pathlib
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.parse
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase4 import AuthorityState, build_binaries, dns_query, launch, observe_response
from phase4 import stop, tcp_query, wait_dns_ready
from phase4e5 import encrypted_udp_query


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e12-diff.json"


class HTTPAuthority(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, expected_path: str) -> None:
        self.expected_path = expected_path
        self.state = AuthorityState()
        self.state.counts = {"http": 0}
        self.connection_count = 0
        self.requests: list[dict[str, Any]] = []
        self.observation_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), HTTPHandler)

    def begin_connection(self) -> None:
        with self.observation_lock:
            self.connection_count += 1

    def record(self, observation: dict[str, Any]) -> None:
        with self.observation_lock:
            self.requests.append(observation)

    def snapshot(self) -> dict[str, Any]:
        with self.observation_lock:
            connections = self.connection_count
            requests = list(self.requests)
        return {
            "connections": connections,
            "queries": self.state.snapshot(),
            "requests": requests,
        }


class HTTPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: HTTPAuthority = self.server  # type: ignore[assignment]
        server.begin_connection()
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
                return
            valid = (
                method == "GET"
                and version == "HTTP/1.1"
                and parsed.path == server.expected_path
                and set(parameters) == {"dns"}
                and len(encoded) == 1
                and len(query) >= 12
                and query[:2] == b"\x00\x00"
                and headers.get("accept") == "application/dns-message"
                and not buffered
            )
            server.record(
                {
                    "method": method,
                    "path": parsed.path,
                    "version": version,
                    "dns-parameter-count": len(encoded),
                    "dns-id-zero": len(query) >= 2 and query[:2] == b"\x00\x00",
                    "accept": headers.get("accept"),
                    "request-body-bytes": len(buffered),
                    "valid": valid,
                }
            )
            if not valid:
                return
            response = server.state.answer(query, "http")
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
    upstream: str,
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  nameserver:
    - {upstream}
rules:
  - MATCH,DIRECT
"""
    )


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    forms = {
        "default-port-empty-path": "http://127.0.0.1",
        "default-port-root-path": "http://127.0.0.1/",
        "explicit-port-empty-path": f"http://127.0.0.1:{reserve_port()}",
        "explicit-port-root-path": f"http://127.0.0.1:{reserve_port()}/",
        "explicit-port-custom-path": f"http://127.0.0.1:{reserve_port()}/dns-query",
        "wrong-scheme": f"bogus://127.0.0.1:{reserve_port()}",
    }
    configs: dict[str, pathlib.Path] = {}
    for name, upstream in forms.items():
        config = scratch / f"{name}.yaml"
        render_config(
            config,
            mixed_port=reserve_port(),
            dns_port=reserve_port(),
            upstream=upstream,
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
    configured_path: str,
    expected_path: str,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = HTTPAuthority(expected_path)
    thread = threading.Thread(target=authority.serve_forever, daemon=True)
    thread.start()
    mixed_port, dns_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        upstream=f"http://127.0.0.1:{authority.server_address[1]}{configured_path}",
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        first_name = f"first.{scratch.name}.phase4.test"
        second_name = f"second.{scratch.name}.phase4.test"
        first = encrypted_udp_query(dns_port, dns_query(first_name, 0x8D10))
        second = tcp_query(dns_port, dns_query(second_name, 0x8D20))
        cached = encrypted_udp_query(dns_port, dns_query(first_name, 0x8D30))
        return {
            "first": observe_response(first, 0x8D10),
            "second": observe_response(second, 0x8D20),
            "cached": observe_response(cached, 0x8D30),
            "http-authority": authority.snapshot(),
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


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    config = validation(binary, scratch)
    if any(code != 0 for name, code in config.items() if name != "wrong-scheme"):
        return {"config": config, "runtime": "not-run"}
    return {
        "config": config,
        "runtime": {
            "empty-path": exercise(
                binary,
                scratch / "empty-path",
                configured_path="",
                expected_path="/",
            ),
            "root-path": exercise(
                binary,
                scratch / "root-path",
                configured_path="/",
                expected_path="/",
            ),
            "custom-path": exercise(
                binary,
                scratch / "custom-path",
                configured_path="/dns-query",
                expected_path="/dns-query",
            ),
        },
    }


def satisfies_phase_contract(observation: dict[str, Any]) -> bool:
    expected_config = {
        "default-port-empty-path": 0,
        "default-port-root-path": 0,
        "explicit-port-empty-path": 0,
        "explicit-port-root-path": 0,
        "explicit-port-custom-path": 0,
        "wrong-scheme": 1,
    }
    if observation["config"] != expected_config:
        return False
    runtime = observation["runtime"]
    for name, expected_path in (
        ("empty-path", "/"),
        ("root-path", "/"),
        ("custom-path", "/dns-query"),
    ):
        case = runtime[name]
        authority = case["http-authority"]
        if (
            case["first"].get("address") != "192.0.2.42"
            or case["second"].get("address") != "192.0.2.42"
            or case["cached"].get("address") != "192.0.2.42"
            or authority["connections"] != 1
            or authority["queries"] != {"http": 2}
            or len(authority["requests"]) != 2
            or any(request["path"] != expected_path for request in authority["requests"])
            or any(request["valid"] is not True for request in authority["requests"])
            or case["exit-code"] != 0
        ):
            return False
    return True


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e12-") as temporary:
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
            raise SystemExit(f"Phase 4E12 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E12 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

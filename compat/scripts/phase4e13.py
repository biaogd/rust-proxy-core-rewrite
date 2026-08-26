#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E13 HTTPS URL semantics."""

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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e13-diff.json"
SERVER_NAME = "dot.phase4.test"


class HTTPSAuthority(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, behavior: str) -> None:
        self.behavior = behavior
        self.state = AuthorityState()
        self.state.counts = {"https": 0}
        self.connection_count = 0
        self.requests: list[dict[str, Any]] = []
        self.observation_lock = threading.Lock()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        self.context.set_alpn_protocols(["http/1.1"])
        super().__init__(("127.0.0.1", 0), HTTPSHandler)

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
                    "query-keys": sorted(parameters),
                    "authorization": headers.get("authorization"),
                    "dns-id-zero": len(query) >= 2 and query[:2] == b"\x00\x00",
                    "valid": valid,
                }
            )
            if not valid:
                return

            if server.behavior == "redirect" and parsed.path == "/redirect":
                self.send_redirect(f"/final?{parsed.query}")
                continue
            if server.behavior == "loop":
                self.send_redirect(f"/loop?{parsed.query}")
                continue
            if server.behavior == "redirect" and parsed.path != "/final":
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

    def send_redirect(self, location: str) -> None:
        response = (
            "HTTP/1.1 302 Found\r\n"
            f"Location: {location}\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        ).encode("ascii")
        self.request.sendall(response)


def render_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    dns_port: int,
    upstream: str,
) -> None:
    root_pem = "\n".join(
        f"      {line}" for line in ROOT_CERTIFICATE.read_text().splitlines()
    )
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
  nameserver:
    - "{upstream}"
rules:
  - MATCH,DIRECT
"""
    )


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    forms = {
        "default-port-root": f"https://127.0.0.1#name-cert-verify={SERVER_NAME}",
        "explicit-root-query": (
            f"https://127.0.0.1:{reserve_port()}?legacy=1"
            f"#name-cert-verify={SERVER_NAME}"
        ),
        "userinfo-query": (
            f"https://phase:secret@127.0.0.1:{reserve_port()}/dns-query?legacy=1"
            f"#name-cert-verify={SERVER_NAME}"
        ),
        "encoded-userinfo-boundary": (
            f"https://ph%61se:secret@127.0.0.1:{reserve_port()}/dns-query"
            f"#name-cert-verify={SERVER_NAME}"
        ),
        "custom-path": (
            f"https://127.0.0.1:{reserve_port()}/dns-query"
            f"#name-cert-verify={SERVER_NAME}"
        ),
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
    behavior: str,
    configured_path: str,
    credentials: str | None,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = HTTPSAuthority(behavior)
    thread = threading.Thread(target=authority.serve_forever, daemon=True)
    thread.start()
    mixed_port, dns_port = reserve_port(), reserve_port()
    userinfo = f"{credentials}@" if credentials else ""
    upstream = (
        f"https://{userinfo}127.0.0.1:{authority.server_address[1]}"
        f"{configured_path}?legacy=discarded#name-cert-verify={SERVER_NAME}"
    )
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        upstream=upstream,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        name = f"{behavior}.{scratch.name}.phase4.test"
        query = dns_query(name, 0x8E10)
        if behavior == "loop":
            result: dict[str, Any] = {
                "first": rejected_query(encrypted_udp_query, dns_port, query),
            }
        else:
            first = encrypted_udp_query(dns_port, query)
            result = {"first": observe_or_raw(first, 0x8E10)}
            cached = tcp_query(dns_port, dns_query(name, 0x8E20))
            result["cached"] = observe_or_raw(cached, 0x8E20)
        result["https-authority"] = authority.snapshot()
        result["exit-code"] = stop(process)
        return result
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.shutdown()
        authority.server_close()
        thread.join(timeout=IO_DEADLINE)


def observe_or_raw(response: bytes, identifier: int) -> dict[str, Any]:
    try:
        return observe_response(response, identifier)
    except (AssertionError, IndexError):
        return {"raw": response.hex()}


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    config = validation(binary, scratch)
    if any(
        code != 0
        for name, code in config.items()
        if name not in {"wrong-scheme", "encoded-userinfo-boundary"}
    ):
        return {"config": config, "runtime": "not-run"}
    return {
        "config": config,
        "runtime": {
            "root-query": exercise(
                binary,
                scratch / "root-query",
                behavior="answer",
                configured_path="",
                credentials=None,
            ),
            "userinfo": exercise(
                binary,
                scratch / "userinfo",
                behavior="answer",
                configured_path="/dns-query",
                credentials="phase:secret",
            ),
            "redirect": exercise(
                binary,
                scratch / "redirect",
                behavior="redirect",
                configured_path="/redirect",
                credentials="phase:secret",
            ),
            "redirect-limit": exercise(
                binary,
                scratch / "redirect-limit",
                behavior="loop",
                configured_path="/loop",
                credentials=None,
            ),
        },
    }


def satisfies_phase_contract(observation: dict[str, Any], implementation: str) -> bool:
    if observation["config"] != {
        "default-port-root": 0,
        "explicit-root-query": 0,
        "userinfo-query": 0,
        "encoded-userinfo-boundary": 0 if implementation == "go" else 1,
        "custom-path": 0,
        "wrong-scheme": 1,
    }:
        return False
    runtime = observation["runtime"]
    basic = "Basic " + base64.b64encode(b"phase:secret").decode("ascii")
    for name, path, authorization in (
        ("root-query", "/", None),
        ("userinfo", "/dns-query", basic),
    ):
        case = runtime[name]
        authority = case["https-authority"]
        if (
            case["first"].get("address") != "192.0.2.42"
            or case["cached"].get("address") != "192.0.2.42"
            or authority["connections"] != 1
            or authority["queries"] != {"https": 1}
            or len(authority["requests"]) != 1
            or authority["requests"][0]["path"] != path
            or authority["requests"][0]["query-keys"] != ["dns"]
            or authority["requests"][0]["authorization"] != authorization
            or authority["requests"][0]["valid"] is not True
            or case["exit-code"] != 0
        ):
            return False

    redirect = runtime["redirect"]
    redirect_authority = redirect["https-authority"]
    if (
        redirect["first"].get("address") != "192.0.2.42"
        or redirect["cached"].get("address") != "192.0.2.42"
        or redirect_authority["connections"] != 1
        or redirect_authority["queries"] != {"https": 1}
        or [request["path"] for request in redirect_authority["requests"]]
        != ["/redirect", "/final"]
        or any(
            request["authorization"] != basic
            or request["query-keys"] != ["dns"]
            or request["valid"] is not True
            for request in redirect_authority["requests"]
        )
        or redirect["exit-code"] != 0
    ):
        return False

    limit = runtime["redirect-limit"]
    limit_authority = limit["https-authority"]
    return (
        limit["first"].get("flags") == "8102"
        and limit_authority["connections"] == 1
        and limit_authority["queries"] == {"https": 0}
        and len(limit_authority["requests"]) == 10
        and [request["path"] for request in limit_authority["requests"]]
        == ["/loop"] * 10
        and all(
            request["query-keys"] == ["dns"] and request["valid"] is True
            for request in limit_authority["requests"]
        )
        and limit["exit-code"] == 0
    )


def comparable_observation(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        "config": {
            name: code
            for name, code in observation["config"].items()
            if name != "encoded-userinfo-boundary"
        },
        "runtime": observation["runtime"],
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e13-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if (
            comparable_observation(observations["go"])
            != comparable_observation(observations["rust"])
            or not satisfies_phase_contract(observations["go"], "go")
            or not satisfies_phase_contract(observations["rust"], "rust")
        ):
            FAILURE_ARTIFACT.write_text(
                json.dumps(observations, indent=2, sort_keys=True)
            )
            raise SystemExit(f"Phase 4E13 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E13 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

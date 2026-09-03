#!/usr/bin/env python3
"""Go/Rust differential suite for Phase 4F10 DNS lookup semantics."""

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

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    cargo_target_path,
    recv_exact,
    reserve_port,
    socks_connect,
    start_server,
    wait_ready,
)
from phase4 import build_binaries, dns_question_end, launch, stop


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f10-diff.json"


class AuthorityState:
    def __init__(self, behaviors: dict[int, tuple[str, Any, float]]) -> None:
        self.behaviors = behaviors
        self.lock = threading.Lock()
        self.received: dict[int, float] = {}
        self.replied: dict[int, float] = {}
        self.counts: dict[int, int] = {}

    def answer(self, query: bytes) -> bytes | None:
        end = dns_question_end(query)
        record_type = int.from_bytes(query[end - 4 : end - 2], "big")
        with self.lock:
            self.counts[record_type] = self.counts.get(record_type, 0) + 1
            self.received.setdefault(record_type, time.monotonic())
        mode, value, delay = self.behaviors.get(record_type, ("empty", None, 0.0))
        if mode == "blackhole":
            return None
        if delay:
            time.sleep(delay)
        if mode == "servfail":
            response = query[:2] + b"\x81\x82\x00\x01\x00\x00\x00\x00\x00\x00" + query[12:end]
        elif mode == "empty":
            response = query[:2] + b"\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" + query[12:end]
        elif mode in {"ech", "https"}:
            parameters = b""
            if mode == "ech":
                parameters = b"\x00\x05" + len(value).to_bytes(2, "big") + value
            else:
                parameters = b"\x00\x01\x00\x03\x02h2"
            rdata = b"\x00\x01\x00" + parameters
            answer = (
                b"\xc0\x0c\x00\x41\x00\x01\x00\x00\x00\x1e"
                + len(rdata).to_bytes(2, "big")
                + rdata
            )
            response = (
                query[:2]
                + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
                + query[12:end]
                + answer
            )
        else:
            packed = socket.inet_pton(
                socket.AF_INET6 if ":" in value else socket.AF_INET, value
            )
            answer_type = 28 if len(packed) == 16 else 1
            answer = (
                b"\xc0\x0c"
                + answer_type.to_bytes(2, "big")
                + b"\x00\x01\x00\x00\x00\x1e"
                + len(packed).to_bytes(2, "big")
                + packed
            )
            response = (
                query[:2]
                + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
                + query[12:end]
                + answer
            )
        with self.lock:
            self.replied.setdefault(record_type, time.monotonic())
        return response

    def contacted(self, record_type: int) -> bool:
        with self.lock:
            return record_type in self.received

    def concurrent(self) -> bool:
        with self.lock:
            if 1 not in self.received or 28 not in self.received:
                return False
            return abs(self.received[1] - self.received[28]) <= 0.12


class UDPAuthority(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, server_socket = self.request
        state: AuthorityState = self.server.state  # type: ignore[attr-defined]
        response = state.answer(query)
        if response is not None:
            try:
                server_socket.sendto(response, self.client_address)
            except OSError:
                pass


class LocalAuthority:
    def __init__(self, behaviors: dict[int, tuple[str, Any, float]]) -> None:
        self.state = AuthorityState(behaviors)
        self.server = UDPAuthority(("127.0.0.1", 0), UDPHandler)
        self.port = self.server.server_address[1]
        self.server.state = self.state  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=IO_DEADLINE)


def render_config(
    path: pathlib.Path,
    authority: LocalAuthority,
    *,
    ipv6_timeout: int = 100,
    mixed_port: int | None = None,
    direct: LocalAuthority | None = None,
    rules: list[str] | None = None,
) -> None:
    direct_block = ""
    if direct is not None:
        direct_block = f"  direct-nameserver:\n    - udp://127.0.0.1:{direct.port}\n"
    rule_lines = "\n".join(f"  - {rule}" for rule in (rules or ["MATCH,DIRECT"]))
    path.write_text(
        f"""mixed-port: {mixed_port or reserve_port()}
mode: rule
log-level: info
ipv6: true
dns:
  enable: true
  listen: 127.0.0.1:{reserve_port()}
  ipv6: true
  ipv6-timeout: {ipv6_timeout}
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  nameserver:
    - udp://127.0.0.1:{authority.port}
{direct_block}rules:
{rule_lines}
"""
    )


def build_helpers(root: pathlib.Path) -> dict[str, pathlib.Path]:
    products = build_binaries(root)
    go_helper = root / "go-dns-lookup"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_helper), "./compat/oracle/phase4f10"],
        cwd=ROOT,
        check=True,
    )
    target = cargo_target_path("PHASE4_CARGO_TARGET", "phase4-rust")
    return {
        "go-product": products["go"],
        "rust-product": products["rust"],
        "go": go_helper,
        "rust": target / "debug" / "rewrite-dns-lookup",
    }


def run_helper(
    binary: pathlib.Path, config: pathlib.Path, operation: str, host: str
) -> tuple[int, str | None, float]:
    started = time.monotonic()
    result = subprocess.run(
        [str(binary), str(config), operation, host],
        cwd=config.parent,
        capture_output=True,
        text=True,
        check=False,
        timeout=8,
    )
    finished = time.monotonic()
    lines = [line for line in result.stdout.splitlines() if line]
    output = lines[-1] if result.returncode == 0 and lines else None
    return result.returncode, output, finished


def lookup_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    label: str,
    behaviors: dict[int, tuple[str, Any, float]],
    operation: str,
    expected: str | None,
    *,
    ipv6_timeout: int = 100,
    host: str | None = None,
) -> dict[str, Any]:
    authority = LocalAuthority(behaviors)
    try:
        config = scratch / f"{label}.yaml"
        render_config(config, authority, ipv6_timeout=ipv6_timeout)
        exit_code, output, _finished = run_helper(
            binary, config, operation, host or f"{label}.phase4f10.test"
        )
        time.sleep(max((behavior[2] for behavior in behaviors.values()), default=0.0) + 0.1)
        return {
            "exit-code": exit_code,
            "output": output,
            "expected": expected,
            "a-contacted": authority.state.contacted(1),
            "aaaa-contacted": authority.state.contacted(28),
            "https-contacted": authority.state.contacted(65),
            "dual-started-concurrently": authority.state.concurrent(),
        }
    finally:
        authority.close()


def exercise_lookup(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    answer4 = ("answer", "192.0.2.40", 0.02)
    answer6 = ("answer", "2001:db8::40", 0.05)
    return {
        "dual-fast": lookup_case(
            binary, scratch, "dual-fast", {1: answer4, 28: answer6},
            "lookup", "192.0.2.40,2001:db8::40", ipv6_timeout=500
        ),
        "aaaa-over-window": lookup_case(
            binary, scratch, "aaaa-over-window",
            {1: ("answer", "192.0.2.41", 0.0), 28: ("answer", "2001:db8::41", 0.30)},
            "lookup", "192.0.2.41"
        ),
        "configured-window": lookup_case(
            binary, scratch, "configured-window",
            {1: ("answer", "192.0.2.42", 0.0), 28: ("answer", "2001:db8::42", 0.25)},
            "lookup", "192.0.2.42,2001:db8::42", ipv6_timeout=350
        ),
        "a-orders-result": lookup_case(
            binary, scratch, "a-orders-result",
            {1: ("answer", "192.0.2.43", 0.20), 28: ("answer", "2001:db8::43", 0.0)},
            "lookup", "192.0.2.43,2001:db8::43"
        ),
        "primary-a": lookup_case(
            binary, scratch, "primary-a",
            {1: ("answer", "192.0.2.44", 0.0), 28: ("answer", "2001:db8::44", 0.50)},
            "primary", "192.0.2.44"
        ),
        "primary-aaaa-fallback": lookup_case(
            binary, scratch, "primary-aaaa-fallback",
            {1: ("servfail", None, 0.05), 28: ("answer", "2001:db8::45", 0.20)},
            "primary", "2001:db8::45"
        ),
        "primary-both-fail": lookup_case(
            binary, scratch, "primary-both-fail",
            {1: ("servfail", None, 0.01), 28: ("empty", None, 0.02)},
            "primary", None
        ),
        "ipv4-literal": lookup_case(
            binary, scratch, "ipv4-literal", {}, "lookup", "192.0.2.99",
            host="192.0.2.99"
        ),
        "ipv6-literal": lookup_case(
            binary, scratch, "ipv6-literal", {}, "lookup", "2001:db8::99",
            host="2001:db8::99"
        ),
        "ech": lookup_case(
            binary, scratch, "ech", {65: ("ech", b"\x00\x01\x02\xff", 0.0)},
            "ech", "000102ff"
        ),
        "missing-ech": lookup_case(
            binary, scratch, "missing-ech", {65: ("https", None, 0.0)},
            "ech", None
        ),
    }


def domain_stream(proxy_port: int, domain: str, destination_port: int) -> socket.socket:
    encoded = domain.encode("ascii")
    return socks_connect(proxy_port, 3, bytes([len(encoded)]) + encoded, destination_port)


def tunnel_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    echo_port: int,
    label: str,
    rules: list[str],
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    behaviors = {1: ("answer", "127.0.0.1", 0.0), 28: ("empty", None, 0.0)}
    main = LocalAuthority(behaviors)
    direct = LocalAuthority(behaviors)
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config, main, mixed_port=mixed_port, direct=direct, rules=rules
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        payload = label.encode()
        echoed = False
        deadline = time.monotonic() + IO_DEADLINE
        while time.monotonic() < deadline:
            try:
                with domain_stream(
                    mixed_port, f"{label}.phase4f10.test", echo_port
                ) as stream:
                    stream.sendall(payload)
                    echoed = recv_exact(stream, len(payload)) == payload
                if echoed:
                    break
            except (EOFError, OSError):
                time.sleep(0.02)
        if not echoed:
            raise TimeoutError(f"{label} DNS tunnel did not relay")
        time.sleep(0.1)
        return {
            "echo": echoed,
            "main-a": main.state.contacted(1),
            "main-aaaa": main.state.contacted(28),
            "direct-a": direct.state.contacted(1),
            "direct-aaaa": direct.state.contacted(28),
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        main.close()
        direct.close()


def exercise_tunnel(
    binary: pathlib.Path, scratch: pathlib.Path, echo_port: int
) -> dict[str, Any]:
    return {
        "domain-rule": tunnel_case(
            binary,
            scratch / "domain",
            echo_port,
            "domain-lazy",
            [
                "DOMAIN,domain-lazy.phase4f10.test,DIRECT",
                "IP-CIDR,127.0.0.0/8,REJECT",
                "MATCH,REJECT",
            ],
        ),
        "ip-rule": tunnel_case(
            binary,
            scratch / "ip",
            echo_port,
            "ip-lazy",
            ["IP-CIDR,127.0.0.0/8,DIRECT", "MATCH,REJECT"],
        ),
    }


def validate_products(
    binaries: dict[str, pathlib.Path], scratch: pathlib.Path
) -> dict[str, dict[str, bool]]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = LocalAuthority({1: ("answer", "192.0.2.50", 0.0)})
    try:
        valid = scratch / "valid.yaml"
        render_config(valid, authority, ipv6_timeout=0)
        negative = scratch / "negative.yaml"
        render_config(negative, authority)
        negative.write_text(negative.read_text().replace("ipv6-timeout: 100", "ipv6-timeout: -1"))
        commands = {
            "go": lambda path: [
                str(binaries["go-product"]), "-t", "-f", str(path)
            ],
            "rust": lambda path: [str(binaries["rust-product"]), "-t", "-f", str(path)],
        }
        return {
            implementation: {
                "zero-valid": subprocess.run(
                    command(valid), cwd=scratch, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, check=False
                ).returncode == 0,
                "negative-rejected": subprocess.run(
                    command(negative), cwd=scratch, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, check=False
                ).returncode != 0,
            }
            for implementation, command in commands.items()
        }
    finally:
        authority.close()


def satisfies_lookup(observation: dict[str, Any]) -> bool:
    if not all(
        (
            case["exit-code"] != 0 and case["output"] is None
            if case["expected"] is None
            else case["exit-code"] == 0 and case["output"] == case["expected"]
        )
        for case in observation.values()
    ):
        return False
    network_cases = [
        "dual-fast", "aaaa-over-window", "configured-window", "a-orders-result",
        "primary-a", "primary-aaaa-fallback", "primary-both-fail",
    ]
    return (
        all(observation[name]["dual-started-concurrently"] for name in network_cases)
        and observation["ipv4-literal"]["a-contacted"] is False
        and observation["ipv4-literal"]["aaaa-contacted"] is False
        and observation["ipv6-literal"]["a-contacted"] is False
        and observation["ipv6-literal"]["aaaa-contacted"] is False
        and observation["ech"]["https-contacted"] is True
        and observation["missing-ech"]["https-contacted"] is True
    )


def satisfies_tunnel(observation: dict[str, Any]) -> bool:
    domain = observation["domain-rule"]
    ip = observation["ip-rule"]
    return (
        domain == {
            "echo": True,
            "main-a": False,
            "main-aaaa": False,
            "direct-a": True,
            "direct-aaaa": True,
            "exit-code": 0,
        }
        and ip == {
            "echo": True,
            "main-a": True,
            "main-aaaa": True,
            "direct-a": True,
            "direct-aaaa": True,
            "exit-code": 0,
        }
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    echo = start_server(EchoHandler)
    try:
        with tempfile.TemporaryDirectory(prefix="mihomo-phase4f10-") as temporary:
            root = pathlib.Path(temporary)
            binaries = build_helpers(root)
            validation = validate_products(binaries, root / "validation")
            lookup = {
                implementation: exercise_lookup(binaries[implementation], root / implementation)
                for implementation in ("go", "rust")
            }
            tunnel = {
                implementation: exercise_tunnel(
                    binaries[f"{implementation}-product"],
                    root / f"{implementation}-tunnel",
                    echo.port,
                )
                for implementation in ("go", "rust")
            }
            evidence = {"config": validation, "lookup": lookup, "tunnel": tunnel}
            expected_validation = {
                "go": {"zero-valid": True, "negative-rejected": True},
                "rust": {"zero-valid": True, "negative-rejected": True},
            }
            if (
                validation != expected_validation
                or lookup["go"] != lookup["rust"]
                or tunnel["go"] != tunnel["rust"]
                or not satisfies_lookup(lookup["go"])
                or not satisfies_tunnel(tunnel["go"])
            ):
                FAILURE_ARTIFACT.write_text(json.dumps(evidence, indent=2, sort_keys=True))
                raise SystemExit(f"Phase 4F10 mismatch; see {FAILURE_ARTIFACT}")
    finally:
        echo.close()
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F10 DNS lookup differential passed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Go/Rust differential suite for Phase 4F12 complete hosts semantics."""

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

from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port, socks_connect
from phase4 import build_binaries, launch, stop, wait_dns_ready
from phase4b import (
    decode_name,
    encode_name,
    local_interface_ip,
    make_query,
    parse_query,
    parse_response,
    system_host_candidate,
    udp_query,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f12-diff.json"


class AuthorityState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.questions: list[str] = []

    def respond(self, query: bytes) -> bytes:
        name, record_type, question_end = parse_query(query)
        record_class = int.from_bytes(query[question_end - 2 : question_end], "big")
        with self.lock:
            self.questions.append(f"{name}:{record_type}:{record_class}")
        if record_type == 1:
            data = socket.inet_aton("198.51.100.99")
            answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04" + data
        elif record_type == 28:
            data = socket.inet_pton(socket.AF_INET6, "2001:db8::99")
            answer = b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x1e\x00\x10" + data
        elif record_type == 5:
            data = encode_name("authority-cname.phase4f12.test")
            answer = (
                b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x1e"
                + len(data).to_bytes(2, "big")
                + data
            )
        elif record_type == 16:
            data = b"\x03txt"
            answer = (
                b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x1e"
                + len(data).to_bytes(2, "big")
                + data
            )
        else:
            answer = b""
        count = int(bool(answer))
        return (
            query[:2]
            + b"\x81\x80\x00\x01"
            + count.to_bytes(2, "big")
            + b"\x00\x00\x00\x00"
            + query[12:question_end]
            + answer
        )

    def snapshot(self) -> list[str]:
        with self.lock:
            return list(self.questions)


class AuthorityServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class AuthorityHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, server_socket = self.request
        state: AuthorityState = self.server.state  # type: ignore[attr-defined]
        server_socket.sendto(state.respond(query), self.client_address)


def hosts_block(include_lan: bool = False) -> str:
    lan = "  lan.phase4f12.test: lan\n" if include_lan else ""
    return f"""hosts:
  exact.suffix.phase4f12.test: 192.0.2.3
  "*.suffix.phase4f12.test": 192.0.2.2
  "+.suffix.phase4f12.test": 192.0.2.1
  ".dot.phase4f12.test": 192.0.2.4
  "deep.*.suffix.phase4f12.test": 192.0.2.5
  multi.phase4f12.test:
    - 192.0.2.10
    - 2001:db8::10
    - 192.0.2.11
  alias.phase4f12.test: external.phase4f12.test
  chain-one.phase4f12.test: chain-two.phase4f12.test
  chain-two.phase4f12.test:
    - 192.0.2.20
    - 2001:db8::20
{lan}"""


def render_dns_config(
    path: pathlib.Path,
    dns_port: int,
    authority_port: int,
    *,
    include_lan: bool = False,
    use_hosts: bool = True,
) -> None:
    path.write_text(
        f"""mixed-port: {reserve_port()}
mode: rule
log-level: info
{hosts_block(include_lan)}dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: true
  use-hosts: {str(use_hosts).lower()}
  use-system-hosts: true
  enhanced-mode: redir-host
  nameserver:
    - udp://127.0.0.1:{authority_port}
rules:
  - MATCH,DIRECT
"""
    )


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    scratch.mkdir(parents=True, exist_ok=True)
    base = scratch / "valid.yaml"
    render_dns_config(base, reserve_port(), reserve_port())
    invalid_wildcard = scratch / "invalid-wildcard.yaml"
    invalid_wildcard.write_text(base.read_text().replace(
        "  exact.suffix.phase4f12.test: 192.0.2.3",
        "  bad+key.phase4f12.test: 192.0.2.3",
    ))
    mixed = scratch / "mixed.yaml"
    mixed.write_text(base.read_text().replace(
        "  exact.suffix.phase4f12.test: 192.0.2.3",
        "  exact.suffix.phase4f12.test: [192.0.2.3, target.phase4f12.test]",
    ))
    short_target = scratch / "short-target.yaml"
    short_target.write_text(base.read_text().replace(
        "  alias.phase4f12.test: external.phase4f12.test",
        "  alias.phase4f12.test: external",
    ))
    cycle = scratch / "cycle.yaml"
    cycle.write_text(base.read_text().replace(
        "  alias.phase4f12.test: external.phase4f12.test",
        "  alias.phase4f12.test: cycle.phase4f12.test\n"
        "  cycle.phase4f12.test: alias.phase4f12.test",
    ))
    return {
        name: subprocess.run(
            [str(binary), "-t", "-f", str(path)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        for name, path in {
            "valid": base,
            "invalid-wildcard-skipped": invalid_wildcard,
            "mixed-values": mixed,
            "short-target": short_target,
            "cycle": cycle,
        }.items()
    }


def query_observation(
    dns_port: int, name: str, record_type: int, identifier: int, record_class: int = 1
) -> dict[str, Any]:
    query = bytearray(make_query(name, record_type, identifier))
    query[-2:] = record_class.to_bytes(2, "big")
    return parse_response(udp_query(dns_port, bytes(query)), identifier)


def normalize_records(observation: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(observation))
    for value in result.values():
        if isinstance(value, dict) and "records" in value:
            value["records"] = sorted(
                value["records"], key=lambda record: (record["type"], record["data"])
            )
    return result


def exercise_dns(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    state = AuthorityState()
    authority = AuthorityServer(("127.0.0.1", 0), AuthorityHandler)
    authority.state = state  # type: ignore[attr-defined]
    thread = threading.Thread(target=authority.serve_forever, daemon=True)
    thread.start()
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    render_dns_config(config, dns_port, authority.server_address[1])
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        cases = [
            ("plus-root", "suffix.phase4f12.test", 1, 1),
            ("star", "one.suffix.phase4f12.test", 1, 1),
            ("exact", "exact.suffix.phase4f12.test", 1, 1),
            ("inner-star", "deep.mid.suffix.phase4f12.test", 1, 1),
            ("plus-deep", "a.b.suffix.phase4f12.test", 1, 1),
            ("dot-one", "one.dot.phase4f12.test", 1, 1),
            ("dot-deep", "a.b.dot.phase4f12.test", 1, 1),
            ("dot-root-upstream", "dot.phase4f12.test", 1, 1),
            ("case-fold", "EXACT.SUFFIX.PHASE4F12.TEST", 1, 1),
            ("multi-a", "multi.phase4f12.test", 1, 1),
            ("multi-aaaa", "multi.phase4f12.test", 28, 1),
            ("address-cname-upstream", "multi.phase4f12.test", 5, 1),
            ("alias-cname", "alias.phase4f12.test", 5, 1),
            ("alias-a", "alias.phase4f12.test", 1, 1),
            ("chain-a", "chain-one.phase4f12.test", 1, 1),
            ("chain-cname", "chain-one.phase4f12.test", 5, 1),
            ("txt-upstream", "multi.phase4f12.test", 16, 1),
            ("chaos-upstream", "exact.suffix.phase4f12.test", 1, 3),
        ]
        observation = {
            label: query_observation(dns_port, name, record_type, 0x5C00 + index, record_class)
            for index, (label, name, record_type, record_class) in enumerate(cases)
        }
        candidate = system_host_candidate()
        if candidate is None:
            observation["system-host"] = {"available": False}
        else:
            name, expected = candidate
            observation["system-host"] = {
                "available": True,
                "name": name,
                "expected": expected,
                "response": query_observation(dns_port, name, 1, 0x5CF0),
            }
        observation["upstream"] = state.snapshot()
        time.sleep(0.3)
        observation["exit-code"] = stop(process)
        return normalize_records(observation)
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.shutdown()
        authority.server_close()
        thread.join(timeout=IO_DEADLINE)


def exercise_disabled_hosts(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    state = AuthorityState()
    authority = AuthorityServer(("127.0.0.1", 0), AuthorityHandler)
    authority.state = state  # type: ignore[attr-defined]
    thread = threading.Thread(target=authority.serve_forever, daemon=True)
    thread.start()
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    render_dns_config(config, dns_port, authority.server_address[1], use_hosts=False)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        response = query_observation(dns_port, "exact.suffix.phase4f12.test", 1, 0x5CF1)
        time.sleep(0.3)
        return {"response": response, "upstream": state.snapshot(), "exit-code": stop(process)}
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.shutdown()
        authority.server_close()
        thread.join(timeout=IO_DEADLINE)


def exercise_lan(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    candidate = local_interface_ip()
    if candidate is None:
        return {"available": False}
    scratch.mkdir(parents=True, exist_ok=True)
    state = AuthorityState()
    authority = AuthorityServer(("127.0.0.1", 0), AuthorityHandler)
    authority.state = state  # type: ignore[attr-defined]
    thread = threading.Thread(target=authority.serve_forever, daemon=True)
    thread.start()
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    render_dns_config(config, dns_port, authority.server_address[1], include_lan=True)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        ipv4 = query_observation(dns_port, "lan.phase4f12.test", 1, 0x5CF2)
        ipv6 = query_observation(dns_port, "lan.phase4f12.test", 28, 0x5CF3)
        time.sleep(0.3)
        return normalize_records({
            "available": True,
            "candidate": candidate,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "upstream": state.snapshot(),
            "exit-code": stop(process),
        })
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.shutdown()
        authority.server_close()
        thread.join(timeout=IO_DEADLINE)


class MarkerServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class MarkerHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        marker: bytes = self.server.marker  # type: ignore[attr-defined]
        self.request.sendall(marker)


def exercise_tunnel(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    first = MarkerServer(("127.0.0.1", 0), MarkerHandler)
    port = first.server_address[1]
    try:
        second = MarkerServer(("127.0.0.2", port), MarkerHandler)
    except OSError:
        first.server_close()
        return {"available": False}
    first.marker = b"1"  # type: ignore[attr-defined]
    second.marker = b"2"  # type: ignore[attr-defined]
    threads = [
        threading.Thread(target=first.serve_forever, daemon=True),
        threading.Thread(target=second.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
hosts:
  route.phase4f12.test: [127.0.0.1, 127.0.0.2]
  route-alias.phase4f12.test: route.phase4f12.test
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        deadline = time.monotonic() + IO_DEADLINE
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("hosts tunnel candidate exited")
            try:
                with socket.create_connection(("127.0.0.1", mixed_port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        markers: dict[str, list[str]] = {}
        for name in ("route.phase4f12.test", "route-alias.phase4f12.test"):
            values = set()
            encoded = name.encode("ascii")
            successes = 0
            deadline = time.monotonic() + (2 * IO_DEADLINE)
            while successes < 48 and time.monotonic() < deadline:
                try:
                    with socks_connect(
                        mixed_port, 3, bytes([len(encoded)]) + encoded, port
                    ) as stream:
                        values.add(recv_exact(stream, 1).decode())
                        successes += 1
                except (EOFError, OSError):
                    # A just-accepted connection may race listener startup on
                    # loaded runners.  It contributes no routing observation,
                    # so retry until the same 48 successful samples exist.
                    time.sleep(0.01)
            if successes != 48:
                raise TimeoutError(f"only {successes}/48 hosts tunnel samples succeeded")
            markers[name] = sorted(values)
        time.sleep(0.3)
        return {"available": True, "markers": markers, "exit-code": stop(process)}
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        first.shutdown()
        second.shutdown()
        first.server_close()
        second.server_close()
        for thread in threads:
            thread.join(timeout=IO_DEADLINE)


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    return {
        "config": validation(binary, scratch / "validation"),
        "dns": exercise_dns(binary, scratch / "dns"),
        "disabled": exercise_disabled_hosts(binary, scratch / "disabled"),
        "lan": exercise_lan(binary, scratch / "lan"),
        "tunnel": exercise_tunnel(binary, scratch / "tunnel"),
    }


def satisfies(observation: dict[str, Any]) -> bool:
    dns = observation["dns"]
    expected_validation = {
        "valid": 0,
        "invalid-wildcard-skipped": 0,
        "mixed-values": 1,
        "short-target": 1,
        "cycle": 1,
    }
    addresses = lambda label: [
        record["data"] for record in dns[label]["records"] if record["type"] in (1, 28)
    ]
    tunnel = observation["tunnel"]
    return (
        observation["config"] == expected_validation
        and dns["exit-code"] == 0
        and addresses("plus-root") == ["192.0.2.1"]
        and addresses("star") == ["192.0.2.2"]
        and addresses("exact") == ["192.0.2.3"]
        and addresses("inner-star") == ["192.0.2.5"]
        and addresses("plus-deep") == ["192.0.2.1"]
        and addresses("dot-one") == ["192.0.2.4"]
        and addresses("dot-deep") == ["192.0.2.4"]
        and addresses("multi-a") == ["192.0.2.10", "192.0.2.11"]
        and addresses("multi-aaaa") == ["2001:db8::10"]
        and dns["alias-cname"]["records"][0]["data"] == "external.phase4f12.test"
        and addresses("alias-a") == ["198.51.100.99"]
        and any(record["type"] == 5 for record in dns["alias-a"]["records"])
        and addresses("chain-a") == ["192.0.2.20"]
        and dns["chain-cname"]["records"][0]["data"] == "chain-two.phase4f12.test"
        and observation["disabled"]["response"]["records"][0]["data"] == "198.51.100.99"
        and observation["disabled"]["exit-code"] == 0
        and (not observation["lan"]["available"] or observation["lan"]["exit-code"] == 0)
        and (not tunnel["available"] or (
            tunnel["exit-code"] == 0
            and all(markers == ["1", "2"] for markers in tunnel["markers"].values())
        ))
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f12-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        evidence = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if evidence["go"] != evidence["rust"] or not satisfies(evidence["go"]):
            FAILURE_ARTIFACT.write_text(json.dumps(evidence, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4F12 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F12 hosts differential passed")


if __name__ == "__main__":
    main()

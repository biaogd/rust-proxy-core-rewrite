#!/usr/bin/env python3
"""Go/Rust differential suite for Phase 4F11 DNS cache lifecycle semantics."""

from __future__ import annotations

import json
import os
import pathlib
import signal
import socket
import socketserver
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase4 import (
    build_binaries,
    dns_question_end,
    dns_query,
    launch,
    stop,
    udp_query,
    wait_dns_ready,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f11-diff.json"


def query_name(message: bytes) -> str:
    end = dns_question_end(message) - 4
    labels: list[str] = []
    offset = 12
    while offset < end:
        length = message[offset]
        offset += 1
        if length == 0:
            break
        labels.append(message[offset : offset + length].decode("ascii"))
        offset += length
    return ".".join(labels)


class AuthorityState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.counts: dict[str, int] = {}
        self.values: dict[str, str] = {}
        self.modes: dict[str, str] = {}
        self.delays: dict[str, float] = {}
        self.ttls: dict[str, int] = {}

    def configure(
        self,
        name: str,
        *,
        mode: str = "answer",
        value: str = "192.0.2.11",
        ttl: int = 30,
        delay: float = 0.0,
    ) -> None:
        with self.lock:
            self.modes[name] = mode
            self.values[name] = value
            self.ttls[name] = ttl
            self.delays[name] = delay

    def set_value(self, name: str, value: str) -> None:
        with self.lock:
            self.values[name] = value

    def count(self, name: str) -> int:
        with self.lock:
            return self.counts.get(name, 0)

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return dict(sorted(self.counts.items()))

    def answer(self, query: bytes) -> bytes:
        name = query_name(query)
        with self.lock:
            count = self.counts.get(name, 0) + 1
            self.counts[name] = count
            mode = self.modes.get(name, "answer")
            value = self.values.get(name, "192.0.2.11")
            ttl = self.ttls.get(name, 30)
            delay = self.delays.get(name, 0.0)
        if delay:
            time.sleep(delay)
        end = dns_question_end(query)
        question = query[12:end]
        if mode == "servfail-once" and count == 1:
            return query[:2] + b"\x81\x82\x00\x01\x00\x00\x00\x00\x00\x00" + question
        if mode == "nxdomain":
            # SOA header TTL is the Go cache lifetime for a negative response.
            rdata = (
                b"\x02ns\xc0\x0c\x0ahostmaster\xc0\x0c"
                + b"\x00\x00\x00\x01"
                + b"\x00\x00\x00\x3c" * 3
                + ttl.to_bytes(4, "big")
            )
            authority = (
                b"\xc0\x0c\x00\x06\x00\x01"
                + ttl.to_bytes(4, "big")
                + len(rdata).to_bytes(2, "big")
                + rdata
            )
            return (
                query[:2]
                + b"\x81\x83\x00\x01\x00\x00\x00\x01\x00\x00"
                + question
                + authority
            )
        packed = socket.inet_aton(value)
        answer = (
            b"\xc0\x0c\x00\x01\x00\x01"
            + ttl.to_bytes(4, "big")
            + b"\x00\x04"
            + packed
        )
        return (
            query[:2]
            + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            + question
            + answer
        )


class UDPAuthority(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, server_socket = self.request
        state: AuthorityState = self.server.state  # type: ignore[attr-defined]
        server_socket.sendto(state.answer(query), self.client_address)


class LocalAuthority:
    def __init__(self) -> None:
        self.state = AuthorityState()
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
    dns_port: int,
    algorithm: str = "lru",
    max_size: int = 4096,
) -> None:
    path.write_text(
        f"""mixed-port: {reserve_port()}
mode: rule
log-level: info
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  cache-algorithm: {algorithm}
  cache-max-size: {max_size}
  nameserver:
    - udp://127.0.0.1:{authority.port}
rules:
  - MATCH,DIRECT
"""
    )


def skip_name(message: bytes, offset: int) -> int:
    while True:
        length = message[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length


def observe(response: bytes, identifier: int) -> dict[str, Any]:
    offset = dns_question_end(response)
    answer_count = int.from_bytes(response[6:8], "big")
    authority_count = int.from_bytes(response[8:10], "big")
    address = None
    ttl = None
    if answer_count or authority_count:
        offset = skip_name(response, offset)
        record_type = int.from_bytes(response[offset : offset + 2], "big")
        ttl = int.from_bytes(response[offset + 4 : offset + 8], "big")
        length = int.from_bytes(response[offset + 8 : offset + 10], "big")
        if record_type == 1 and length == 4:
            address = socket.inet_ntoa(response[offset + 10 : offset + 14])
    return {
        "id": int.from_bytes(response[:2], "big") == identifier,
        "rcode": response[3] & 0x0F,
        "address": address,
        "ttl": ttl,
    }


def wait_count(state: AuthorityState, name: str, expected: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if state.count(name) >= expected:
            return
        time.sleep(0.02)
    raise TimeoutError(f"upstream count for {name} did not reach {expected}")


def with_candidate(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    algorithm: str,
    max_size: int,
    exercise: Any,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = LocalAuthority()
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    render_config(config, authority, dns_port, algorithm, max_size)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        result = exercise(process, dns_port, authority, config)
        time.sleep(0.1)
        result["exit-code"] = stop(process)
        return result
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def cache_trace(
    _process: Any,
    dns_port: int,
    authority: LocalAuthority,
    _config: pathlib.Path,
    names: list[str],
) -> dict[str, Any]:
    responses = []
    for index, name in enumerate(names):
        identifier = 0x4B00 + index
        responses.append(observe(udp_query(dns_port, dns_query(name, identifier)), identifier))
    return {"responses": responses, "counts": authority.state.snapshot()}


def stale_negative(
    _process: Any,
    dns_port: int,
    authority: LocalAuthority,
    _config: pathlib.Path,
) -> dict[str, Any]:
    positive = "stale.phase4f11.test"
    negative = "negative.phase4f11.test"
    authority.state.configure(positive, value="192.0.2.21", ttl=2)
    authority.state.configure(negative, mode="nxdomain", ttl=2)
    first = observe(udp_query(dns_port, dns_query(positive, 0x4B20)), 0x4B20)
    negative_first = observe(udp_query(dns_port, dns_query(negative, 0x4B21)), 0x4B21)
    negative_cached = observe(udp_query(dns_port, dns_query(negative, 0x4B22)), 0x4B22)
    authority.state.set_value(positive, "192.0.2.22")
    time.sleep(2.2)
    stale = observe(udp_query(dns_port, dns_query(positive, 0x4B23)), 0x4B23)
    wait_count(authority.state, positive, 2)
    deadline = time.monotonic() + IO_DEADLINE
    refreshed = stale
    while time.monotonic() < deadline:
        refreshed = observe(udp_query(dns_port, dns_query(positive, 0x4B24)), 0x4B24)
        if refreshed["address"] == "192.0.2.22":
            break
        time.sleep(0.02)
    return {
        "positive-first": first,
        "positive-stale": stale,
        "positive-refreshed": refreshed,
        "negative-first": negative_first,
        "negative-cached": negative_cached,
        "positive-upstream": authority.state.count(positive),
        "negative-upstream": authority.state.count(negative),
    }


def concurrent_queries(
    _process: Any,
    dns_port: int,
    authority: LocalAuthority,
    _config: pathlib.Path,
) -> dict[str, Any]:
    name = "singleflight.phase4f11.test"
    authority.state.configure(name, value="192.0.2.31", delay=0.25)
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [
            pool.submit(udp_query, dns_port, dns_query(name, 0x4B30 + index))
            for index in range(8)
        ]
    responses = [observe(future.result(), 0x4B30 + index) for index, future in enumerate(futures)]
    return {"responses": responses, "upstream": authority.state.count(name)}


def retry_case(
    _process: Any,
    dns_port: int,
    authority: LocalAuthority,
    _config: pathlib.Path,
) -> dict[str, Any]:
    name = "retry.phase4f11.test"
    authority.state.configure(name, mode="servfail-once", value="192.0.2.41")
    first = observe(udp_query(dns_port, dns_query(name, 0x4B40)), 0x4B40)
    wait_count(authority.state, name, 2)
    second = observe(udp_query(dns_port, dns_query(name, 0x4B41)), 0x4B41)
    return {"first": first, "retried": second, "upstream": authority.state.count(name)}


def reload_case(
    process: Any,
    dns_port: int,
    authority: LocalAuthority,
    config: pathlib.Path,
) -> dict[str, Any]:
    name = "reload.phase4f11.test"
    authority.state.configure(name, value="192.0.2.51")
    first = observe(udp_query(dns_port, dns_query(name, 0x4B50)), 0x4B50)
    cached = observe(udp_query(dns_port, dns_query(name, 0x4B51)), 0x4B51)
    config.touch()
    os.kill(process.pid, signal.SIGHUP)
    time.sleep(0.35)
    deadline = time.monotonic() + IO_DEADLINE
    while True:
        try:
            after = observe(udp_query(dns_port, dns_query(name, 0x4B52)), 0x4B52)
            break
        except TimeoutError:
            if time.monotonic() >= deadline:
                raise
    return {
        "first": first,
        "cached": cached,
        "after-reload": after,
        "upstream": authority.state.count(name),
    }


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    lru_names = [
        "a.lru.phase4f11.test",
        "b.lru.phase4f11.test",
        "a.lru.phase4f11.test",
        "c.lru.phase4f11.test",
        "b.lru.phase4f11.test",
    ]
    arc_names = [
        "a.arc.phase4f11.test",
        "b.arc.phase4f11.test",
        "a.arc.phase4f11.test",
        "c.arc.phase4f11.test",
        "d.arc.phase4f11.test",
        "a.arc.phase4f11.test",
    ]
    return {
        "lru": with_candidate(
            binary,
            scratch / "lru",
            "lru",
            2,
            lambda *args: cache_trace(*args, lru_names),
        ),
        "arc": with_candidate(
            binary,
            scratch / "arc",
            "arc",
            2,
            lambda *args: cache_trace(*args, arc_names),
        ),
        "ttl": with_candidate(binary, scratch / "ttl", "lru", 8, stale_negative),
        "singleflight": with_candidate(
            binary, scratch / "singleflight", "lru", 8, concurrent_queries
        ),
        "retry": with_candidate(binary, scratch / "retry", "lru", 8, retry_case),
        "reload": with_candidate(binary, scratch / "reload", "lru", 8, reload_case),
    }


def normalized(observation: dict[str, Any]) -> dict[str, Any]:
    # Fresh TTL can differ by one second because the Go cache rounds expiry to
    # wall-clock seconds. Preserve the semantic stale TTL and omit only fresh TTL.
    result = json.loads(json.dumps(observation))
    for section in result.values():
        stack = [section]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                if value.get("ttl") not in (None, 1):
                    value["ttl"] = "fresh"
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
    return result


def satisfies(observation: dict[str, Any]) -> bool:
    lru_counts = observation["lru"]["counts"]
    arc_counts = observation["arc"]["counts"]
    ttl = observation["ttl"]
    singleflight = observation["singleflight"]
    retry = observation["retry"]
    reload = observation["reload"]
    return (
        all(section["exit-code"] == 0 for section in observation.values())
        and lru_counts["a.lru.phase4f11.test"] == 1
        and lru_counts["b.lru.phase4f11.test"] == 2
        and arc_counts["a.arc.phase4f11.test"] == 1
        and ttl["positive-stale"]["address"] == "192.0.2.21"
        and ttl["positive-stale"]["ttl"] == 1
        and ttl["positive-refreshed"]["address"] == "192.0.2.22"
        and ttl["negative-first"]["rcode"] == 3
        and ttl["negative-cached"]["rcode"] == 3
        and ttl["negative-upstream"] == 1
        and singleflight["upstream"] == 1
        and all(response["id"] for response in singleflight["responses"])
        and retry["first"]["rcode"] == 2
        and retry["retried"]["address"] == "192.0.2.41"
        and retry["upstream"] == 2
        and reload["upstream"] == 2
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f11-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        evidence = {
            implementation: exercise(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if (
            normalized(evidence["go"]) != normalized(evidence["rust"])
            or not satisfies(evidence["go"])
            or not satisfies(evidence["rust"])
        ):
            FAILURE_ARTIFACT.write_text(json.dumps(evidence, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4F11 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F11 DNS cache lifecycle differential passed")


if __name__ == "__main__":
    main()

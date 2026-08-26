#!/usr/bin/env python3
"""Local Go/Rust differential suite for the Phase 4C fake-IP gate."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, EchoHandler, recv_exact, reserve_port
from phase4 import build_binaries, launch, stop, wait_dns_ready
from phase4b import (
    AllInterfacesServer,
    local_interface_ip,
    make_query,
    parse_query,
    parse_response,
    socks5_connect,
    udp_query,
)


FIXTURE = ROOT / "compat" / "fixtures" / "phase4" / "fake-ip.yaml.tmpl"
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4c-diff.json"


class AuthorityState:
    def __init__(self, ipv4: str) -> None:
        self.ipv4 = ipv4
        self.questions: list[tuple[str, int]] = []
        self.lock = threading.Lock()

    def respond(self, query: bytes) -> bytes:
        name, record_type, question_end = parse_query(query)
        with self.lock:
            self.questions.append((name, record_type))
        answer = b""
        count = 0
        if record_type == 1:
            payload = socket.inet_pton(socket.AF_INET, self.ipv4)
        elif record_type == 28:
            payload = socket.inet_pton(socket.AF_INET6, "2001:db8::42")
        else:
            payload = b""
        if payload:
            answer = (
                b"\xc0\x0c"
                + record_type.to_bytes(2, "big")
                + b"\x00\x01"
                + (30).to_bytes(4, "big")
                + len(payload).to_bytes(2, "big")
                + payload
            )
            count = 1
        return (
            query[:2]
            + b"\x81\x80\x00\x01"
            + count.to_bytes(2, "big")
            + b"\x00\x00\x00\x00"
            + query[12:question_end]
            + answer
        )

    def snapshot(self) -> list[list[Any]]:
        with self.lock:
            # The pinned Go dual-stack resolver issues A and AAAA concurrently;
            # repeated oracle runs demonstrate that their arrival order flips.
            # Names, types and multiplicity remain semantic.
            return [
                [name, record_type]
                for name, record_type in sorted(self.questions)
            ]


class AuthorityServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class AuthorityHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, server_socket = self.request
        state: AuthorityState = self.server.state  # type: ignore[attr-defined]
        server_socket.sendto(state.respond(query), self.client_address)


def render_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    dns_port: int,
    upstream_port: int,
    store: bool = False,
    ipv4_range: str = "198.19.0.1/16",
    ipv6_range: str = "fd00:198:19::1/120",
    filter_mode: str = "blacklist",
    filter_domain: str = "real.phase4.test",
) -> None:
    path.write_text(
        FIXTURE.read_text()
        .replace("${MIXED_PORT}", str(mixed_port))
        .replace("${DNS_PORT}", str(dns_port))
        .replace("${UPSTREAM_PORT}", str(upstream_port))
        .replace("${STORE_FAKE_IP}", str(store).lower())
        .replace("${FAKE_IP_RANGE}", ipv4_range)
        .replace("${FAKE_IP_RANGE6}", ipv6_range)
        .replace("${FILTER_MODE}", filter_mode)
        .replace("${FILTER_DOMAIN}", filter_domain)
    )


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    cases = {
        "valid": {},
        "small-v4": {"ipv4_range": "198.19.0.1/31"},
        "wrong-v4-family": {"ipv4_range": "fd00::1/120"},
        "empty-ranges": {"ipv4_range": "", "ipv6_range": ""},
        "rule-filter": {"filter_mode": "rule"},
    }
    result: dict[str, int] = {}
    for index, (name, overrides) in enumerate(cases.items()):
        config = scratch / f"validation-{index}.yaml"
        render_config(
            config,
            mixed_port=reserve_port(),
            dns_port=reserve_port(),
            upstream_port=reserve_port(),
            **overrides,  # type: ignore[arg-type]
        )
        result[name] = subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
    return result


def fake_address(port: int, name: str, record_type: int, identifier: int) -> dict[str, Any]:
    return parse_response(
        udp_query(port, make_query(name, record_type, identifier)), identifier
    )


def exercise_basic(
    binary: pathlib.Path, scratch: pathlib.Path, authority: AuthorityServer
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    config = scratch / "basic.yaml"
    dns_port, mixed_port = reserve_port(), reserve_port()
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        upstream_port=authority.server_address[1],
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        observation = {
            "a-first": fake_address(dns_port, "one.phase4.test", 1, 0x6101),
            "a-case-hit": fake_address(dns_port, "ONE.PHASE4.TEST", 1, 0x6102),
            "a-next": fake_address(dns_port, "two.phase4.test", 1, 0x6103),
            "aaaa-first": fake_address(dns_port, "six.phase4.test", 28, 0x6104),
            "filtered-real": fake_address(dns_port, "real.phase4.test", 1, 0x6105),
        }
        observation["exit-code"] = stop(process)
        return observation
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def exercise_reverse(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authority: AuthorityServer,
    echo: AllInterfacesServer | None,
) -> dict[str, Any] | str:
    if echo is None:
        return "skipped-no-nonloopback-interface"
    scratch.mkdir(parents=True, exist_ok=True)
    config = scratch / "reverse.yaml"
    dns_port, mixed_port = reserve_port(), reserve_port()
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        upstream_port=authority.server_address[1],
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        response = fake_address(dns_port, "route.phase4.test", 1, 0x6201)
        address = response["records"][0]["data"]
        with socks5_connect(mixed_port, address, echo.server_address[1]) as stream:
            stream.sendall(b"fake-route")
            echoed = recv_exact(stream, 10).decode()
        return {
            "fake-response": response,
            "relay": echoed,
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def exercise_whitelist(
    binary: pathlib.Path, scratch: pathlib.Path, authority: AuthorityServer
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    config = scratch / "whitelist.yaml"
    dns_port = reserve_port()
    render_config(
        config,
        mixed_port=reserve_port(),
        dns_port=dns_port,
        upstream_port=authority.server_address[1],
        filter_mode="whitelist",
        filter_domain="only-fake.phase4.test",
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        result = {
            "listed": fake_address(dns_port, "only-fake.phase4.test", 1, 0x6301),
            "unlisted": fake_address(dns_port, "unlisted.phase4.test", 1, 0x6302),
        }
        result["exit-code"] = stop(process)
        return result
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def exercise_cycle_and_capacity(
    binary: pathlib.Path, scratch: pathlib.Path, authority: AuthorityServer
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    cycle_config = scratch / "cycle.yaml"
    cycle_port = reserve_port()
    render_config(
        cycle_config,
        mixed_port=reserve_port(),
        dns_port=cycle_port,
        upstream_port=authority.server_address[1],
        ipv4_range="198.19.0.1/29",
    )
    process, stdout, stderr = launch(binary, cycle_config, scratch)
    try:
        wait_dns_ready(process, cycle_port)
        time.sleep(0.1)
        cycle = [
            fake_address(cycle_port, f"cycle-{index}.phase4.test", 1, 0x6400 + index)[
                "records"
            ][0]["data"]
            for index in range(4)
        ]
        cycle_exit = stop(process)
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()

    capacity_scratch = scratch / "capacity"
    capacity_scratch.mkdir()
    capacity_config = capacity_scratch / "config.yaml"
    capacity_port = reserve_port()
    render_config(
        capacity_config,
        mixed_port=reserve_port(),
        dns_port=capacity_port,
        upstream_port=authority.server_address[1],
    )
    process, stdout, stderr = launch(binary, capacity_config, capacity_scratch)
    try:
        wait_dns_ready(process, capacity_port)
        time.sleep(0.1)
        first = ""
        for index in range(1001):
            response = fake_address(
                capacity_port,
                f"capacity-{index}.phase4.test",
                1,
                (0x6500 + index) & 0xFFFF,
            )
            if index == 0:
                first = response["records"][0]["data"]
        revisited = fake_address(
            capacity_port, "capacity-0.phase4.test", 1, 0x6901
        )["records"][0]["data"]
        capacity_exit = stop(process)
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
    return {
        "cycle": cycle,
        "cycle-exit": cycle_exit,
        "capacity-first": first,
        "capacity-revisited": revisited,
        "capacity-exit": capacity_exit,
    }


def exercise_persistence(
    binary: pathlib.Path, scratch: pathlib.Path, authority: AuthorityServer
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    addresses: dict[str, str] = {}
    exit_codes: list[int] = []
    for generation in (1, 2):
        config = scratch / f"persistent-{generation}.yaml"
        dns_port = reserve_port()
        render_config(
            config,
            mixed_port=reserve_port(),
            dns_port=dns_port,
            upstream_port=authority.server_address[1],
            store=True,
        )
        process, stdout, stderr = launch(binary, config, scratch)
        try:
            wait_dns_ready(process, dns_port)
            time.sleep(0.1)
            if generation == 1:
                names = ["persist-one.phase4.test", "persist-two.phase4.test"]
            else:
                names = ["persist-one.phase4.test", "persist-three.phase4.test"]
            for index, name in enumerate(names):
                response = fake_address(
                    dns_port, name, 1, 0x7000 + generation * 10 + index
                )
                addresses[f"g{generation}-{name}"] = response["records"][0]["data"]
            time.sleep(0.1)
            exit_codes.append(stop(process))
        finally:
            if process.poll() is None:
                stop(process)
            stdout.close()
            stderr.close()
    return {"addresses": addresses, "exit-codes": exit_codes}


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    interface_ip = local_interface_ip() or "192.0.2.42"
    authority_state = AuthorityState(interface_ip)
    authority = AuthorityServer(("127.0.0.1", 0), AuthorityHandler)
    authority.state = authority_state  # type: ignore[attr-defined]
    authority_thread = threading.Thread(target=authority.serve_forever, daemon=True)
    authority_thread.start()

    echo: AllInterfacesServer | None = None
    echo_thread: threading.Thread | None = None
    if local_interface_ip() is not None:
        echo = AllInterfacesServer(("0.0.0.0", 0), EchoHandler)
        echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
        echo_thread.start()

    try:
        result = {
            "basic": exercise_basic(binary, scratch / "basic", authority),
            "reverse": exercise_reverse(binary, scratch / "reverse", authority, echo),
            "whitelist": exercise_whitelist(binary, scratch / "whitelist", authority),
            "pool": exercise_cycle_and_capacity(binary, scratch / "pool", authority),
            "persistence": exercise_persistence(
                binary, scratch / "persistence", authority
            ),
        }
        result["upstream-questions"] = authority_state.snapshot()
        return result
    finally:
        authority.shutdown()
        authority.server_close()
        authority_thread.join(timeout=IO_DEADLINE)
        if echo is not None:
            echo.shutdown()
            echo.server_close()
        if echo_thread is not None:
            echo_thread.join(timeout=IO_DEADLINE)


def main() -> None:
    # The pinned Go parser removes the configured IPv6 fake-IP range when the
    # host has no global-unicast IPv6 interface. Use its documented test escape
    # hatch so this explicit dual-stack fixture has identical semantics on
    # developer machines and IPv4-only CI runners.
    os.environ["SKIP_SYSTEM_IPV6_CHECK"] = "1"
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4c-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations: dict[str, Any] = {}
        for implementation, binary in binaries.items():
            scratch = root / implementation
            scratch.mkdir()
            observations[implementation] = {
                "config": validation(binary, scratch),
                "runtime": exercise(binary, scratch / "run"),
            }
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4C mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4C Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

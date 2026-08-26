#!/usr/bin/env python3
"""Go/Rust differential suite for Phase 4F2 classic DNS upstreams."""

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

from phase1 import IO_DEADLINE, reserve_port
from phase4 import (
    build_binaries,
    dns_query,
    dns_question_end,
    launch,
    observe_response,
    recv_exact,
    stop,
    wait_dns_ready,
)


ROOT = pathlib.Path(__file__).resolve().parents[2]
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f2-diff.json"


class AuthorityState:
    def __init__(
        self,
        mode: str,
        *,
        address: str = "192.0.2.42",
        delay: float = 0.0,
    ) -> None:
        self.mode = mode
        self.address = address
        self.delay = delay
        self.lock = threading.Lock()
        self.counts = {"udp": 0, "tcp": 0}
        self.first_received: float | None = None

    def receive(self, transport: str) -> None:
        with self.lock:
            self.counts[transport] += 1
            if self.first_received is None:
                self.first_received = time.monotonic()

    def answer(self, query: bytes, transport: str) -> bytes | None:
        self.receive(transport)
        if self.mode == "blackhole":
            return None
        if self.delay:
            time.sleep(self.delay)
        end = dns_question_end(query)
        if self.mode == "servfail":
            return query[:2] + b"\x81\x82\x00\x01\x00\x00\x00\x00\x00\x00" + query[12:end]
        if self.mode == "truncated" and transport == "udp":
            return query[:2] + b"\x83\x80\x00\x01\x00\x00\x00\x00\x00\x00" + query[12:end]
        address = "127.0.0.1" if self.mode == "bootstrap" else self.address
        answer = (
            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04"
            + socket.inet_aton(address)
        )
        return (
            query[:2]
            + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            + query[12:end]
            + answer
        )

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return dict(self.counts)


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, server_socket = self.request
        state: AuthorityState = self.server.state  # type: ignore[attr-defined]
        response = state.answer(query, "udp")
        if response is not None:
            server_socket.sendto(response, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        state: AuthorityState = self.server.state  # type: ignore[attr-defined]
        while True:
            try:
                length = int.from_bytes(recv_exact(self.request, 2), "big")
                query = recv_exact(self.request, length)
            except (EOFError, OSError):
                return
            response = state.answer(query, "tcp")
            if response is None:
                time.sleep(IO_DEADLINE)
                return
            self.request.sendall(len(response).to_bytes(2, "big") + response)


class LocalAuthority:
    def __init__(
        self,
        mode: str,
        *,
        address: str = "192.0.2.42",
        delay: float = 0.0,
    ) -> None:
        self.state = AuthorityState(mode, address=address, delay=delay)
        self.tcp = TCPServer(("127.0.0.1", 0), TCPHandler)
        self.port = self.tcp.server_address[1]
        self.udp = UDPServer(("127.0.0.1", self.port), UDPHandler)
        self.tcp.state = self.state  # type: ignore[attr-defined]
        self.udp.state = self.state  # type: ignore[attr-defined]
        self.threads = [
            threading.Thread(target=self.tcp.serve_forever, daemon=True),
            threading.Thread(target=self.udp.serve_forever, daemon=True),
        ]
        for thread in self.threads:
            thread.start()

    def close(self) -> None:
        self.tcp.shutdown()
        self.udp.shutdown()
        self.tcp.server_close()
        self.udp.server_close()
        for thread in self.threads:
            thread.join(timeout=IO_DEADLINE)


def config_text(
    dns_port: int,
    nameservers: list[str],
    *,
    default_nameserver: str | None = None,
) -> str:
    nameserver_lines = "\n".join(f"    - {server}" for server in nameservers)
    default = (
        f"\n  default-nameserver:\n    - {default_nameserver}"
        if default_nameserver is not None
        else ""
    )
    return f"""mixed-port: {reserve_port()}
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
{nameserver_lines}{default}
rules:
  - MATCH,DIRECT
"""


def observe_or_failure(response: bytes, identifier: int) -> dict[str, Any]:
    if int.from_bytes(response[6:8], "big"):
        return observe_response(response, identifier)
    return {
        "id-echoed": int.from_bytes(response[:2], "big") == identifier,
        "flags": response[2:4].hex(),
        "questions": int.from_bytes(response[4:6], "big"),
        "answers": int.from_bytes(response[6:8], "big"),
    }


def local_udp_query(port: int, query: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(8.0)
        client.sendto(query, ("127.0.0.1", port))
        response, source = client.recvfrom(65535)
        if source[1] != port:
            raise AssertionError(f"unexpected DNS UDP source {source}")
        return response


def run_query(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    nameservers: list[str],
    name: str,
    identifier: int,
    *,
    default_nameserver: str | None = None,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        config_text(
            dns_port,
            nameservers,
            default_nameserver=default_nameserver,
        )
    )
    process, stdout, stderr = launch(binary, config, scratch)
    started = time.monotonic()
    try:
        wait_dns_ready(process, dns_port)
        response = local_udp_query(dns_port, dns_query(name, identifier))
        elapsed = time.monotonic() - started
        time.sleep(0.1)
        return {
            "response": observe_or_failure(response, identifier),
            "duration": "five-second" if 4.5 <= elapsed <= 6.5 else "prompt",
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    scratch.mkdir(parents=True, exist_ok=True)
    port = reserve_port()
    cases = {
        "multiple-classic": config_text(
            reserve_port(),
            [f"udp://127.0.0.1:{port}", f"tcp://127.0.0.1:{reserve_port()}"],
        ),
        "domain-bootstrap": config_text(
            reserve_port(),
            [f"udp://resolver.phase4.test:{port}"],
            default_nameserver=f"udp://127.0.0.1:{reserve_port()}",
        ),
        "non-loopback-ip": config_text(
            reserve_port(), ["udp://192.0.2.1:53"]
        ),
        "empty": config_text(reserve_port(), []),
    }
    results = {}
    for name, source in cases.items():
        path = scratch / f"{name}.yaml"
        path.write_text(source)
        results[name] = subprocess.run(
            [str(binary), "-t", "-f", str(path)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
    return results


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authorities: list[LocalAuthority] = []
    try:
        slow = LocalAuthority("answer", address="192.0.2.41", delay=1.0)
        fast = LocalAuthority("answer", address="192.0.2.42", delay=0.05)
        authorities.extend([slow, fast])
        parallel = run_query(
            binary,
            scratch / "parallel",
            [f"udp://127.0.0.1:{slow.port}", f"udp://127.0.0.1:{fast.port}"],
            "parallel.phase4.test",
            0xF301,
        )
        parallel["authorities"] = {
            "slow": slow.state.snapshot(),
            "fast": fast.state.snapshot(),
            "started-together": slow.state.first_received is not None
            and fast.state.first_received is not None
            and abs(slow.state.first_received - fast.state.first_received) < 0.25,
        }

        failed_port = reserve_port()
        failover_authority = LocalAuthority("answer", address="192.0.2.43")
        authorities.append(failover_authority)
        failover = run_query(
            binary,
            scratch / "failover",
            [
                f"tcp://127.0.0.1:{failed_port}",
                f"udp://127.0.0.1:{failover_authority.port}",
            ],
            "failover.phase4.test",
            0xF302,
        )
        failover["winner"] = failover_authority.state.snapshot()

        failing = LocalAuthority("servfail")
        healthy = LocalAuthority("answer", address="192.0.2.44", delay=0.05)
        authorities.extend([failing, healthy])
        rcode_failover = run_query(
            binary,
            scratch / "rcode-failover",
            [f"udp://127.0.0.1:{failing.port}", f"udp://127.0.0.1:{healthy.port}"],
            "rcode-failover.phase4.test",
            0xF303,
        )
        rcode_failover["queried"] = {
            "failing": failing.state.snapshot()["udp"] > 0,
            "healthy": healthy.state.snapshot()["udp"] > 0,
        }

        truncated = LocalAuthority("truncated", address="192.0.2.45")
        authorities.append(truncated)
        tc_retry = run_query(
            binary,
            scratch / "tc-retry",
            [f"udp://127.0.0.1:{truncated.port}"],
            "tc-retry.phase4.test",
            0xF304,
        )
        tc_retry["authority"] = truncated.state.snapshot()

        tcp = LocalAuthority("answer", address="192.0.2.46")
        authorities.append(tcp)
        tcp_direct = run_query(
            binary,
            scratch / "tcp-direct",
            [f"tcp://127.0.0.1:{tcp.port}"],
            "tcp-direct.phase4.test",
            0xF305,
        )
        tcp_direct["authority"] = tcp.state.snapshot()

        bootstrap_udp = LocalAuthority("bootstrap")
        domain_udp = LocalAuthority("answer", address="192.0.2.47")
        authorities.extend([bootstrap_udp, domain_udp])
        domain_udp_result = run_query(
            binary,
            scratch / "domain-udp",
            [f"udp://resolver-udp.phase4.test:{domain_udp.port}"],
            "domain-udp.phase4.test",
            0xF306,
            default_nameserver=f"udp://127.0.0.1:{bootstrap_udp.port}",
        )
        domain_udp_result["bootstrap"] = bootstrap_udp.state.snapshot()
        domain_udp_result["target"] = domain_udp.state.snapshot()

        bootstrap_tcp = LocalAuthority("bootstrap")
        domain_tcp = LocalAuthority("answer", address="192.0.2.48")
        authorities.extend([bootstrap_tcp, domain_tcp])
        domain_tcp_result = run_query(
            binary,
            scratch / "domain-tcp",
            [f"tcp://resolver-tcp.phase4.test:{domain_tcp.port}"],
            "domain-tcp.phase4.test",
            0xF307,
            default_nameserver=f"udp://127.0.0.1:{bootstrap_tcp.port}",
        )
        domain_tcp_result["bootstrap"] = bootstrap_tcp.state.snapshot()
        domain_tcp_result["target"] = domain_tcp.state.snapshot()

        blackhole = LocalAuthority("blackhole")
        authorities.append(blackhole)
        timeout = run_query(
            binary,
            scratch / "timeout",
            [f"udp://127.0.0.1:{blackhole.port}"],
            "timeout.phase4.test",
            0xF308,
        )
        timeout["authority-contacted"] = blackhole.state.snapshot()["udp"] > 0

        return {
            "config": validation(binary, scratch / "validation"),
            "parallel": parallel,
            "connection-failover": failover,
            "rcode-failover": rcode_failover,
            "udp-tc-retry": tc_retry,
            "tcp-direct": tcp_direct,
            "domain-udp": domain_udp_result,
            "domain-tcp": domain_tcp_result,
            "timeout": timeout,
        }
    finally:
        for authority in authorities:
            authority.close()


def address(case: dict[str, Any]) -> str | None:
    return case["response"].get("address")


def satisfies_contract(observation: dict[str, Any]) -> bool:
    return (
        observation["config"]
        == {
            "multiple-classic": 0,
            "domain-bootstrap": 0,
            "non-loopback-ip": 0,
            "empty": 1,
        }
        and address(observation["parallel"]) == "192.0.2.42"
        and observation["parallel"]["authorities"]
        == {
            "slow": {"udp": 1, "tcp": 0},
            "fast": {"udp": 1, "tcp": 0},
            "started-together": True,
        }
        and address(observation["connection-failover"]) == "192.0.2.43"
        and observation["connection-failover"]["winner"] == {"udp": 1, "tcp": 0}
        and address(observation["rcode-failover"]) == "192.0.2.44"
        and observation["rcode-failover"]["queried"]
        == {"failing": True, "healthy": True}
        and address(observation["udp-tc-retry"]) == "192.0.2.45"
        and observation["udp-tc-retry"]["authority"] == {"udp": 1, "tcp": 1}
        and address(observation["tcp-direct"]) == "192.0.2.46"
        and observation["tcp-direct"]["authority"] == {"udp": 0, "tcp": 1}
        and address(observation["domain-udp"]) == "192.0.2.47"
        and observation["domain-udp"]["bootstrap"] == {"udp": 1, "tcp": 0}
        and observation["domain-udp"]["target"] == {"udp": 1, "tcp": 0}
        and address(observation["domain-tcp"]) == "192.0.2.48"
        and observation["domain-tcp"]["bootstrap"] == {"udp": 1, "tcp": 0}
        and observation["domain-tcp"]["target"] == {"udp": 0, "tcp": 1}
        and observation["timeout"]["response"].get("flags") == "8102"
        and observation["timeout"]["duration"] == "five-second"
        and observation["timeout"]["authority-contacted"] is True
        and all(
            case["exit-code"] == 0
            for name, case in observation.items()
            if name != "config"
        )
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f2-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: exercise(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if observations["go"] != observations["rust"] or not satisfies_contract(
            observations["go"]
        ):
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4F2 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F2 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

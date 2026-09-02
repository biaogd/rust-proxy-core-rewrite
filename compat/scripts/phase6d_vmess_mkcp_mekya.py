#!/usr/bin/env python3
"""Go/Rust differential for Phase 6D-K/L VMess mKCP and Mekya TCP."""

from __future__ import annotations

import json
import pathlib
import select
import socket
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, connect_domain, debug_files
from phase6d_vmess_tcp import UUID, build_authority, exchange, start_authority
from phase6d_vmess_websocket import LARGE_PAYLOAD, trusted_roots


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6d-vmess-mkcp-mekya-diff.json"


def reserve_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def decode_simple_segment(packet: bytes) -> tuple[int, int | None, list[int]] | None:
    original = len(packet)
    plain = bytearray(packet)
    plain.extend(b"\0" * ((4 - original % 4) % 4))
    for index in range(len(plain) - 1, 3, -1):
        plain[index] ^= plain[index - 4]
    del plain[original:]
    if len(plain) < 10:
        return None
    length = int.from_bytes(plain[4:6], "big")
    payload = plain[6:]
    if len(payload) != length or len(payload) < 4:
        return None
    command = payload[2]
    if command == 1 and len(payload) >= 18:
        return command, int.from_bytes(payload[8:12], "big"), []
    if command == 0 and len(payload) >= 17:
        count = payload[16]
        end = 17 + count * 4
        if len(payload) < end:
            return None
        numbers = [
            int.from_bytes(payload[offset : offset + 4], "big")
            for offset in range(17, end, 4)
        ]
        return command, None, numbers
    return command, None, []


class SemanticUdpFaultRelay:
    """Applies repeatable faults to unseeded/no-header mKCP segments."""

    def __init__(self, authority_port: int, drop_modulus: int) -> None:
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(("127.0.0.1", 0))
        self.back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.back.connect(("127.0.0.1", authority_port))
        self.port = int(self.front.getsockname()[1])
        self.drop_modulus = drop_modulus
        self.client: tuple[str, int] | None = None
        self.attempts: dict[tuple[str, int], int] = {}
        self.dropped: set[tuple[str, int]] = set()
        self.ack_dropped = False
        self.duplicated = False
        self.reordered = False
        self.held: bytes | None = None
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.stopping.set()
        self.front.close()
        self.back.close()
        self.thread.join(timeout=2)

    def run(self) -> None:
        while not self.stopping.is_set():
            try:
                ready, _, _ = select.select([self.front, self.back], [], [], 0.05)
                for source in ready:
                    if source is self.front:
                        packet, self.client = self.front.recvfrom(65_535)
                        self.forward("c2s", packet)
                    else:
                        self.forward("s2c", self.back.recv(65_535))
            except (OSError, ValueError):
                return

    def send(self, direction: str, packet: bytes) -> None:
        if direction == "c2s":
            self.back.send(packet)
        elif self.client is not None:
            self.front.sendto(packet, self.client)

    def forward(self, direction: str, packet: bytes) -> None:
        decoded = decode_simple_segment(packet)
        if decoded is None:
            self.send(direction, packet)
            return
        command, number, acknowledgements = decoded
        if command == 1 and number is not None:
            key = (direction, number)
            attempt = self.attempts.get(key, 0) + 1
            self.attempts[key] = attempt
            if attempt == 1 and number % self.drop_modulus == 3 % self.drop_modulus:
                self.dropped.add(key)
                return
            if direction == "c2s" and number == 6 and attempt == 1:
                self.send(direction, packet)
                self.send(direction, packet)
                self.duplicated = True
                return
            if direction == "c2s" and number == 8 and attempt == 1:
                self.held = packet
                return
            if direction == "c2s" and number == 9 and attempt == 1 and self.held is not None:
                self.send(direction, packet)
                self.send(direction, self.held)
                self.held = None
                self.reordered = True
                return
        if direction == "s2c" and command == 0 and 3 in acknowledgements and not self.ack_dropped:
            self.ack_dropped = True
            return
        self.send(direction, packet)

    def result(self) -> dict[str, bool | int]:
        retransmitted = all(self.attempts.get(key, 0) >= 2 for key in self.dropped)
        maximum_attempts = max(self.attempts.values(), default=0)
        return {
            "semantic-data-loss": bool(self.dropped),
            "all-dropped-data-retransmitted": retransmitted,
            "ack-loss": self.ack_dropped,
            "duplicate-data": self.duplicated,
            "reordered-data": self.reordered,
            # The pinned Go oracle reaches the 70s under this compounded DATA +
            # ACK fault schedule. Keep a coarse leak/runaway guard instead of
            # treating runtime scheduling as a wire-semantic difference.
            "bounded-retransmission": maximum_attempts <= 128,
        }


def record(name: str, port: int, network: str, options: str, *, tls: bool = False) -> str:
    tls_fields = ""
    if tls:
        tls_fields = "    tls: true\n    servername: dot.phase4.test\n"
    return f"""  - name: {name}
    type: vmess
    server: 127.0.0.1
    port: {port}
    uuid: {UUID}
    alterId: 0
    cipher: auto
    network: {network}
{tls_fields}{options}"""


def wait_exchange(
    process: Any,
    mixed_port: int,
    host: str,
    port: int,
    payload: bytes,
    *,
    half_close: bool = False,
) -> bool:
    deadline = time.monotonic() + max(IO_DEADLINE, 15)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during VMess transport readiness: {process.returncode}")
        try:
            if exchange(mixed_port, host, port, payload, half_close=half_close):
                return True
        except (AssertionError, EOFError, OSError):
            pass
        time.sleep(0.05)
    raise TimeoutError(f"VMess transport route {host}:{port} did not become ready")


def observations(paths: list[pathlib.Path], expected: set[str]) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        seen = {
            line.strip()
            for path in paths
            for line in path.read_text(errors="replace").splitlines()
            if line.startswith("CONNECT ")
        }
        if expected <= seen:
            return sorted(expected)
        time.sleep(0.02)
    raise TimeoutError(f"missing authority observations: {sorted(expected - seen)}")


def half_close_outcomes(mixed_port: int, host: str, port: int) -> dict[str, int]:
    outcomes: dict[str, int] = {}
    for _ in range(10):
        outcome = "unexpected"
        try:
            with connect_domain(mixed_port, host, port) as stream:
                stream.settimeout(2)
                payload = b"phase6d-transport-half-close" * 32
                stream.sendall(payload)
                stream.shutdown(socket.SHUT_WR)
                try:
                    outcome = "echo" if recv_exact(stream, len(payload)) == payload else "mismatch"
                except EOFError:
                    outcome = "eof"
                except socket.timeout:
                    outcome = "timeout"
                except (BrokenPipeError, ConnectionResetError):
                    outcome = "reset"
        except (AssertionError, EOFError, OSError):
            outcome = "connect-error"
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
    return outcomes


def peer_close_outcomes(mixed_port: int, host: str, port: int) -> dict[str, int]:
    outcomes: dict[str, int] = {}
    for _ in range(3):
        outcome = "unexpected"
        try:
            with connect_domain(mixed_port, host, port) as stream:
                stream.settimeout(6)
                try:
                    response = recv_exact(stream, len(b"server-close"))
                    ending = stream.recv(1)
                    outcome = "payload-eof" if response == b"server-close" and ending == b"" else "mismatch"
                except EOFError:
                    outcome = "early-eof"
                except socket.timeout:
                    outcome = "timeout"
                except (BrokenPipeError, ConnectionResetError):
                    outcome = "reset"
        except (AssertionError, EOFError, OSError):
            outcome = "connect-error"
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
    return outcomes


def exercise(binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    mkcp_specs = [
        ("default", "", ""),
        ("seed", "phase6d-k-seed", ""),
        ("srtp", "", "srtp"),
        ("utp", "phase6d-k-utp", "utp"),
        ("wechat", "", "wechat-video"),
        ("dtls", "phase6d-k-dtls", "dtls"),
        ("wireguard", "", "wireguard"),
    ]
    authority_handles = []
    authority_logs: list[pathlib.Path] = []
    fault_relays: list[SemanticUdpFaultRelay] = []
    records = []
    rules = []
    expected = set()
    route_port = 28600
    for index, (name, seed, header) in enumerate(mkcp_specs):
        port = reserve_udp_port()
        handle = start_authority(
            authority,
            scratch,
            port,
            log_name=f"authority-mkcp-{name}",
            transport="mkcp",
            mkcp_seed=seed,
            mkcp_header=header,
        )
        authority_handles.append(handle[:3])
        authority_logs.append(handle[3])
        options = "    mkcp-opts:\n      tti: 15\n"
        if seed:
            options += f"      seed: {seed}\n"
        if header:
            options += f"      header: {header}\n"
        records.append(record(f"vmess-mkcp-{name}", port, "mkcp", options))
        target_port = route_port + index
        rules.append(f"  - DST-PORT,{target_port},vmess-mkcp-{name}\n")
        expected.add(f"CONNECT mkcp-{name}.phase6d:{target_port}")

    fault_specs = [
        ("moderate-off", False, 7),
        ("moderate-on", True, 7),
        ("heavy-off", False, 4),
        ("heavy-on", True, 4),
    ]
    for index, (name, congestion, drop_modulus) in enumerate(fault_specs):
        authority_port = reserve_udp_port()
        handle = start_authority(
            authority,
            scratch,
            authority_port,
            log_name=f"authority-mkcp-loss-{name}",
            transport="mkcp",
        )
        authority_handles.append(handle[:3])
        authority_logs.append(handle[3])
        relay = SemanticUdpFaultRelay(authority_port, drop_modulus)
        relay.start()
        fault_relays.append(relay)
        options = f"""    mkcp-opts:
      tti: 15
      congestion: {str(congestion).lower()}
"""
        records.append(record(f"vmess-mkcp-loss-{name}", relay.port, "mkcp", options))
        target_port = 28800 + index
        rules.append(f"  - DST-PORT,{target_port},vmess-mkcp-loss-{name}\n")
        expected.add(f"CONNECT mkcp-loss-{name}.phase6d:{target_port}")

    for index, alpn in enumerate(("h2", "http/1.1")):
        name = "h2" if alpn == "h2" else "h1"
        port = reserve_port()
        handle = start_authority(
            authority,
            scratch,
            port,
            log_name=f"authority-mekya-{name}",
            transport="mekya",
            certificate=pathlib.Path(SERVER_CERTIFICATE),
            private_key=pathlib.Path(SERVER_KEY),
            mkcp_seed=f"phase6d-l-{name}",
            mkcp_header="srtp" if name == "h2" else "",
            mekya_alpn=alpn,
        )
        authority_handles.append(handle[:3])
        authority_logs.append(handle[3])
        options = f"""    mekya-opts:
      url: https://127.0.0.1:{port}/mekya
      h2-pool-size: 2
      max-write-delay: 20
      max-request-size: 96000
      polling-interval-initial: 20
      max-write-size: 1048576
      max-write-duration-ms: 5000
      max-simultaneous-write-connection: 16
      packet-writing-buffer: 1024
      kcp:
        tti: 15
        seed: phase6d-l-{name}
"""
        if name == "h2":
            options += "        header: srtp\n"
        records.append(record(f"vmess-mekya-{name}", port, "mekya", options, tls=True))
        target_port = 28700 + index
        rules.append(f"  - DST-PORT,{target_port},vmess-mekya-{name}\n")
        expected.add(f"CONNECT mekya-{name}.phase6d:{target_port}")

    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        trusted_roots()
        + f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
{''.join(records)}rules:
{''.join(rules)}  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        matrix: dict[str, bool] = {}
        for index, (name, _, _) in enumerate(mkcp_specs):
            payload = LARGE_PAYLOAD if name in {"seed", "dtls"} else f"mkcp-{name}".encode()
            matrix[f"mkcp-{name}"] = wait_exchange(
                process,
                mixed_port,
                f"mkcp-{name}.phase6d",
                route_port + index,
                payload,
            )
        matrix["mekya-h2"] = wait_exchange(
            process, mixed_port, "mekya-h2.phase6d", 28700, LARGE_PAYLOAD
        )
        matrix["mekya-h1"] = wait_exchange(
            process,
            mixed_port,
            "mekya-h1.phase6d",
            28701,
            b"mekya-http1",
        )
        loss: dict[str, dict[str, bool | int]] = {}
        loss_payload = bytes((index * 37) & 0xFF for index in range(512 * 1024))
        for index, (name, _, _) in enumerate(fault_specs):
            matrix[f"mkcp-loss-{name}"] = wait_exchange(
                process,
                mixed_port,
                f"mkcp-loss-{name}.phase6d",
                28800 + index,
                loss_payload,
            )
            loss[name] = fault_relays[index].result()
        half_close = {
            "mkcp": half_close_outcomes(mixed_port, "eof-response.mkcp.phase6d", route_port),
            "mekya-h2": half_close_outcomes(
                mixed_port, "eof-response.mekya-h2.phase6d", 28700
            ),
            "mekya-h1": half_close_outcomes(
                mixed_port, "eof-response.mekya-h1.phase6d", 28701
            ),
        }
        peer_close = {
            "mkcp": peer_close_outcomes(mixed_port, "server-close.mkcp.phase6d", route_port),
            "mekya-h2": peer_close_outcomes(
                mixed_port, "server-close.mekya-h2.phase6d", 28700
            ),
            "mekya-h1": peer_close_outcomes(
                mixed_port, "server-close.mekya-h1.phase6d", 28701
            ),
        }
        return {
            "matrix": matrix,
            "half-close": half_close,
            "peer-close": peer_close,
            "loss": loss,
            "authority": observations(authority_logs, expected),
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        for authority_process, authority_stdout, authority_stderr in authority_handles:
            stop(authority_process)
            authority_stdout.close()
            authority_stderr.close()
        for relay in fault_relays:
            relay.close()


def contract_errors(name: str, result: dict[str, Any]) -> list[str]:
    errors = []
    for route, passed in result["matrix"].items():
        if not passed:
            errors.append(f"{name}: route {route} did not preserve the payload")
    for route, evidence in result["loss"].items():
        for invariant, passed in evidence.items():
            if not passed:
                errors.append(f"{name}: loss route {route} did not prove {invariant}")
    for transport, outcomes in result["half-close"].items():
        if outcomes != {"eof": 10}:
            errors.append(f"{name}: {transport} half-close outcomes were {outcomes!r}")
    for transport, outcomes in result["peer-close"].items():
        if outcomes != {"payload-eof": 3}:
            errors.append(f"{name}: {transport} peer-close outcomes were {outcomes!r}")
    if not result["process-alive"]:
        errors.append(f"{name}: proxy exited before the fixture completed")
    return errors


def main() -> int:
    result: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6d-vmess-mkcp-mekya-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6DKL_CARGO_TARGET", "phase6d-kl-vmess")
        authority = build_authority(root)
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                result[name] = exercise(binary, authority, scratch)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "error": f"{type(error).__name__}: {error}",
                        "observations": result,
                        "debug": debug_files(root),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            raise
    errors = [
        error
        for name, observations in result.items()
        for error in contract_errors(name, observations)
    ]
    if result["go"] != result["rust"] or errors:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {"contract-errors": errors, "observations": result},
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6D-K/L VMess mKCP and Mekya differential passed")
    print(json.dumps(result["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

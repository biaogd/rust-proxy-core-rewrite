#!/usr/bin/env python3
"""HY2-B Brutal send-rate differential (Go vs Rust).

Echo success alone is not Brutal parity. With a low configured `up` and enough
RTT that Quinn's window-derived pacer can express the rate (queued delay relay),
both stacks must keep measured TCP goodput near the configured rate — not race
to line rate.

Quinn lacks Go's independent Brutal pacer; Rust approximates via a
1.25-compensated congestion window (documented in congestion.rs). This gate
fails if either side is uncapped or starved.
"""

from __future__ import annotations

import json
import pathlib
import select
import socket
import tempfile
import threading
import time
from typing import Any

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    recv_exact,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files
from phase5d_streams import SECRET, wait_controller
from phase_hy2b_hysteria2 import hy2_record, start_authority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-hy2b-brutal-rate-diff.json"
PASSWORD = "phase-hy2b-password"  # must match phase_hy2b_hysteria2.PASSWORD
# 1 Mbps with ~25 ms one-way queued delay → RTT ~50 ms; window ≫ MTU.
UP = "1 Mbps"
UP_BPS = 1_000_000 / 8  # bytes/sec
DOWN = "10 Mbps"
PAYLOAD = b"B" * 32_768
ROUNDS = 12
RELAY_DELAY_MS = 25.0
CAP_MULTIPLIER = 4.0
MIN_GOODPUT_FRACTION = 0.10


class QueuedDelayRelay:
    """Per-packet delay without blocking the receive loop (unlike sleep-per-forward)."""

    def __init__(self, listen_port: int, target_port: int, delay_ms: float) -> None:
        self.listen_port = listen_port
        self.target_port = target_port
        self.delay_s = delay_ms / 1000.0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)

    def _run(self) -> None:
        listen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen.bind(("127.0.0.1", self.listen_port))
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(("127.0.0.1", 0))
        listen.setblocking(False)
        upstream.setblocking(False)
        client_addr: tuple[str, int] | None = None
        pending: list[tuple[float, str, bytes]] = []
        try:
            while not self._stop.is_set():
                now = time.monotonic()
                remain: list[tuple[float, str, bytes]] = []
                for due, direction, data in pending:
                    if now < due:
                        remain.append((due, direction, data))
                        continue
                    if direction == "up":
                        upstream.sendto(data, ("127.0.0.1", self.target_port))
                    elif client_addr is not None:
                        listen.sendto(data, client_addr)
                pending = remain
                readable, _, _ = select.select([listen, upstream], [], [], 0.005)
                if listen in readable:
                    data, addr = listen.recvfrom(65_535)
                    client_addr = addr
                    pending.append((now + self.delay_s, "up", data))
                if upstream in readable:
                    data, _ = upstream.recvfrom(65_535)
                    pending.append((now + self.delay_s, "down", data))
        finally:
            listen.close()
            upstream.close()


def rate_class(measured_bps: float) -> str:
    if measured_bps <= 0:
        return "starved"
    if measured_bps > UP_BPS * CAP_MULTIPLIER:
        return "uncapped"
    if measured_bps < UP_BPS * MIN_GOODPUT_FRACTION:
        return "starved"
    return "capped"


def measure_upload(mixed_port: int, echo_port: int) -> dict[str, Any]:
    ok = 0
    started = time.monotonic()
    for _ in range(ROUNDS):
        try:
            with connect_domain(mixed_port, "127.0.0.1", echo_port) as stream:
                stream.settimeout(max(IO_DEADLINE, 30.0))
                stream.sendall(PAYLOAD)
                if recv_exact(stream, len(PAYLOAD)) == PAYLOAD:
                    ok += 1
        except (AssertionError, EOFError, OSError, TimeoutError):
            continue
    elapsed = max(time.monotonic() - started, 1e-3)
    measured = (ok * len(PAYLOAD)) / elapsed
    return {
        "rounds-ok": ok,
        "rounds": ROUNDS,
        "measured-bps": int(measured),
        "configured-up-bps": int(UP_BPS),
        "rate-class": rate_class(measured),
    }


def wait_exchange(process, mixed_port: int, echo_port: int, payload: bytes) -> None:
    deadline = time.monotonic() + 25.0
    while True:
        try:
            with connect_domain(mixed_port, "127.0.0.1", echo_port) as stream:
                stream.settimeout(10.0)
                stream.sendall(payload)
                assert recv_exact(stream, len(payload)) == payload
            return
        except (AssertionError, EOFError, OSError, TimeoutError):
            if process.poll() is not None or time.monotonic() >= deadline:
                raise
            time.sleep(0.3)


def exercise(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    authority_port = reserve_port()
    front_port = reserve_port()
    authority_scratch = scratch / "authority"
    authority_scratch.mkdir()
    authority, a_out, a_err = start_authority(
        authority_binary,
        authority_scratch,
        authority_port,
        up=UP,
        down=DOWN,
    )
    time.sleep(0.4)
    if authority.poll() is not None:
        raise RuntimeError("authority exited early")

    relay = QueuedDelayRelay(front_port, authority_port, RELAY_DELAY_MS)
    relay.start()
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: true
proxies:
{hy2_record("hy2", front_port, password=PASSWORD, up=UP, down=DOWN)}proxy-groups:
  - name: hy2-select
    type: select
    proxies: [hy2]
    default-selected: hy2
rules:
  - MATCH,hy2-select
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_exchange(process, mixed_port, echo.port, b"warm")
        time.sleep(0.3)
        measured = measure_upload(mixed_port, echo.port)
        return {
            **measured,
            "process-alive": process.poll() is None,
            "relay-delay-ms": RELAY_DELAY_MS,
        }
    finally:
        for stopper in (
            lambda: stop(process),
            relay.stop,
            lambda: stop(authority),
        ):
            try:
                stopper()
            except Exception:
                pass
        stdout.close()
        stderr.close()
        a_out.close()
        a_err.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-hy2b-brutal-rate-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE_HY2B_BRUTAL_RATE_CARGO_TARGET", "phase-hy2b-brutal-rate"
        )
        try:
            for engine in ("rust", "go"):
                scratch = root / engine
                scratch.mkdir()
                observations[engine] = exercise(
                    binaries[engine], binaries["go"], scratch
                )
                if observations[engine]["rate-class"] != "capped":
                    raise AssertionError(
                        f"{engine} Brutal rate class "
                        f"{observations[engine]['rate-class']!r} "
                        f"(measured={observations[engine]['measured-bps']} "
                        f"configured={int(UP_BPS)})"
                    )
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "error": f"{type(error).__name__}: {error}",
                        "observations": observations,
                        "debug": debug_files(root),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            raise

    go = {
        "rate-class": observations["go"]["rate-class"],
        "process-alive": observations["go"]["process-alive"],
    }
    rust = {
        "rate-class": observations["rust"]["rate-class"],
        "process-alive": observations["rust"]["process-alive"],
    }
    if go != rust:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(observations, indent=2, sort_keys=True)
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("HY2-B Brutal rate differential passed")
    print(json.dumps(observations, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

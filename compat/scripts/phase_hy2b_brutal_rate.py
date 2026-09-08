#!/usr/bin/env python3
"""HY2-B Brutal send-rate differential (Go vs Rust).

Measures sustained **unidirectional client upload** at a TCP sink (no echo
return path). Server bandwidth is set high and numeric so the observed cap
cannot be blamed on server send limits or `CC-RX: auto` → BBR.

Positive case: client `up: 1 Mbps` must stay near the configured rate.
Negative control: client without `up` must be **uncapped** on the same path —
if that control is misclassified as capped, the assertion is not client-side.
"""

from __future__ import annotations

import json
import pathlib
import select
import socket
import socketserver
import tempfile
import threading
import time
from typing import Any

from phase1 import (
    ROOT,
    reserve_port,
    wait_ready,
)
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files
from phase5d_streams import SECRET, wait_controller
from phase_hy2b_hysteria2 import hy2_record, start_authority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-hy2b-brutal-rate-diff.json"
PASSWORD = "phase-hy2b-password"  # must match phase_hy2b_hysteria2.PASSWORD
UP = "1 Mbps"
UP_BPS = 1_000_000 / 8  # bytes/sec
# High numeric server Rx keeps the client on Brutal (avoids CC-RX: auto → BBR)
# without becoming the upload bottleneck for a 1 Mbps client `up`.
SERVER_BW = "100 Mbps"
CLIENT_DOWN = "100 Mbps"
# ~25 ms one-way queued delay → RTT ~50 ms; Quinn window ≫ MTU for 1 Mbps.
RELAY_DELAY_MS = 25.0
# Measure time for the sink to receive this many bytes (steady unidirectional).
MEASURE_BYTES = 256_000  # ~2.05 s at 1 Mbps
CHUNK = b"U" * 16_384
# Tight band around configured rate (not 0.1–4×).
CAP_MAX_MULTIPLIER = 2.0
CAP_MIN_FRACTION = 0.40
# Negative control must clearly exceed the configured Brutal rate.
UNCAP_MIN_MULTIPLIER = 3.0
MEASURE_TIMEOUT = 30.0


class CountingSinkHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(60.0)
        server = self.server
        assert isinstance(server, CountingSinkServer)
        try:
            while True:
                data = self.request.recv(65_536)
                if not data:
                    break
                with server.lock:
                    server.bytes_received += len(data)
                    server.progress.notify_all()
        except OSError:
            pass


class CountingSinkServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, CountingSinkHandler)
        self.lock = threading.Lock()
        self.progress = threading.Condition(self.lock)
        self.bytes_received = 0


def start_sink() -> tuple[CountingSinkServer, int]:
    server = CountingSinkServer(("127.0.0.1", 0))
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


class QueuedDelayRelay:
    """Per-packet delay without blocking the receive loop."""

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


def rate_class(measured_bps: float, *, expect_capped: bool) -> str:
    if measured_bps <= 0:
        return "starved"
    if expect_capped:
        if measured_bps > UP_BPS * CAP_MAX_MULTIPLIER:
            return "uncapped"
        if measured_bps < UP_BPS * CAP_MIN_FRACTION:
            return "starved"
        return "capped"
    if measured_bps >= UP_BPS * UNCAP_MIN_MULTIPLIER:
        return "uncapped"
    return "still-capped"


def measure_unidirectional_upload(
    mixed_port: int, sink: CountingSinkServer, sink_port: int
) -> dict[str, Any]:
    """Time how long the sink needs to receive MEASURE_BYTES (client upload)."""
    stop = threading.Event()
    send_error: list[BaseException] = []

    def sender() -> None:
        try:
            with connect_domain(mixed_port, "127.0.0.1", sink_port) as stream:
                stream.settimeout(MEASURE_TIMEOUT + 5.0)
                while not stop.is_set():
                    try:
                        stream.sendall(CHUNK)
                    except (BrokenPipeError, ConnectionResetError, OSError, TimeoutError):
                        break
                try:
                    stream.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        except BaseException as error:  # noqa: BLE001 — surface to waiter
            send_error.append(error)

    with sink.lock:
        sink.bytes_received = 0

    thread = threading.Thread(target=sender, daemon=True)
    thread.start()
    try:
        # Wait until the first byte reaches the sink (path ready), then mark.
        deadline = time.monotonic() + MEASURE_TIMEOUT
        with sink.progress:
            while sink.bytes_received < 1:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("sink received no upload bytes")
                sink.progress.wait(timeout=min(0.5, remaining))

            baseline = sink.bytes_received
            started = time.monotonic()
            target = baseline + MEASURE_BYTES
            while sink.bytes_received < target:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"sink only reached {sink.bytes_received - baseline} "
                        f"of {MEASURE_BYTES} bytes"
                    )
                sink.progress.wait(timeout=min(0.5, remaining))
            elapsed = max(time.monotonic() - started, 1e-3)
            received = sink.bytes_received - baseline
    finally:
        stop.set()
        thread.join(timeout=2.0)

    if send_error:
        raise send_error[0]

    return {
        "sink-bytes": received,
        "elapsed-secs": round(elapsed, 3),
        "measured-bps": int(received / elapsed),
        "configured-up-bps": int(UP_BPS),
    }


def wait_upload(process, mixed_port: int, sink_port: int, nbytes: int = 4096) -> None:
    deadline = time.monotonic() + 25.0
    payload = b"w" * nbytes
    while True:
        try:
            with connect_domain(mixed_port, "127.0.0.1", sink_port) as stream:
                stream.settimeout(10.0)
                stream.sendall(payload)
                try:
                    stream.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            return
        except (AssertionError, EOFError, OSError, TimeoutError):
            if process.poll() is not None or time.monotonic() >= deadline:
                raise
            time.sleep(0.3)


def exercise(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    client_brutal: bool,
) -> dict[str, Any]:
    sink, sink_port = start_sink()
    authority_port = reserve_port()
    front_port = reserve_port()
    authority_scratch = scratch / "authority"
    authority_scratch.mkdir()
    # High server up/down: numeric CC-RX (not auto) so client Brutal stays on,
    # without a 1 Mbps return/receive bottleneck on the upload path.
    authority, a_out, a_err = start_authority(
        authority_binary,
        authority_scratch,
        authority_port,
        up=SERVER_BW,
        down=SERVER_BW,
    )
    time.sleep(0.4)
    if authority.poll() is not None:
        raise RuntimeError("authority exited early")

    relay = QueuedDelayRelay(front_port, authority_port, RELAY_DELAY_MS)
    relay.start()
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    up = UP if client_brutal else None
    # Client `down` must be >0 so the server does not reply CC-RX: auto
    # (sing-quic sets RxAuto when request.Rx==0).
    down = CLIENT_DOWN
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: true
proxies:
{hy2_record("hy2", front_port, password=PASSWORD, up=up, down=down)}proxy-groups:
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
        wait_upload(process, mixed_port, sink_port)
        time.sleep(0.3)
        measured = measure_unidirectional_upload(mixed_port, sink, sink_port)
        measured["rate-class"] = rate_class(
            float(measured["measured-bps"]), expect_capped=client_brutal
        )
        measured["client-brutal"] = client_brutal
        measured["process-alive"] = process.poll() is None
        measured["relay-delay-ms"] = RELAY_DELAY_MS
        return measured
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
        sink.shutdown()
        sink.server_close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-hy2b-brutal-rate-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE_HY2B_BRUTAL_RATE_CARGO_TARGET", "phase-hy2b-brutal-rate"
        )
        try:
            for engine in ("rust", "go"):
                profiles: dict[str, Any] = {}
                for name, brutal in (("capped", True), ("negative-uncapped", False)):
                    scratch = root / engine / name
                    scratch.mkdir(parents=True)
                    profiles[name] = exercise(
                        binaries[engine],
                        binaries["go"],
                        scratch,
                        client_brutal=brutal,
                    )
                if profiles["capped"]["rate-class"] != "capped":
                    raise AssertionError(
                        f"{engine} Brutal capped class "
                        f"{profiles['capped']['rate-class']!r} "
                        f"(measured={profiles['capped']['measured-bps']} "
                        f"configured={int(UP_BPS)})"
                    )
                if profiles["negative-uncapped"]["rate-class"] != "uncapped":
                    raise AssertionError(
                        f"{engine} negative control must be uncapped without "
                        f"client up; got {profiles['negative-uncapped']['rate-class']!r} "
                        f"(measured={profiles['negative-uncapped']['measured-bps']})"
                    )
                observations[engine] = {
                    "capped-class": profiles["capped"]["rate-class"],
                    "negative-class": profiles["negative-uncapped"]["rate-class"],
                    "capped-bps": profiles["capped"]["measured-bps"],
                    "negative-bps": profiles["negative-uncapped"]["measured-bps"],
                    "process-alive": profiles["capped"]["process-alive"]
                    and profiles["negative-uncapped"]["process-alive"],
                    "detail": profiles,
                }
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
        "capped-class": observations["go"]["capped-class"],
        "negative-class": observations["go"]["negative-class"],
        "process-alive": observations["go"]["process-alive"],
    }
    rust = {
        "capped-class": observations["rust"]["capped-class"],
        "negative-class": observations["rust"]["negative-class"],
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

#!/usr/bin/env python3
"""HY2-B Brutal send-rate differential (Go vs Rust).

Echo success alone is not Brutal parity. With a low configured `up`, both
stacks must keep measured TCP throughput near the configured rate — not race
to line rate. Quinn lacks Go's independent pacer; Rust approximates via a
1.25-compensated congestion window. This gate fails if either side is uncapped.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import textwrap
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
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, connect_domain, debug_files
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-hy2b-brutal-rate-diff.json"
PASSWORD = "phase-hy2b-brutal-rate"
SNI = "dot.phase4.test"
# 512 Kib/s ≈ 64 KiB/s — low enough that an uncapped localhost path is obvious.
UP = "512 Kbps"
UP_BPS = 512_000 / 8  # bytes/sec
DOWN = "10 Mbps"
PAYLOAD = b"B" * 32_768
ROUNDS = 24
# Measured rate must stay under this multiple of configured up (headroom for
# ACK/retransmit/QUIC overhead and Quinn's approximate pacing).
CAP_MULTIPLIER = 3.0
# Must transfer enough to be meaningful (avoid "starved" false green).
MIN_GOODPUT_FRACTION = 0.15


def hy2_record(name: str, server_port: int) -> str:
    return f"""  - name: {name}
    type: hysteria2
    server: 127.0.0.1
    port: {server_port}
    password: {PASSWORD}
    sni: {SNI}
    alpn: [h3]
    skip-cert-verify: true
    udp: true
    up: {UP}
    down: {DOWN}
"""


def start_authority(
    go_binary: pathlib.Path,
    scratch: pathlib.Path,
    listen_port: int,
) -> tuple[subprocess.Popen[bytes], Any, Any]:
    cert_pem = textwrap.indent(SERVER_CERTIFICATE.read_text().strip(), "      ")
    key_pem = textwrap.indent(SERVER_KEY.read_text().strip(), "      ")
    config = scratch / "authority.yaml"
    config.write_text(
        f"""mixed-port: 0
mode: rule
log-level: warning
ipv6: true
listeners:
  - name: hy2-in
    type: hysteria2
    listen: 127.0.0.1
    port: {listen_port}
    users:
      hy2-user: {PASSWORD}
    up: {UP}
    down: {DOWN}
    certificate: |-
{cert_pem}
    private-key: |-
{key_pem}
    alpn:
      - h3
rules:
  - MATCH,DIRECT
"""
    )
    stdout = (scratch / "stdout.log").open("wb")
    stderr = (scratch / "stderr.log").open("wb")
    process = subprocess.Popen(
        [str(go_binary), "-f", str(config), "-d", str(scratch)],
        cwd=scratch,
        stdout=stdout,
        stderr=stderr,
    )
    return process, stdout, stderr


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
                stream.settimeout(max(IO_DEADLINE, 20.0))
                stream.sendall(PAYLOAD)
                if recv_exact(stream, len(PAYLOAD)) == PAYLOAD:
                    ok += 1
        except (AssertionError, EOFError, OSError, TimeoutError):
            continue
    elapsed = max(time.monotonic() - started, 1e-3)
    # Count only successful payload bytes toward goodput.
    measured = (ok * len(PAYLOAD)) / elapsed
    return {
        "rounds-ok": ok,
        "rounds": ROUNDS,
        "measured-bps": int(measured),
        "configured-up-bps": int(UP_BPS),
        "rate-class": rate_class(measured),
    }


def exercise(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    authority_port = reserve_port()
    authority_scratch = scratch / "authority"
    authority_scratch.mkdir()
    authority, a_out, a_err = start_authority(
        authority_binary, authority_scratch, authority_port
    )
    time.sleep(0.4)
    if authority.poll() is not None:
        raise RuntimeError("authority exited early")

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
{hy2_record("hy2", authority_port)}proxy-groups:
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
        # Warm path once so Brutal RTT samples exist before the timed window.
        with connect_domain(mixed_port, "127.0.0.1", echo.port) as stream:
            stream.settimeout(IO_DEADLINE)
            stream.sendall(b"warm")
            assert recv_exact(stream, 4) == b"warm"
        time.sleep(0.2)
        measured = measure_upload(mixed_port, echo.port)
        return {
            **measured,
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop(authority)
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

    # Compare coarse class only — absolute bps will differ across stacks.
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

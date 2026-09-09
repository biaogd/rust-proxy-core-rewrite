#!/usr/bin/env python3
"""SSR-D soak harness for outbound connection churn (TCP + periodic UDP).

Default duration is short (CI / local smoke). Longer soak:

  SSR_D_SOAK_SECONDS=7200 PYTHONPATH=compat/scripts \\
    python3 compat/scripts/phase7d_ssr_soak.py

Samples RSS/FD across churn and fails if growth looks unbounded. Compares
Go vs Rust boolean/coarse outcomes (not absolute RSS values).

UDP probes reuse one SOCKS UDP client socket so association churn does not
inflate FD samples (fresh ephemeral clients per probe would).

Production gate (optional):

  SSR_PRODUCTION_GATE=1 SSR_D_SOAK_SECONDS=7200 SSR_BUILD_PROFILE=release ...
"""

from __future__ import annotations

import json
import os
import pathlib
import statistics
import tempfile
import time
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, assert_go_oracle_baseline, reserve_port, start_server, wait_ready
from phase3 import UdpEchoHandler, launch, socks_udp_packet, decode_socks_udp, stop, wait_udp_route
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks_ciphers import echo
from phase7a_ssr_tcp import PASSWORD, SSR_SERVER_PIN, ensure_ssr_server
from phase7c_ssr import start_ssr_server_cipher
from phase7d_ssr import process_fd_count, process_rss_kib


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase7d-ssr-soak-diff.json"
# CI/smoke default; overnight / release: export SSR_D_SOAK_SECONDS=7200
DEFAULT_SOAK_SECONDS = 45
SAMPLE_EVERY = 5.0
CIPHER = "aes-128-cfb"
PROTOCOL = "origin"
OBFS = "plain"


def soak_seconds() -> int:
    raw = os.environ.get("SSR_D_SOAK_SECONDS", str(DEFAULT_SOAK_SECONDS))
    duration = max(10, int(raw))
    if os.environ.get("SSR_PRODUCTION_GATE") == "1":
        if duration < 7200 or os.environ.get("SSR_BUILD_PROFILE") != "release":
            raise ValueError(
                "production gate requires SSR_BUILD_PROFILE=release and "
                "SSR_D_SOAK_SECONDS>=7200"
            )
    return duration


def resource_verdict(samples: list[dict[str, Any]], duration: int) -> dict[str, Any]:
    complete = [s for s in samples if s.get("rss") and s.get("fd") is not None]
    measured = len(complete) == len(samples) and len(complete) >= max(
        2, int(duration / SAMPLE_EVERY * 0.8)
    )
    if not measured:
        return {"samples-complete": False, "rss-bounded": False, "fd-bounded": False}
    rss = [s["rss"] for s in complete]
    fds = [s["fd"] for s in complete]
    quarter = max(1, len(complete) // 4)
    rss_growth = statistics.median(rss[-quarter:]) - statistics.median(rss[:quarter])
    fd_growth = statistics.median(fds[-quarter:]) - statistics.median(fds[:quarter])
    # Steady-state envelope after paced TCP churn + one reused SOCKS UDP client
    # (fresh UDP clients per probe create associations and inflate FD counts).
    descriptor_budget = 64 if os.name == "nt" else 16
    return {
        "samples-complete": True,
        "rss-bounded": max(rss) - min(rss) <= 65536 and rss_growth <= 16384,
        "fd-bounded": max(fds) - min(fds) <= descriptor_budget
        and fd_growth <= descriptor_budget / 2,
        "rss-growth-kib": rss_growth,
        "descriptor-growth": fd_growth,
        "descriptor-kind": "handles" if os.name == "nt" else "fds",
    }


def udp_once(
    mixed_port: int,
    echo_port: int,
    payload: bytes,
    client: "socket.socket | None" = None,
) -> bool:
    import socket

    owns = client is None
    if client is None:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(IO_DEADLINE)
    try:
        client.sendto(socks_udp_packet(echo_port, payload), ("127.0.0.1", mixed_port))
        packet, _ = client.recvfrom(65_535)
        address, _, got = decode_socks_udp(packet)
        return address == "127.0.0.1" and got == payload
    except (OSError, AssertionError, TimeoutError):
        return False
    finally:
        if owns:
            client.close()


def exercise(
    binary: pathlib.Path,
    server_py: pathlib.Path,
    scratch: pathlib.Path,
    duration: int,
) -> dict[str, Any]:
    import socket
    import socketserver
    import threading

    echo_server = start_server(EchoHandler)
    udp_echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    udp_echo.allow_reuse_address = True
    threading.Thread(target=udp_echo.serve_forever, daemon=True).start()
    udp_port = int(udp_echo.server_address[1])

    mixed_port = reserve_port()
    ssr_port = reserve_port()
    authority, a_out, a_err = start_ssr_server_cipher(
        server_py,
        scratch,
        ssr_port,
        cipher=CIPHER,
        protocol=PROTOCOL,
        obfs=OBFS,
        protocol_param="",
        obfs_param="",
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: warning
ipv6: false
proxies:
  - name: local-ssr
    type: ssr
    server: 127.0.0.1
    port: {ssr_port}
    password: {PASSWORD}
    cipher: {CIPHER}
    protocol: {PROTOCOL}
    obfs: {OBFS}
    udp: true
rules:
  - MATCH,local-ssr
""",
        encoding="utf-8",
    )
    process, stdout, stderr = launch(binary, config, scratch)
    samples: list[dict[str, Any]] = []
    udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_client.settimeout(IO_DEADLINE)
    try:
        wait_ready(process, mixed_port)
        wait_udp_route(process, mixed_port, udp_port)
        if not echo(mixed_port, "127.0.0.1", echo_server.port, b"soak-warmup"):
            raise AssertionError("soak warmup failed")
        if not udp_once(mixed_port, udp_port, b"soak-udp-warmup", udp_client):
            raise AssertionError("soak udp warmup failed")

        deadline = time.monotonic() + duration
        next_sample = time.monotonic()
        churn = 0
        failures = 0
        attempts = 0
        while time.monotonic() < deadline:
            churn += 1
            attempts += 1
            try:
                if not echo(
                    mixed_port, "127.0.0.1", echo_server.port, f"soak-{churn}".encode()
                ):
                    failures += 1
            except (OSError, TimeoutError, AssertionError, EOFError):
                failures += 1
            if churn % 4 == 0:
                attempts += 1
                try:
                    if not udp_once(
                        mixed_port, udp_port, f"u{churn}".encode(), udp_client
                    ):
                        failures += 1
                except (OSError, TimeoutError, AssertionError):
                    failures += 1
            now = time.monotonic()
            if now >= next_sample:
                samples.append(
                    {
                        "t": round(now - (deadline - duration), 3),
                        "rss": process_rss_kib(process.pid),
                        "fd": process_fd_count(process.pid),
                        "churn": churn,
                    }
                )
                next_sample = now + SAMPLE_EVERY
            # Pace like HY2-C soak so RSS/FD samples reflect steady state, not
            # a connection-storm artifact from zero-delay churn.
            time.sleep(0.05)

        failure_rate = failures / max(attempts, 1)
        failure_class = "ok" if failures == 0 else ("low" if failure_rate < 0.05 else "high")
        verdict = resource_verdict(samples, duration)
        return {
            "duration-seconds": duration,
            "attempts": attempts,
            "failures": failures,
            "failure-rate-class": failure_class,
            "full-soak": duration >= 7200,
            "process-alive": process.poll() is None,
            "ssr-server-pin": SSR_SERVER_PIN,
            **verdict,
        }
    finally:
        udp_client.close()
        stop(process)
        stdout.close()
        stderr.close()
        if authority.poll() is None:
            authority.kill()
            try:
                authority.wait(timeout=IO_DEADLINE)
            except Exception:
                pass
        a_out.close()
        a_err.close()
        echo_server.close()
        udp_echo.shutdown()
        udp_echo.server_close()


def portable_view(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        key: entry.get(key)
        for key in (
            "duration-seconds",
            "failure-rate-class",
            "rss-bounded",
            "fd-bounded",
            "samples-complete",
            "process-alive",
            "full-soak",
            "ssr-server-pin",
        )
    }


def main() -> int:
    assert_go_oracle_baseline()
    duration = soak_seconds()
    observations: dict[str, Any] = {"soak-seconds": duration}
    server_py = ensure_ssr_server()
    print(
        f"SSR-D soak starting ({duration}s per engine). "
        "Default is a short CI soak. Set SSR_D_SOAK_SECONDS=7200 for the "
        "long opt-in gate (SSR_PRODUCTION_GATE=1 also requires release)."
    )
    with tempfile.TemporaryDirectory(prefix="phase7d-ssr-soak-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE7D_SSR_SOAK_CARGO_TARGET", "phase7d-ssr-soak")
        try:
            for engine in ("rust", "go"):
                scratch = root / engine
                scratch.mkdir()
                observations[engine] = exercise(
                    binaries[engine], server_py, scratch, duration
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

    go_view = portable_view(observations.get("go", {}))
    rust_view = portable_view(observations.get("rust", {}))
    required = (
        "failure-rate-class",
        "rss-bounded",
        "fd-bounded",
        "samples-complete",
        "process-alive",
    )
    rust_ok = all(
        observations["rust"].get(key) is True
        or observations["rust"].get(key) == "ok"
        for key in required
    )
    go_ok = all(
        observations["go"].get(key) is True or observations["go"].get(key) == "ok"
        for key in required
    )
    if go_view != rust_view or not rust_ok or not go_ok:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("SSR-D ShadowsocksR soak differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

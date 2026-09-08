#!/usr/bin/env python3
"""HY2-C soak harness for Hysteria2 outbound connection churn.

Default duration is short (CI / local smoke). Full ≥2h soak:

  HY2C_SOAK_SECONDS=7200 PYTHONPATH=compat/scripts \\
    python3 compat/scripts/phase_hy2c_hysteria2_soak.py

Samples RSS/FD across churn and fails if growth looks unbounded. Compares
Go vs Rust boolean/coarse outcomes (not absolute RSS values).
"""

from __future__ import annotations

import json
import os
import pathlib
import statistics
import tempfile
import time
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, recv_exact, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import connect_domain, debug_files
from hy2_support import build_binaries
from phase_hy2b_hysteria2 import udp_exchange
from phase_hy2c_hysteria2 import (
    PASSWORD,
    hy2_record,
    process_fd_count,
    process_rss_kib,
    start_authority,
    start_udp_echo,
    wait_exchange,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-hy2c-hysteria2-soak-diff.json"
# CI/smoke default; overnight / release: export HY2C_SOAK_SECONDS=7200
DEFAULT_SOAK_SECONDS = 45
SAMPLE_EVERY = 5.0


def soak_seconds() -> int:
    raw = os.environ.get("HY2C_SOAK_SECONDS", str(DEFAULT_SOAK_SECONDS))
    duration = max(10, int(raw))
    if os.environ.get("HY2_PRODUCTION_GATE") == "1":
        if duration < 7200 or os.environ.get("HY2_BUILD_PROFILE") != "release":
            raise ValueError("production gate requires release and >=7200 seconds per engine")
    return duration


def resource_verdict(samples, duration):
    # Missing or sporadic measurements must never certify a leak-free process.
    complete = [s for s in samples if s.get("rss", 0) and s.get("fd") is not None]
    measured = len(complete) == len(samples) and len(complete) >= max(2, int(duration / SAMPLE_EVERY * 0.8))
    if not measured:
        return {"samples-complete": False, "rss-bounded": False, "fd-bounded": False}
    rss = [s["rss"] for s in complete]
    fds = [s["fd"] for s in complete]
    quarter = max(1, len(complete) // 4)
    rss_growth = statistics.median(rss[-quarter:]) - statistics.median(rss[:quarter])
    fd_growth = statistics.median(fds[-quarter:]) - statistics.median(fds[:quarter])
    descriptor_budget = 64 if os.name == "nt" else 16
    return {
        "samples-complete": True,
        "rss-bounded": max(rss) - min(rss) <= 65536 and rss_growth <= 16384,
        "fd-bounded": max(fds) - min(fds) <= descriptor_budget and fd_growth <= descriptor_budget / 2,
        "rss-growth-kib": rss_growth,
        "descriptor-growth": fd_growth,
        "descriptor-kind": "handles" if os.name == "nt" else "fds",
    }


def exchange_once(mixed_port: int, echo_port: int, payload: bytes) -> bool:
    with connect_domain(mixed_port, "127.0.0.1", echo_port) as stream:
        stream.settimeout(IO_DEADLINE)
        stream.sendall(payload)
        return recv_exact(stream, len(payload)) == payload


def exercise(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
    duration: int,
) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    udp_echo, udp_port = start_udp_echo()
    authority_port = reserve_port()
    authority_scratch = scratch / "authority"
    authority_scratch.mkdir()
    authority, a_out, a_err = start_authority(
        authority_binary, authority_scratch, authority_port
    )
    time.sleep(0.4)
    if authority.poll() is not None:
        raise RuntimeError("authority exited early")

    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: warning
ipv6: true
proxies:
{hy2_record("inline-hy2", authority_port, password=PASSWORD)}
rules:
  - MATCH,inline-hy2
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    samples: list[dict[str, Any]] = []
    try:
        wait_ready(process, mixed_port)
        if not wait_exchange(process, mixed_port, echo.port, b"soak-warmup"):
            raise AssertionError("soak warmup failed")
        deadline = time.monotonic() + duration
        next_sample = time.monotonic()
        churn = 0
        failures = 0
        attempts = 0
        failure_events = []

        def record_failure(protocol, error):
            if len(failure_events) < 256:
                failure_events.append({
                    "protocol": protocol, "churn": churn,
                    "t": round(time.monotonic() - (deadline - duration), 3),
                    "error": str(error), "class": type(error).__name__,
                })
        while time.monotonic() < deadline:
            churn += 1
            attempts += 1
            try:
                ok = exchange_once(
                    mixed_port, echo.port, f"soak-{churn}".encode()
                )
                if not ok:
                    failures += 1
                    record_failure("tcp", AssertionError("payload mismatch"))
            except (OSError, TimeoutError, AssertionError, EOFError) as error:
                failures += 1
                record_failure("tcp", error)
            if churn % 4 == 0:
                attempts += 1
                try:
                    if not udp_exchange(
                        mixed_port, "127.0.0.1", udp_port, f"u{churn}".encode()
                    ):
                        failures += 1
                        record_failure("udp", AssertionError("payload mismatch"))
                except (OSError, TimeoutError, AssertionError, EOFError) as error:
                    failures += 1
                    record_failure("udp", error)
            now = time.monotonic()
            if now >= next_sample:
                samples.append(
                    {
                        "t": round(now - (deadline - duration), 1),
                        "rss": process_rss_kib(process.pid),
                        "fd": process_fd_count(process.pid),
                        "churn": churn,
                    }
                )
                next_sample = now + SAMPLE_EVERY
            time.sleep(0.05)

        return {
            "duration-seconds": duration,
            "churn": churn,
            "attempts": attempts,
            "failures": failures,
            "failure-events": failure_events,
            "failure-rate": failures / max(attempts, 1),
            "failure-rate-class": "ok" if failures == 0 else "failed",
            **resource_verdict(samples, duration),
            "samples": samples,
            "sample-count": len(samples),
            "process-alive": process.poll() is None,
            "full-soak": duration >= 7200,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop(authority)
        a_out.close()
        a_err.close()
        echo.close()
        udp_echo.shutdown()
        udp_echo.server_close()


def main() -> int:
    duration = soak_seconds()
    observations: dict[str, Any] = {
        "requested-seconds": duration,
        "note": (
            "Default is a short CI soak. Set HY2C_SOAK_SECONDS=7200 for the "
            "≥2h resource-growth gate."
        ),
    }
    with tempfile.TemporaryDirectory(prefix="phase-hy2c-soak-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE_HY2C_SOAK_CARGO_TARGET", "phase-hy2c-soak")
        try:
            for engine in ("rust", "go"):
                scratch = root / engine
                scratch.mkdir()
                observations[engine] = exercise(
                    binaries[engine], binaries["go"], scratch, duration
                )
            if any(
                observations[engine]["failures"]
                or not observations[engine]["rss-bounded"]
                or not observations[engine]["fd-bounded"]
                for engine in ("rust", "go")
            ):
                observations["debug"] = debug_files(root)
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

    # Compare portable fields only (absolute RSS differs by runtime).
    def view(entry: dict[str, Any]) -> dict[str, Any]:
        return {
            "duration-seconds": entry["duration-seconds"],
            "failure-rate-class": entry["failure-rate-class"],
            "rss-bounded": entry["rss-bounded"],
            "fd-bounded": entry["fd-bounded"],
            "process-alive": entry["process-alive"],
            "full-soak": entry["full-soak"],
        }

    if view(observations["go"]) != view(observations["rust"]):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    # Both must stay bounded and alive for the requested window.
    for engine in ("go", "rust"):
        entry = observations[engine]
        if not (
            entry["rss-bounded"]
            and entry["fd-bounded"]
            and entry["process-alive"]
            and entry["failure-rate-class"] == "ok"
        ):
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    label = "full ≥2h" if duration >= 7200 else f"short ({duration}s)"
    print(f"HY2-C Hysteria2 soak ({label}) passed")
    print(json.dumps(observations, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
import tempfile
import time
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, recv_exact, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files
from phase_hy2b_hysteria2 import udp_exchange
from phase_hy2c_hysteria2 import (
    PASSWORD,
    hy2_record,
    process_fd_count,
    process_rss_kib,
    start_authority,
    start_udp_echo,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-hy2c-hysteria2-soak-diff.json"
# CI/smoke default; overnight / release: export HY2C_SOAK_SECONDS=7200
DEFAULT_SOAK_SECONDS = 45
SAMPLE_EVERY = 5.0


def soak_seconds() -> int:
    raw = os.environ.get("HY2C_SOAK_SECONDS", str(DEFAULT_SOAK_SECONDS))
    return max(10, int(raw))


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
        deadline = time.monotonic() + duration
        next_sample = time.monotonic()
        churn = 0
        failures = 0
        while time.monotonic() < deadline:
            churn += 1
            try:
                ok = exchange_once(
                    mixed_port, echo.port, f"soak-{churn}".encode()
                )
                if not ok:
                    failures += 1
            except (OSError, TimeoutError, AssertionError, EOFError):
                failures += 1
            if churn % 4 == 0:
                try:
                    if not udp_exchange(
                        mixed_port, "127.0.0.1", udp_port, f"u{churn}".encode()
                    ):
                        failures += 1
                except (OSError, TimeoutError, AssertionError, EOFError):
                    failures += 1
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

        rss_values = [s["rss"] for s in samples if s.get("rss") is not None]
        fd_values = [s["fd"] for s in samples if s.get("fd") is not None]
        rss_bounded = True
        if len(rss_values) >= 2 and rss_values[0] > 0:
            rss_bounded = max(rss_values) < rss_values[0] * 6 + 512_000
        fd_bounded = True
        if len(fd_values) >= 2 and fd_values[0] > 0:
            fd_bounded = max(fd_values) < fd_values[0] + 512

        failure_rate = failures / max(churn, 1)
        return {
            "duration-seconds": duration,
            "churn": churn,
            "failure-rate-class": (
                "ok" if failure_rate <= 0.05 else "elevated" if failure_rate <= 0.25 else "high"
            ),
            "rss-bounded": rss_bounded,
            "fd-bounded": fd_bounded,
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
    print(json.dumps(view(observations["rust"]), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Short 6H-C soak for TUIC v5 outbound TCP+UDP churn.

Default duration is CI/smoke. Overnight:

  PHASE6HC_SOAK_SECONDS=7200 PYTHONPATH=compat/scripts \\
    python3 compat/scripts/phase6h_tuic_soak.py
"""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
import time
from typing import Any

from hy2_support import build_binaries
from phase1 import EchoHandler, IO_DEADLINE, ROOT, recv_exact, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import connect_domain, debug_files
from phase6h_tuic_tcp import start_authority, tuic_record, wait_exchange
from phase6h_tuic_udp import start_udp_echo, udp_exchange


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6h-tuic-soak-diff.json"
DEFAULT_SOAK_SECONDS = 45
SAMPLE_EVERY = 5.0


def soak_seconds() -> int:
    raw = os.environ.get("PHASE6HC_SOAK_SECONDS", str(DEFAULT_SOAK_SECONDS))
    return max(10, int(raw))


def process_rss_kib(pid: int) -> int | None:
    try:
        import psutil
    except ImportError:
        return None
    try:
        return psutil.Process(pid).memory_info().rss // 1024
    except Exception:
        return None


def process_fd_count(pid: int) -> int | None:
    try:
        import psutil
    except ImportError:
        return None
    try:
        process = psutil.Process(pid)
        return process.num_handles() if os.name == "nt" else process.num_fds()
    except Exception:
        return None


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
        raise RuntimeError("TUIC authority exited early")

    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: warning
ipv6: true
proxies:
{tuic_record("inline-tuic", authority_port, extra="    heartbeat-interval: 1000\n")}rules:
  - DST-PORT,{udp_port},inline-tuic
  - MATCH,inline-tuic
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    samples: list[dict[str, Any]] = []
    try:
        wait_ready(process, mixed_port)
        if not wait_exchange(process, mixed_port, "127.0.0.1", echo.port, b"soak-warmup"):
            raise AssertionError("soak warmup failed")
        deadline = time.monotonic() + duration
        next_sample = time.monotonic()
        churn = 0
        failures = 0
        attempts = 0
        while time.monotonic() < deadline:
            churn += 1
            attempts += 1
            try:
                if not exchange_once(mixed_port, echo.port, f"soak-{churn}".encode()):
                    failures += 1
            except (OSError, TimeoutError, AssertionError, EOFError):
                failures += 1
            if churn % 4 == 0:
                attempts += 1
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

        return {
            "duration-seconds": duration,
            "churn": churn,
            "attempts": attempts,
            "failures": failures,
            "failure-rate-class": "ok" if failures == 0 else "failed",
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
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-6hc-soak-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6HTUIC_CARGO_TARGET", "phase-6hc-soak")
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(
                    binaries[name], binaries["go"], scratch, duration
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

    go = observations["go"]
    rust = observations["rust"]
    comparable = {
        "duration-seconds",
        "failure-rate-class",
        "process-alive",
        "full-soak",
    }
    go_cmp = {key: go[key] for key in comparable}
    rust_cmp = {key: rust[key] for key in comparable}
    if (
        go_cmp != rust_cmp
        or rust["failure-rate-class"] != "ok"
        or not rust["process-alive"]
        or rust["churn"] < 1
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps({"go": go, "rust": rust}, indent=2, sort_keys=True)
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("6H-C TUIC v5 soak differential passed")
    print(json.dumps(rust, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

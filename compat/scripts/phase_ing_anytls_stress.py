#!/usr/bin/env python3
"""IN-G Go/Rust performance/stress differential for AnyTLS named inbound TCP.

Product AnyTLS outbound dials a named `type: anytls` inbound (same engine).
Measures concurrent relay, cancel churn, coarse throughput class, connection
slot recycling, and a short soak with optional RSS/FD samples.

Compares Go vs Rust on success/failure classes and coarse throughput — not
absolute Mbps claims (CI/agent hardware varies).
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import socket
import socketserver
import statistics
import tempfile
import threading
import time
from typing import Any

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    connect_tunnel,
    recv_exact,
    reserve_port,
    wait_ready,
)
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase_hy2c_hysteria2 import (
    cancel_churn,
    concurrent_tcp,
    measure_throughput,
)
from phase_ing_anytls_tcp import (
    PASSWORD,
    inbound_yaml,
    outbound_client_yaml,
    stage_tls_material,
)

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-ing-anytls-stress-diff.json"
CONCURRENT = 8
CANCEL_ROUNDS = 16
THROUGHPUT_ROUNDS = 12
SLOT_CHURN = 128
DEFAULT_SOAK_SECONDS = 30
SAMPLE_EVERY = 5.0


def soak_seconds() -> int:
    raw = os.environ.get("PHASE_ING_ANYTLS_SOAK_SECONDS", str(DEFAULT_SOAK_SECONDS))
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


def resource_verdict(samples: list[dict[str, Any]], duration: int) -> dict[str, Any]:
    complete = [s for s in samples if s.get("rss") and s.get("fd") is not None]
    if not complete:
        return {
            "samples-complete": False,
            "rss-bounded": None,
            "fd-bounded": None,
            "resource-metrics": "skipped-no-psutil",
        }
    measured = len(complete) == len(samples) and len(complete) >= max(
        2, int(duration / SAMPLE_EVERY * 0.8)
    )
    if not measured:
        return {
            "samples-complete": False,
            "rss-bounded": None,
            "fd-bounded": None,
            "resource-metrics": "incomplete",
        }
    rss = [int(s["rss"]) for s in complete]
    fds = [int(s["fd"]) for s in complete]
    quarter = max(1, len(complete) // 4)
    rss_growth = statistics.median(rss[-quarter:]) - statistics.median(rss[:quarter])
    fd_growth = statistics.median(fds[-quarter:]) - statistics.median(fds[:quarter])
    descriptor_budget = 64 if os.name == "nt" else 16
    return {
        "samples-complete": True,
        "rss-bounded": max(rss) - min(rss) <= 65536 and rss_growth <= 16384,
        "fd-bounded": max(fds) - min(fds) <= descriptor_budget
        and fd_growth <= descriptor_budget / 2,
        "rss-growth-kib": rss_growth,
        "descriptor-growth": fd_growth,
    }


def wait_anytls_inbound(process: Any, port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"anytls inbound exited during startup with {process.returncode}"
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("anytls inbound did not open listener")


def wait_warmup(mixed_port: int, echo_port: int, payload: bytes = b"warmup") -> None:
    deadline = time.monotonic() + max(IO_DEADLINE * 4, 20.0)
    while time.monotonic() < deadline:
        if exchange_once(mixed_port, echo_port, payload):
            return
        time.sleep(0.05)
    raise TimeoutError("AnyTLS inbound route did not become ready")


def exchange_once(mixed_port: int, echo_port: int, payload: bytes) -> bool:
    try:
        tunnel = connect_tunnel(mixed_port, "127.0.0.1", echo_port)
        try:
            tunnel.sendall(payload)
            return recv_exact(tunnel, len(payload)) == payload
        finally:
            tunnel.close()
    except (AssertionError, EOFError, OSError, TimeoutError):
        return False


def connection_slot_churn(mixed_port: int, echo_port: int, rounds: int) -> bool:
    """Many short-lived tunnels (disable-reuse outbound) to exercise slot free."""
    ok = 0
    for index in range(rounds):
        payload = f"slot-{index}".encode()
        if exchange_once(mixed_port, echo_port, payload):
            ok += 1
    # Require strong majority; a few timing flakes under load are acceptable.
    return ok >= max(1, (rounds * 9) // 10)


def exercise(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    soak_duration: int,
) -> dict[str, Any]:
    tcp_echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    tcp_echo.allow_reuse_address = True
    tcp_thread = threading.Thread(target=tcp_echo.serve_forever, daemon=True)
    tcp_thread.start()
    echo_port = int(tcp_echo.server_address[1])

    certificate, private_key = stage_tls_material(scratch)
    anytls_port = reserve_port()
    server_config = scratch / "server.yaml"
    server_config.write_text(inbound_yaml(anytls_port, certificate, private_key))

    mixed_port = reserve_port()
    client_config = scratch / "client.yaml"
    client_config.write_text(outbound_client_yaml(mixed_port, anytls_port))
    client_dir = scratch / "client-home"
    client_dir.mkdir()

    server, s_out, s_err = launch(binary, server_config, scratch)
    client, c_out, c_err = launch(binary, client_config, client_dir)
    samples: list[dict[str, Any]] = []
    try:
        wait_anytls_inbound(server, anytls_port)
        wait_ready(client, mixed_port)
        wait_warmup(mixed_port, echo_port)

        concurrent_ok = concurrent_tcp(mixed_port, echo_port, CONCURRENT)
        cancel_ok = cancel_churn(mixed_port, echo_port, CANCEL_ROUNDS)
        throughput = measure_throughput(mixed_port, echo_port, rounds=THROUGHPUT_ROUNDS)
        slot_ok = connection_slot_churn(mixed_port, echo_port, SLOT_CHURN)

        deadline = time.monotonic() + soak_duration
        next_sample = time.monotonic()
        churn = 0
        failures = 0
        attempts = 0
        while time.monotonic() < deadline:
            churn += 1
            attempts += 1
            if not exchange_once(mixed_port, echo_port, f"soak-{churn}".encode()):
                failures += 1
            now = time.monotonic()
            if now >= next_sample:
                samples.append(
                    {
                        "t": round(now - (deadline - soak_duration), 1),
                        "rss": process_rss_kib(server.pid),
                        "fd": process_fd_count(server.pid),
                        "churn": churn,
                    }
                )
                next_sample = now + SAMPLE_EVERY
            time.sleep(0.02)

        return {
            "concurrent": concurrent_ok,
            "cancel-churn": cancel_ok,
            "connection-slot-churn": slot_ok,
            "throughput-class": throughput["throughput-class"],
            "throughput-rounds-ok": throughput["rounds-ok"],
            "throughput-rounds": throughput["rounds"],
            "soak-seconds": soak_duration,
            "soak-churn": churn,
            "soak-failures": failures,
            "soak-failure-rate-class": "ok" if failures == 0 else "failed",
            "server-alive": server.poll() is None,
            "client-alive": client.poll() is None,
            **resource_verdict(samples, soak_duration),
        }
    finally:
        stop(client)
        stop(server)
        c_out.close()
        c_err.close()
        s_out.close()
        s_err.close()
        tcp_echo.shutdown()
        tcp_echo.server_close()
        tcp_thread.join(timeout=1)


def parity_view(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "concurrent": entry["concurrent"],
        "cancel-churn": entry["cancel-churn"],
        "connection-slot-churn": entry["connection-slot-churn"],
        "throughput-class": entry["throughput-class"],
        "soak-failure-rate-class": entry["soak-failure-rate-class"],
        "server-alive": entry["server-alive"],
        "client-alive": entry["client-alive"],
        "rss-bounded": entry.get("rss-bounded"),
        "fd-bounded": entry.get("fd-bounded"),
    }


def required_pass(entry: dict[str, Any]) -> bool:
    rss_ok = entry.get("rss-bounded") is not False
    fd_ok = entry.get("fd-bounded") is not False
    return bool(
        entry.get("concurrent")
        and entry.get("cancel-churn")
        and entry.get("connection-slot-churn")
        and entry.get("soak-failure-rate-class") == "ok"
        and entry.get("server-alive")
        and entry.get("client-alive")
        and entry.get("throughput-class") in {"high", "medium", "low"}
        and rss_ok
        and fd_ok
    )


def main() -> int:
    soak_duration = soak_seconds()
    observations: dict[str, Any] = {"requested-soak-seconds": soak_duration}
    with tempfile.TemporaryDirectory(prefix="phase-ing-anytls-stress-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE_ING_ANYTLS_STRESS_CARGO_TARGET", "phase-ing-anytls-stress"
        )
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], scratch, soak_duration)
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

    go_view = parity_view(observations["go"])
    rust_view = parity_view(observations["rust"])
    report = {
        "go": observations["go"],
        "rust": observations["rust"],
        "parity": go_view == rust_view,
        "go-view": go_view,
        "rust-view": rust_view,
    }
    if (
        go_view != rust_view
        or not required_pass(observations["go"])
        or not required_pass(observations["rust"])
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

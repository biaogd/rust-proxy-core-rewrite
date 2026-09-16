#!/usr/bin/env python3
"""Diagnostic: isolate AnyTLS inbound Go vs Rust latency sources.

Runs product outbound → named inbound with disable-reuse on/off and reports
per-exchange latency percentiles + effective conn/s. Not a CI gate.
"""

from __future__ import annotations

import json
import pathlib
import socketserver
import statistics
import tempfile
import threading
import time
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, connect_tunnel, recv_exact, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries
from phase_ing_anytls_tcp import inbound_yaml, stage_tls_material

PASSWORD = "phase-ing-anytls-password"
SNI = "dot.phase4.test"
WARMUP = 8
SAMPLES = 80


def client_yaml(mixed_port: int, anytls_port: int, *, disable_reuse: bool) -> str:
    reuse = "true" if disable_reuse else "false"
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: warning
ipv6: false
proxies:
  - name: anytls-out
    type: anytls
    server: 127.0.0.1
    port: {anytls_port}
    password: {PASSWORD}
    sni: {SNI}
    skip-cert-verify: true
    udp: true
    disable-reuse: {reuse}
proxy-groups:
  - name: PROXY
    type: select
    proxies: [anytls-out]
rules:
  - MATCH,PROXY
"""


def wait_listener(process: Any, port: int) -> None:
    import socket

    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"process exited: {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError(f"port {port} not open")


def exchange_latency_ms(mixed_port: int, echo_port: int, payload: bytes) -> float:
    started = time.perf_counter()
    tunnel = connect_tunnel(mixed_port, "127.0.0.1", echo_port)
    try:
        tunnel.sendall(payload)
        assert recv_exact(tunnel, len(payload)) == payload
    finally:
        tunnel.close()
    return (time.perf_counter() - started) * 1000.0


def wait_route(mixed_port: int, echo_port: int) -> None:
    deadline = time.monotonic() + max(IO_DEADLINE * 4, 20.0)
    while time.monotonic() < deadline:
        try:
            exchange_latency_ms(mixed_port, echo_port, b"ready")
            return
        except (AssertionError, EOFError, OSError, TimeoutError):
            time.sleep(0.05)
    raise TimeoutError("route not ready")


def percentile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    index = min(len(sorted_values) - 1, max(0, int(round((len(sorted_values) - 1) * p))))
    return sorted_values[index]


def summarize(latencies_ms: list[float]) -> dict[str, Any]:
    ordered = sorted(latencies_ms)
    mean = statistics.fmean(ordered)
    return {
        "n": len(ordered),
        "mean-ms": round(mean, 2),
        "p50-ms": round(percentile(ordered, 0.50), 2),
        "p90-ms": round(percentile(ordered, 0.90), 2),
        "p99-ms": round(percentile(ordered, 0.99), 2),
        "min-ms": round(ordered[0], 2),
        "max-ms": round(ordered[-1], 2),
        "approx-conn-per-sec": round(1000.0 / mean, 1) if mean > 0 else 0.0,
    }


def run_case(
    server_binary: pathlib.Path,
    client_binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    disable_reuse: bool,
    payload: bytes,
) -> dict[str, Any]:
    echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    echo.allow_reuse_address = True
    thread = threading.Thread(target=echo.serve_forever, daemon=True)
    thread.start()
    echo_port = int(echo.server_address[1])

    certificate, private_key = stage_tls_material(scratch)
    anytls_port = reserve_port()
    server_cfg = scratch / "server.yaml"
    server_cfg.write_text(inbound_yaml(anytls_port, certificate, private_key))

    mixed_port = reserve_port()
    client_home = scratch / "client-home"
    client_home.mkdir()
    client_cfg = scratch / "client.yaml"
    client_cfg.write_text(client_yaml(mixed_port, anytls_port, disable_reuse=disable_reuse))

    server, s_out, s_err = launch(server_binary, server_cfg, scratch)
    client, c_out, c_err = launch(client_binary, client_cfg, client_home)
    try:
        wait_listener(server, anytls_port)
        wait_ready(client, mixed_port)
        wait_route(mixed_port, echo_port)
        for index in range(WARMUP):
            exchange_latency_ms(mixed_port, echo_port, f"w{index}".encode())
        samples: list[float] = []
        for index in range(SAMPLES):
            samples.append(
                exchange_latency_ms(mixed_port, echo_port, payload + index.to_bytes(2, "big"))
            )
        return summarize(samples)
    finally:
        stop(client)
        stop(server)
        c_out.close()
        c_err.close()
        s_out.close()
        s_err.close()
        echo.shutdown()
        echo.server_close()
        thread.join(timeout=1)


def main() -> int:
    same_engine_cases = [
        ("tiny-no-reuse", b"x", True),
        ("tiny-reuse", b"x", False),
        ("16kib-no-reuse", bytes(range(256)) * 64, True),
        ("16kib-reuse", bytes(range(256)) * 64, False),
    ]
    report: dict[str, Any] = {"samples-per-case": SAMPLES, "warmup": WARMUP}
    with tempfile.TemporaryDirectory(prefix="ing-anytls-diag-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE_ING_ANYTLS_DIAG_CARGO_TARGET",
            "phase-ing-anytls-diag",
            profile="release",
        )
        for name in ["go", "rust"]:
            report[name] = {}
            for label, payload, disable_reuse in same_engine_cases:
                scratch = root / f"{name}-{label}"
                scratch.mkdir()
                report[name][label] = run_case(
                    binaries[name],
                    binaries[name],
                    scratch,
                    disable_reuse=disable_reuse,
                    payload=payload,
                )
                report[name][label]["disable-reuse"] = disable_reuse
                report[name][label]["payload-bytes"] = len(payload)

        # Cross matrix: which side dominates with disable-reuse (handshake path).
        cross = {}
        for server_name in ["go", "rust"]:
            for client_name in ["go", "rust"]:
                key = f"client-{client_name}_server-{server_name}"
                scratch = root / f"cross-{key}"
                scratch.mkdir(parents=True, exist_ok=True)
                cross[key] = run_case(
                    binaries[server_name],
                    binaries[client_name],
                    scratch,
                    disable_reuse=True,
                    payload=b"x",
                )
        report["cross-tiny-no-reuse"] = cross

    ratios = {}
    for label, _, _ in same_engine_cases:
        go_mean = report["go"][label]["mean-ms"]
        rust_mean = report["rust"][label]["mean-ms"]
        ratios[label] = {
            "rust-over-go-mean": round(rust_mean / go_mean, 2) if go_mean else None,
            "go-mean-ms": go_mean,
            "rust-mean-ms": rust_mean,
            "go-cps": report["go"][label]["approx-conn-per-sec"],
            "rust-cps": report["rust"][label]["approx-conn-per-sec"],
        }
    report["rust-over-go"] = ratios

    # Relative to Go/Go baseline for cross matrix.
    baseline = report["cross-tiny-no-reuse"]["client-go_server-go"]["mean-ms"]
    cross_ratio = {}
    for key, entry in report["cross-tiny-no-reuse"].items():
        cross_ratio[key] = {
            "mean-ms": entry["mean-ms"],
            "over-go-go": round(entry["mean-ms"] / baseline, 2) if baseline else None,
            "approx-conn-per-sec": entry["approx-conn-per-sec"],
        }
    report["cross-over-go-go"] = cross_ratio

    out = ROOT / "compat" / "artifacts" / "phase-ing-anytls-diag.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

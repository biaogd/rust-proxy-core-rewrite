#!/usr/bin/env python3
"""IN-G Go/Rust AnyTLS resource+throughput benchmark (diagnostic, not a CI gate).

Measures absolute Mbps, connection rate, CPU%, and RSS for same-engine
product outbound → named anytls inbound under concurrent load.

Environment:
  PHASE_ING_ANYTLS_PERF_SECONDS   load window per case (default 20)
  PHASE_ING_ANYTLS_PERF_WORKERS   concurrent tunnels (default 8)
  PHASE_ING_ANYTLS_PERF_PAYLOAD   payload bytes (default 262144 = 256 KiB)
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

import psutil

from phase1 import EchoHandler, IO_DEADLINE, ROOT, connect_tunnel, recv_exact, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries
from phase_ing_anytls_tcp import inbound_yaml, stage_tls_material

PASSWORD = "phase-ing-anytls-password"
SNI = "dot.phase4.test"
ARTIFACT = ROOT / "compat" / "artifacts" / "phase-ing-anytls-perf.json"


def env_int(name: str, default: int) -> int:
    return max(1, int(os.environ.get(name, str(default))))


LOAD_SECONDS = env_int("PHASE_ING_ANYTLS_PERF_SECONDS", 20)
WORKERS = env_int("PHASE_ING_ANYTLS_PERF_WORKERS", 8)
PAYLOAD_BYTES = env_int("PHASE_ING_ANYTLS_PERF_PAYLOAD", 262_144)
SAMPLE_EVERY = 0.5


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


def wait_route(mixed_port: int, echo_port: int) -> None:
    deadline = time.monotonic() + max(IO_DEADLINE * 4, 20.0)
    while time.monotonic() < deadline:
        try:
            tunnel = connect_tunnel(mixed_port, "127.0.0.1", echo_port)
            try:
                tunnel.sendall(b"ready")
                assert recv_exact(tunnel, 5) == b"ready"
            finally:
                tunnel.close()
            return
        except (AssertionError, EOFError, OSError, TimeoutError):
            time.sleep(0.05)
    raise TimeoutError("route not ready")


class ProcessSampler:
    """Track RSS/FD plus CPU% from cpu_times wall-clock deltas.

    Fresh ``Process.cpu_percent(interval=None)`` always returns 0 on the first
    call per object; recreating Process each sample loses the baseline.
    """

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.proc = psutil.Process(pid)
        self._last_cpu = self.proc.cpu_times()
        self._last_wall = time.perf_counter()

    def sample(self) -> dict[str, float | int | None]:
        try:
            with self.proc.oneshot():
                mem = self.proc.memory_info()
                fds = self.proc.num_fds() if hasattr(self.proc, "num_fds") else None
                now_cpu = self.proc.cpu_times()
            now_wall = time.perf_counter()
            wall = max(now_wall - self._last_wall, 1e-6)
            busy = (now_cpu.user - self._last_cpu.user) + (
                now_cpu.system - self._last_cpu.system
            )
            self._last_cpu = now_cpu
            self._last_wall = now_wall
            # Percent of one core; can exceed 100 on multi-threaded processes.
            cpu_percent = (busy / wall) * 100.0
            return {
                "cpu-percent": round(cpu_percent, 2),
                "rss-kib": mem.rss // 1024,
                "fds": fds,
            }
        except (psutil.Error, OSError):
            return {"cpu-percent": None, "rss-kib": None, "fds": None}


def summarize_series(values: list[float | int | None], *, key: str) -> dict[str, Any]:
    clean = [float(v) for v in values if v is not None]
    if not clean:
        return {f"{key}-n": 0}
    ordered = sorted(clean)
    return {
        f"{key}-n": len(ordered),
        f"{key}-min": round(ordered[0], 2),
        f"{key}-median": round(statistics.median(ordered), 2),
        f"{key}-p90": round(ordered[max(0, int(len(ordered) * 0.9) - 1)], 2),
        f"{key}-max": round(ordered[-1], 2),
        f"{key}-mean": round(statistics.fmean(ordered), 2),
    }


def worker_loop(
    mixed_port: int,
    echo_port: int,
    payload: bytes,
    stop_at: float,
    counters: dict[str, int],
    lock: threading.Lock,
) -> None:
    while time.monotonic() < stop_at:
        try:
            tunnel = connect_tunnel(mixed_port, "127.0.0.1", echo_port)
            try:
                tunnel.settimeout(max(IO_DEADLINE, 30.0))
                tunnel.sendall(payload)
                got = recv_exact(tunnel, len(payload))
                ok = got == payload
            finally:
                tunnel.close()
            with lock:
                counters["exchanges"] += 1
                if ok:
                    counters["ok"] += 1
                    counters["bytes"] += len(payload)
                else:
                    counters["fail"] += 1
        except (AssertionError, EOFError, OSError, TimeoutError):
            with lock:
                counters["exchanges"] += 1
                counters["fail"] += 1


def run_load(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    disable_reuse: bool,
    label: str,
) -> dict[str, Any]:
    echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    echo.allow_reuse_address = True
    # Larger backlog under concurrent workers.
    echo.request_queue_size = 128
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

    payload = bytes((i * 17) & 0xFF for i in range(PAYLOAD_BYTES))
    server, s_out, s_err = launch(binary, server_cfg, scratch)
    client, c_out, c_err = launch(binary, client_cfg, client_home)
    samples: list[dict[str, Any]] = []
    try:
        wait_listener(server, anytls_port)
        wait_ready(client, mixed_port)
        wait_route(mixed_port, echo_port)

        server_sampler = ProcessSampler(server.pid)
        client_sampler = ProcessSampler(client.pid)
        time.sleep(0.25)
        idle_server = server_sampler.sample()
        idle_client = client_sampler.sample()

        counters = {"exchanges": 0, "ok": 0, "fail": 0, "bytes": 0}
        lock = threading.Lock()
        stop_at = time.monotonic() + LOAD_SECONDS
        started = time.perf_counter()

        sampler_stop = threading.Event()

        def sampler() -> None:
            while not sampler_stop.wait(SAMPLE_EVERY):
                samples.append(
                    {
                        "t": round(time.perf_counter() - started, 2),
                        "server": server_sampler.sample(),
                        "client": client_sampler.sample(),
                    }
                )

        sampler_thread = threading.Thread(target=sampler, daemon=True)
        sampler_thread.start()

        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futures = [
                pool.submit(
                    worker_loop,
                    mixed_port,
                    echo_port,
                    payload,
                    stop_at,
                    counters,
                    lock,
                )
                for _ in range(WORKERS)
            ]
            for future in concurrent.futures.as_completed(futures):
                future.result()

        elapsed = max(time.perf_counter() - started, 1e-6)
        sampler_stop.set()
        sampler_thread.join(timeout=2)
        # Final sample at end of load.
        samples.append(
            {
                "t": round(elapsed, 2),
                "server": server_sampler.sample(),
                "client": client_sampler.sample(),
            }
        )

        bytes_ok = counters["bytes"]
        mbps = (bytes_ok * 8) / elapsed / 1_000_000
        bps = bytes_ok / elapsed
        exchanges_per_sec = counters["exchanges"] / elapsed

        server_cpu = [s["server"]["cpu-percent"] for s in samples]
        client_cpu = [s["client"]["cpu-percent"] for s in samples]
        server_rss = [s["server"]["rss-kib"] for s in samples]
        client_rss = [s["client"]["rss-kib"] for s in samples]
        server_fds = [s["server"]["fds"] for s in samples]
        client_fds = [s["client"]["fds"] for s in samples]

        return {
            "label": label,
            "disable-reuse": disable_reuse,
            "workers": WORKERS,
            "payload-bytes": PAYLOAD_BYTES,
            "load-seconds": LOAD_SECONDS,
            "elapsed-seconds": round(elapsed, 3),
            "exchanges": counters["exchanges"],
            "ok": counters["ok"],
            "fail": counters["fail"],
            "bytes-ok": bytes_ok,
            "throughput-mbps": round(mbps, 3),
            "throughput-bytes-per-sec": round(bps, 1),
            "exchanges-per-sec": round(exchanges_per_sec, 2),
            "success-rate": round(counters["ok"] / max(counters["exchanges"], 1), 4),
            "idle-server": idle_server,
            "idle-client": idle_client,
            "server": {
                **summarize_series(server_cpu, key="cpu-percent"),
                **summarize_series(server_rss, key="rss-kib"),
                **summarize_series(server_fds, key="fds"),
            },
            "client": {
                **summarize_series(client_cpu, key="cpu-percent"),
                **summarize_series(client_rss, key="rss-kib"),
                **summarize_series(client_fds, key="fds"),
            },
            "server-alive": server.poll() is None,
            "client-alive": client.poll() is None,
            "sample-count": len(samples),
        }
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


def compare(go: dict[str, Any], rust: dict[str, Any]) -> dict[str, Any]:
    def ratio(a: float | None, b: float | None) -> float | None:
        if a is None or b is None or b == 0:
            return None
        return round(a / b, 3)

    return {
        "rust-over-go-mbps": ratio(rust.get("throughput-mbps"), go.get("throughput-mbps")),
        "rust-over-go-exchanges-per-sec": ratio(
            rust.get("exchanges-per-sec"), go.get("exchanges-per-sec")
        ),
        "go-mbps": go.get("throughput-mbps"),
        "rust-mbps": rust.get("throughput-mbps"),
        "go-server-cpu-median": go.get("server", {}).get("cpu-percent-median"),
        "rust-server-cpu-median": rust.get("server", {}).get("cpu-percent-median"),
        "go-server-rss-median-kib": go.get("server", {}).get("rss-kib-median"),
        "rust-server-rss-median-kib": rust.get("server", {}).get("rss-kib-median"),
        "go-client-cpu-median": go.get("client", {}).get("cpu-percent-median"),
        "rust-client-cpu-median": rust.get("client", {}).get("cpu-percent-median"),
        "go-client-rss-median-kib": go.get("client", {}).get("rss-kib-median"),
        "rust-client-rss-median-kib": rust.get("client", {}).get("rss-kib-median"),
        "go-success-rate": go.get("success-rate"),
        "rust-success-rate": rust.get("success-rate"),
    }


def main() -> int:
    cases = [
        ("bulk-reuse", False),
        ("bulk-no-reuse", True),
    ]
    report: dict[str, Any] = {
        "load-seconds": LOAD_SECONDS,
        "workers": WORKERS,
        "payload-bytes": PAYLOAD_BYTES,
        "sample-every-seconds": SAMPLE_EVERY,
        "note": "localhost AnyTLS echo relay; absolute Mbps depends on host CPU",
    }
    with tempfile.TemporaryDirectory(prefix="ing-anytls-perf-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE_ING_ANYTLS_PERF_CARGO_TARGET",
            "phase-ing-anytls-perf",
            profile="release",
        )
        for name in ["go", "rust"]:
            report[name] = {}
            for label, disable_reuse in cases:
                scratch = root / f"{name}-{label}"
                scratch.mkdir()
                report[name][label] = run_load(
                    binaries[name],
                    scratch,
                    disable_reuse=disable_reuse,
                    label=label,
                )

    comparisons = {}
    for label, _ in cases:
        comparisons[label] = compare(report["go"][label], report["rust"][label])
    report["compare"] = comparisons

    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(json.dumps(report, indent=2, sort_keys=True))
    # Also drop a copy under /opt/cursor/artifacts for walkthrough.
    out_copy = pathlib.Path("/opt/cursor/artifacts/anytls-perf-resource.json")
    try:
        out_copy.parent.mkdir(parents=True, exist_ok=True)
        out_copy.write_text(json.dumps(report, indent=2, sort_keys=True))
    except OSError:
        pass
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"wrote {ARTIFACT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

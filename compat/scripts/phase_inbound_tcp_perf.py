#!/usr/bin/env python3
"""Go/Rust multi-protocol inbound TCP throughput/latency/CPU/RSS benchmark.

Same-engine product outbound → named inbound under concurrent load.

Coverage (gap-fill vs early harness):
  - Bulk Mbps: TLS + QUIC + WS/gRPC carriers + Shadowsocks AEAD/ChaCha/2022
  - Short-conn latency: tiny payload, connect/exchange percentiles
  - Multi-run median aggregation
  - Short soak stability on a subset
  - Binary size of the release artifacts under test

SSR inbound is not covered: neither Go nor Rust exposes a named SSR listener
(outbound-only; see compatibility-matrix).

Environment:
  PHASE_INBOUND_PERF_SECONDS     bulk load window (default 12)
  PHASE_INBOUND_PERF_WORKERS     concurrent tunnels (default 8)
  PHASE_INBOUND_PERF_PAYLOAD     bulk payload bytes (default 262144)
  PHASE_INBOUND_PERF_PROTOCOLS   comma list (default: all registered)
  PHASE_INBOUND_PERF_RUNS        repeats per case; report median (default 3)
  PHASE_INBOUND_PERF_LATENCY_N   latency samples per case (default 60)
  PHASE_INBOUND_PERF_SOAK_SECONDS short soak window (default 45; 0 disables)
  PHASE_INBOUND_PERF_SKIP_LATENCY set 1 to skip latency suite
  PHASE_INBOUND_PERF_SKIP_SOAK    set 1 to skip soak suite
  PHASE_INBOUND_PERF_SKIP_CARRIERS set 1 to skip WS/gRPC protocols
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
from dataclasses import dataclass
from typing import Any, Callable

import psutil

from phase1 import EchoHandler, IO_DEADLINE, ROOT, connect_tunnel, recv_exact, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries
from phase_inc_trojan_grpc import (
    inbound_yaml as trojan_grpc_inbound,
    outbound_client_yaml as trojan_grpc_outbound,
)
from phase_inc_trojan_tls import (
    inbound_yaml as trojan_inbound,
    outbound_client_yaml as trojan_outbound,
    stage_tls_material,
)
from phase_inc_trojan_websocket import (
    inbound_yaml as trojan_ws_inbound,
    outbound_client_yaml as trojan_ws_outbound,
)
from phase_ind_vless_grpc import (
    inbound_yaml as vless_grpc_inbound,
    outbound_client_yaml as vless_grpc_outbound,
)
from phase_ind_vless_tls import (
    inbound_yaml as vless_inbound,
    outbound_client_yaml as vless_outbound,
)
from phase_ind_vless_websocket import (
    inbound_yaml as vless_ws_inbound,
    outbound_client_yaml as vless_ws_outbound,
)
from phase_ine_vmess_grpc import (
    inbound_yaml as vmess_grpc_inbound,
    outbound_client_yaml as vmess_grpc_outbound,
)
from phase_ine_vmess_tls import (
    inbound_yaml as vmess_inbound,
    outbound_client_yaml as vmess_outbound,
)
from phase_ine_vmess_websocket import (
    inbound_yaml as vmess_ws_inbound,
    outbound_client_yaml as vmess_ws_outbound,
)
from phase_inf_hysteria2_tcp import (
    inbound_yaml as hy2_inbound,
    outbound_client_yaml as hy2_outbound,
)
from phase_inf_tuic_tcp import (
    inbound_yaml as tuic_inbound,
    outbound_client_yaml as tuic_outbound,
)
from phase_ing_anytls_tcp import (
    inbound_yaml as anytls_inbound,
    outbound_client_yaml as anytls_outbound_base,
)

ARTIFACT = ROOT / "compat" / "artifacts" / "phase-inbound-tcp-perf.json"
COMPARE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-inbound-tcp-perf-compare.json"
SNI = "dot.phase4.test"
SS_PASSWORD = "phase-inbound-ss-password"
SS_2022_KEY = "AAECAwQFBgcICQoLDA0ODw=="  # 16-byte base64; matches 6C-N / IN-B fixtures


def env_int(name: str, default: int) -> int:
    return max(0, int(os.environ.get(name, str(default))))


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


LOAD_SECONDS = max(1, env_int("PHASE_INBOUND_PERF_SECONDS", 12))
WORKERS = max(1, env_int("PHASE_INBOUND_PERF_WORKERS", 8))
PAYLOAD_BYTES = max(1, env_int("PHASE_INBOUND_PERF_PAYLOAD", 262_144))
RUNS = max(1, env_int("PHASE_INBOUND_PERF_RUNS", 3))
LATENCY_N = max(1, env_int("PHASE_INBOUND_PERF_LATENCY_N", 60))
LATENCY_WARMUP = 8
LATENCY_PAYLOAD = b"x"
SOAK_SECONDS = env_int("PHASE_INBOUND_PERF_SOAK_SECONDS", 45)
SAMPLE_EVERY = 0.5
SOAK_PROTOCOLS = ("trojan-tls", "anytls", "vmess-tls", "ss-aead")


def anytls_outbound(mixed_port: int, server_port: int) -> str:
    # Prefer session reuse for bulk Mbps (matches production hot path).
    text = anytls_outbound_base(mixed_port, server_port)
    return text.replace("disable-reuse: true", "disable-reuse: false").replace(
        "log-level: info", "log-level: warning"
    )


def with_warning_logs(yaml_text: str) -> str:
    return yaml_text.replace("log-level: info", "log-level: warning")


def ss_inbound_yaml(
    cipher: str,
    password: str,
) -> Callable[[int, pathlib.Path, pathlib.Path], str]:
    def inbound(port: int, _certificate: pathlib.Path, _private_key: pathlib.Path) -> str:
        # Named shadowsocks listener; TLS material unused (same Protocol shape).
        return f"""listeners:
  - name: ss-inbound
    type: shadowsocks
    listen: 127.0.0.1
    port: {port}
    cipher: {cipher}
    password: {password}
    udp: false
mode: rule
log-level: warning
ipv6: false
rules:
  - MATCH,DIRECT
"""

    return inbound


def ss_outbound_yaml(
    cipher: str,
    password: str,
) -> Callable[[int, int], str]:
    def outbound(mixed_port: int, ss_port: int) -> str:
        return f"""mixed-port: {mixed_port}
mode: rule
log-level: warning
ipv6: false
proxies:
  - name: ss-out
    type: ss
    server: 127.0.0.1
    port: {ss_port}
    cipher: {cipher}
    password: {password}
proxy-groups:
  - name: PROXY
    type: select
    proxies: [ss-out]
rules:
  - MATCH,PROXY
"""

    return outbound


@dataclass(frozen=True)
class Protocol:
    name: str
    transport: str  # "tcp" or "quic"
    family: str  # tls / ws / grpc / quic / anytls / ss
    inbound: Callable[[int, pathlib.Path, pathlib.Path], str]
    outbound: Callable[[int, int], str]


CORE_PROTOCOLS: dict[str, Protocol] = {
    "trojan-tls": Protocol("trojan-tls", "tcp", "tls", trojan_inbound, trojan_outbound),
    "vless-tls": Protocol("vless-tls", "tcp", "tls", vless_inbound, vless_outbound),
    "vmess-tls": Protocol("vmess-tls", "tcp", "tls", vmess_inbound, vmess_outbound),
    "anytls": Protocol("anytls", "tcp", "anytls", anytls_inbound, anytls_outbound),
    "hysteria2": Protocol("hysteria2", "quic", "quic", hy2_inbound, hy2_outbound),
    "tuic": Protocol("tuic", "quic", "quic", tuic_inbound, tuic_outbound),
    # Shadowsocks named inbound (product outbound → listener). SSR has no inbound
    # on Go or Rust — outbound-only; see roadmap / compatibility-matrix.
    "ss-aead": Protocol(
        "ss-aead",
        "tcp",
        "ss",
        ss_inbound_yaml("aes-128-gcm", SS_PASSWORD),
        ss_outbound_yaml("aes-128-gcm", SS_PASSWORD),
    ),
    "ss-chacha": Protocol(
        "ss-chacha",
        "tcp",
        "ss",
        ss_inbound_yaml("chacha20-ietf-poly1305", SS_PASSWORD),
        ss_outbound_yaml("chacha20-ietf-poly1305", SS_PASSWORD),
    ),
    "ss-2022": Protocol(
        "ss-2022",
        "tcp",
        "ss",
        ss_inbound_yaml("2022-blake3-aes-128-gcm", SS_2022_KEY),
        ss_outbound_yaml("2022-blake3-aes-128-gcm", SS_2022_KEY),
    ),
}

CARRIER_PROTOCOLS: dict[str, Protocol] = {
    "trojan-wss": Protocol("trojan-wss", "tcp", "ws", trojan_ws_inbound, trojan_ws_outbound),
    "trojan-grpc": Protocol(
        "trojan-grpc", "tcp", "grpc", trojan_grpc_inbound, trojan_grpc_outbound
    ),
    "vless-wss": Protocol("vless-wss", "tcp", "ws", vless_ws_inbound, vless_ws_outbound),
    "vless-grpc": Protocol(
        "vless-grpc", "tcp", "grpc", vless_grpc_inbound, vless_grpc_outbound
    ),
    "vmess-wss": Protocol("vmess-wss", "tcp", "ws", vmess_ws_inbound, vmess_ws_outbound),
    "vmess-grpc": Protocol(
        "vmess-grpc", "tcp", "grpc", vmess_grpc_inbound, vmess_grpc_outbound
    ),
}

PROTOCOLS: dict[str, Protocol] = {**CORE_PROTOCOLS, **CARRIER_PROTOCOLS}


def selected_protocols() -> list[Protocol]:
    raw = os.environ.get("PHASE_INBOUND_PERF_PROTOCOLS", "").strip()
    if raw:
        names = [part.strip() for part in raw.split(",") if part.strip()]
        missing = [name for name in names if name not in PROTOCOLS]
        if missing:
            raise SystemExit(f"unknown protocols: {missing}; known={sorted(PROTOCOLS)}")
        return [PROTOCOLS[name] for name in names]
    if env_flag("PHASE_INBOUND_PERF_SKIP_CARRIERS"):
        return list(CORE_PROTOCOLS.values())
    return list(PROTOCOLS.values())


class ProcessSampler:
    def __init__(self, pid: int) -> None:
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
            return {
                "cpu-percent": round((busy / wall) * 100.0, 2),
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


def percentile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    index = min(len(sorted_values) - 1, max(0, int(round((len(sorted_values) - 1) * p))))
    return sorted_values[index]


def wait_tcp_listener(process: Any, port: int) -> None:
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


def wait_route(mixed_port: int, echo_port: int, process: Any) -> None:
    deadline = time.monotonic() + max(IO_DEADLINE * 4, 25.0)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"client exited during warmup: {process.returncode}")
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


def exchange_latency_ms(mixed_port: int, echo_port: int, payload: bytes) -> float:
    started = time.perf_counter()
    tunnel = connect_tunnel(mixed_port, "127.0.0.1", echo_port)
    try:
        tunnel.settimeout(max(IO_DEADLINE, 30.0))
        tunnel.sendall(payload)
        assert recv_exact(tunnel, len(payload)) == payload
    finally:
        tunnel.close()
    return (time.perf_counter() - started) * 1000.0


def start_pair(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    protocol: Protocol,
) -> tuple[Any, Any, Any, Any, Any, Any, int, int, Any, threading.Thread]:
    echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    echo.allow_reuse_address = True
    echo.request_queue_size = 128
    thread = threading.Thread(target=echo.serve_forever, daemon=True)
    thread.start()
    echo_port = int(echo.server_address[1])

    certificate, private_key = stage_tls_material(scratch)
    listen_port = reserve_port()
    server_cfg = scratch / "server.yaml"
    server_cfg.write_text(
        with_warning_logs(protocol.inbound(listen_port, certificate, private_key))
    )

    mixed_port = reserve_port()
    client_home = scratch / "client-home"
    client_home.mkdir(exist_ok=True)
    client_cfg = scratch / "client.yaml"
    client_cfg.write_text(
        with_warning_logs(protocol.outbound(mixed_port, listen_port))
    )

    server, s_out, s_err = launch(binary, server_cfg, scratch)
    client, c_out, c_err = launch(binary, client_cfg, client_home)
    try:
        if protocol.transport == "tcp":
            wait_tcp_listener(server, listen_port)
        else:
            time.sleep(0.4)
            if server.poll() is not None:
                raise RuntimeError(f"quic server exited: {server.returncode}")
        wait_ready(client, mixed_port)
        wait_route(mixed_port, echo_port, client)
    except Exception:
        stop(client)
        stop(server)
        c_out.close()
        c_err.close()
        s_out.close()
        s_err.close()
        echo.shutdown()
        echo.server_close()
        thread.join(timeout=1)
        raise
    return (
        server,
        client,
        s_out,
        s_err,
        c_out,
        c_err,
        mixed_port,
        echo_port,
        echo,
        thread,
    )


def stop_pair(
    server: Any,
    client: Any,
    s_out: Any,
    s_err: Any,
    c_out: Any,
    c_err: Any,
    echo: Any,
    thread: threading.Thread,
) -> None:
    stop(client)
    stop(server)
    c_out.close()
    c_err.close()
    s_out.close()
    s_err.close()
    echo.shutdown()
    echo.server_close()
    thread.join(timeout=1)


def run_bulk(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    protocol: Protocol,
) -> dict[str, Any]:
    (
        server,
        client,
        s_out,
        s_err,
        c_out,
        c_err,
        mixed_port,
        echo_port,
        echo,
        thread,
    ) = start_pair(binary, scratch, protocol)
    samples: list[dict[str, Any]] = []
    try:
        server_sampler = ProcessSampler(server.pid)
        client_sampler = ProcessSampler(client.pid)
        time.sleep(0.25)
        idle_server = server_sampler.sample()
        idle_client = client_sampler.sample()

        payload = bytes((i * 17) & 0xFF for i in range(PAYLOAD_BYTES))
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
        samples.append(
            {
                "t": round(elapsed, 2),
                "server": server_sampler.sample(),
                "client": client_sampler.sample(),
            }
        )

        bytes_ok = counters["bytes"]
        server_cpu = [s["server"]["cpu-percent"] for s in samples]
        client_cpu = [s["client"]["cpu-percent"] for s in samples]
        server_rss = [s["server"]["rss-kib"] for s in samples]
        client_rss = [s["client"]["rss-kib"] for s in samples]
        server_fds = [s["server"]["fds"] for s in samples]
        client_fds = [s["client"]["fds"] for s in samples]

        return {
            "suite": "bulk",
            "protocol": protocol.name,
            "family": protocol.family,
            "transport": protocol.transport,
            "workers": WORKERS,
            "payload-bytes": PAYLOAD_BYTES,
            "load-seconds": LOAD_SECONDS,
            "elapsed-seconds": round(elapsed, 3),
            "exchanges": counters["exchanges"],
            "ok": counters["ok"],
            "fail": counters["fail"],
            "bytes-ok": bytes_ok,
            "throughput-mbps": round((bytes_ok * 8) / elapsed / 1_000_000, 3),
            "throughput-bytes-per-sec": round(bytes_ok / elapsed, 1),
            "exchanges-per-sec": round(counters["exchanges"] / elapsed, 2),
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
        stop_pair(server, client, s_out, s_err, c_out, c_err, echo, thread)


def run_latency(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    protocol: Protocol,
) -> dict[str, Any]:
    (
        server,
        client,
        s_out,
        s_err,
        c_out,
        c_err,
        mixed_port,
        echo_port,
        echo,
        thread,
    ) = start_pair(binary, scratch, protocol)
    try:
        for index in range(LATENCY_WARMUP):
            exchange_latency_ms(mixed_port, echo_port, f"w{index}".encode())
        samples: list[float] = []
        failures = 0
        for index in range(LATENCY_N):
            try:
                samples.append(
                    exchange_latency_ms(
                        mixed_port,
                        echo_port,
                        LATENCY_PAYLOAD + index.to_bytes(2, "big"),
                    )
                )
            except (AssertionError, EOFError, OSError, TimeoutError):
                failures += 1
        ordered = sorted(samples)
        mean = statistics.fmean(ordered) if ordered else 0.0
        return {
            "suite": "latency",
            "protocol": protocol.name,
            "family": protocol.family,
            "transport": protocol.transport,
            "payload-bytes": len(LATENCY_PAYLOAD) + 2,
            "warmup": LATENCY_WARMUP,
            "requested-samples": LATENCY_N,
            "ok-samples": len(ordered),
            "failures": failures,
            "mean-ms": round(mean, 2),
            "p50-ms": round(percentile(ordered, 0.50), 2) if ordered else None,
            "p90-ms": round(percentile(ordered, 0.90), 2) if ordered else None,
            "p99-ms": round(percentile(ordered, 0.99), 2) if ordered else None,
            "min-ms": round(ordered[0], 2) if ordered else None,
            "max-ms": round(ordered[-1], 2) if ordered else None,
            "approx-conn-per-sec": round(1000.0 / mean, 1) if mean > 0 else 0.0,
            "server-alive": server.poll() is None,
            "client-alive": client.poll() is None,
        }
    finally:
        stop_pair(server, client, s_out, s_err, c_out, c_err, echo, thread)


def run_soak(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    protocol: Protocol,
    *,
    duration: int,
) -> dict[str, Any]:
    (
        server,
        client,
        s_out,
        s_err,
        c_out,
        c_err,
        mixed_port,
        echo_port,
        echo,
        thread,
    ) = start_pair(binary, scratch, protocol)
    try:
        server_sampler = ProcessSampler(server.pid)
        client_sampler = ProcessSampler(client.pid)
        time.sleep(0.2)
        server_sampler.sample()
        client_sampler.sample()

        payload = bytes((i * 13) & 0xFF for i in range(4096))
        stop_at = time.monotonic() + duration
        started = time.perf_counter()
        ok = 0
        fail = 0
        samples: list[dict[str, Any]] = []
        next_sample = time.monotonic() + 5.0
        while time.monotonic() < stop_at:
            try:
                tunnel = connect_tunnel(mixed_port, "127.0.0.1", echo_port)
                try:
                    tunnel.settimeout(max(IO_DEADLINE, 30.0))
                    tunnel.sendall(payload)
                    got = recv_exact(tunnel, len(payload))
                    if got == payload:
                        ok += 1
                    else:
                        fail += 1
                finally:
                    tunnel.close()
            except (AssertionError, EOFError, OSError, TimeoutError):
                fail += 1
            now = time.monotonic()
            if now >= next_sample:
                samples.append(
                    {
                        "t": round(time.perf_counter() - started, 2),
                        "server": server_sampler.sample(),
                        "client": client_sampler.sample(),
                    }
                )
                next_sample = now + 5.0

        elapsed = max(time.perf_counter() - started, 1e-6)
        samples.append(
            {
                "t": round(elapsed, 2),
                "server": server_sampler.sample(),
                "client": client_sampler.sample(),
            }
        )
        total = ok + fail
        return {
            "suite": "soak",
            "protocol": protocol.name,
            "family": protocol.family,
            "transport": protocol.transport,
            "soak-seconds": duration,
            "elapsed-seconds": round(elapsed, 3),
            "ok": ok,
            "fail": fail,
            "exchanges-per-sec": round(total / elapsed, 2),
            "success-rate": round(ok / max(total, 1), 4),
            "server": summarize_series(
                [s["server"]["rss-kib"] for s in samples], key="rss-kib"
            )
            | summarize_series(
                [s["server"]["cpu-percent"] for s in samples], key="cpu-percent"
            ),
            "client": summarize_series(
                [s["client"]["rss-kib"] for s in samples], key="rss-kib"
            )
            | summarize_series(
                [s["client"]["cpu-percent"] for s in samples], key="cpu-percent"
            ),
            "server-alive": server.poll() is None,
            "client-alive": client.poll() is None,
            "sample-count": len(samples),
        }
    finally:
        stop_pair(server, client, s_out, s_err, c_out, c_err, echo, thread)


def median_of_runs(runs: list[dict[str, Any]], keys: list[str]) -> dict[str, Any]:
    if not runs:
        return {}
    out: dict[str, Any] = {
        "runs": len(runs),
        "protocol": runs[0].get("protocol"),
        "family": runs[0].get("family"),
        "transport": runs[0].get("transport"),
        "suite": runs[0].get("suite"),
    }
    for key in keys:
        values = [run.get(key) for run in runs if run.get(key) is not None]
        numeric = [float(v) for v in values if isinstance(v, (int, float))]
        if numeric:
            out[key] = round(statistics.median(numeric), 3)
            out[f"{key}-min"] = round(min(numeric), 3)
            out[f"{key}-max"] = round(max(numeric), 3)
        elif values:
            out[key] = values[0]
    # Nested server/client medians for bulk.
    for side in ("server", "client"):
        nested: dict[str, Any] = {}
        for metric in (
            "cpu-percent-median",
            "rss-kib-median",
            "fds-median",
        ):
            values = []
            for run in runs:
                block = run.get(side) or {}
                if metric in block and block[metric] is not None:
                    values.append(float(block[metric]))
            if values:
                nested[metric] = round(statistics.median(values), 2)
        if nested:
            out[side] = nested
    out["per-run"] = runs
    return out


def compare_bulk(go: dict[str, Any], rust: dict[str, Any]) -> dict[str, Any]:
    def ratio(a: Any, b: Any) -> float | None:
        try:
            if a is None or b in (None, 0):
                return None
            return round(float(a) / float(b), 3)
        except (TypeError, ValueError, ZeroDivisionError):
            return None

    return {
        "rust-over-go-mbps": ratio(rust.get("throughput-mbps"), go.get("throughput-mbps")),
        "go-mbps": go.get("throughput-mbps"),
        "rust-mbps": rust.get("throughput-mbps"),
        "go-mbps-min": go.get("throughput-mbps-min"),
        "go-mbps-max": go.get("throughput-mbps-max"),
        "rust-mbps-min": rust.get("throughput-mbps-min"),
        "rust-mbps-max": rust.get("throughput-mbps-max"),
        "go-server-cpu-median": (go.get("server") or {}).get("cpu-percent-median"),
        "rust-server-cpu-median": (rust.get("server") or {}).get("cpu-percent-median"),
        "go-client-cpu-median": (go.get("client") or {}).get("cpu-percent-median"),
        "rust-client-cpu-median": (rust.get("client") or {}).get("cpu-percent-median"),
        "go-server-rss-median-kib": (go.get("server") or {}).get("rss-kib-median"),
        "rust-server-rss-median-kib": (rust.get("server") or {}).get("rss-kib-median"),
        "go-client-rss-median-kib": (go.get("client") or {}).get("rss-kib-median"),
        "rust-client-rss-median-kib": (rust.get("client") or {}).get("rss-kib-median"),
        "go-success-rate": go.get("success-rate"),
        "rust-success-rate": rust.get("success-rate"),
        "runs": go.get("runs") or rust.get("runs"),
    }


def compare_latency(go: dict[str, Any], rust: dict[str, Any]) -> dict[str, Any]:
    def ratio(a: Any, b: Any) -> float | None:
        try:
            if a is None or b in (None, 0):
                return None
            return round(float(a) / float(b), 3)
        except (TypeError, ValueError, ZeroDivisionError):
            return None

    return {
        "go-p50-ms": go.get("p50-ms"),
        "rust-p50-ms": rust.get("p50-ms"),
        "go-p90-ms": go.get("p90-ms"),
        "rust-p90-ms": rust.get("p90-ms"),
        "go-p99-ms": go.get("p99-ms"),
        "rust-p99-ms": rust.get("p99-ms"),
        "go-conn-per-sec": go.get("approx-conn-per-sec"),
        "rust-conn-per-sec": rust.get("approx-conn-per-sec"),
        "rust-over-go-conn-per-sec": ratio(
            rust.get("approx-conn-per-sec"), go.get("approx-conn-per-sec")
        ),
        "go-over-rust-p50-ms": ratio(go.get("p50-ms"), rust.get("p50-ms")),
        "runs": go.get("runs") or rust.get("runs"),
    }


def binary_size_mib(path: pathlib.Path) -> float:
    return round(path.stat().st_size / (1024 * 1024), 2)


def write_artifacts(report: dict[str, Any]) -> None:
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(json.dumps(report, indent=2, sort_keys=True))
    COMPARE_ARTIFACT.write_text(
        json.dumps(
            {
                "profile": report.get("profile"),
                "binary-size-mib": report.get("binary-size-mib"),
                "conditions": report.get("conditions"),
                "compare-bulk": report.get("compare-bulk"),
                "compare-latency": report.get("compare-latency"),
                "compare-soak": report.get("compare-soak"),
            },
            indent=2,
            sort_keys=True,
        )
    )
    for path in (
        pathlib.Path("/opt/cursor/artifacts/inbound-tcp-perf.json"),
        pathlib.Path("/opt/cursor/artifacts/inbound-tcp-perf-summary.json"),
        pathlib.Path("/opt/cursor/artifacts/inbound-tcp-perf-final.json"),
    ):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.name.endswith("summary.json") or path.name.endswith("final.json"):
                path.write_text(
                    json.dumps(
                        {
                            "profile": report.get("profile"),
                            "binary-size-mib": report.get("binary-size-mib"),
                            "conditions": report.get("conditions"),
                            "compare-bulk": report.get("compare-bulk"),
                            "compare-latency": report.get("compare-latency"),
                            "compare-soak": report.get("compare-soak"),
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                path.write_text(json.dumps(report, indent=2, sort_keys=True))
        except OSError:
            pass


def main() -> int:
    protocols = selected_protocols()
    do_latency = not env_flag("PHASE_INBOUND_PERF_SKIP_LATENCY")
    do_soak = SOAK_SECONDS > 0 and not env_flag("PHASE_INBOUND_PERF_SKIP_SOAK")
    soak_list = [PROTOCOLS[name] for name in SOAK_PROTOCOLS if name in PROTOCOLS]

    report: dict[str, Any] = {
        "profile": {
            "rust": "release opt-level=3 lto=fat codegen-units=1 strip=symbols panic=abort",
            "go": "go build -trimpath",
            "note": "balanced size+perf; not opt-level=z / not under-20MiB target",
        },
        "conditions": {
            "load-seconds": LOAD_SECONDS,
            "workers": WORKERS,
            "payload-bytes": PAYLOAD_BYTES,
            "runs": RUNS,
            "latency-samples": LATENCY_N,
            "soak-seconds": SOAK_SECONDS if do_soak else 0,
            "sample-every-seconds": SAMPLE_EVERY,
            "netem": "unavailable (no tc)",
        },
        "protocols": [p.name for p in protocols],
        "note": (
            "localhost product outbound→named inbound echo; Mbps/latency host-dependent; "
            "multi-run medians; carriers include WS/gRPC"
        ),
        "bulk": {"go": {}, "rust": {}},
        "latency": {"go": {}, "rust": {}},
        "soak": {"go": {}, "rust": {}},
        "compare-bulk": {},
        "compare-latency": {},
        "compare-soak": {},
    }

    # Force balanced release knobs even if a prior shell left OPT_LEVEL=z etc.
    os.environ["CARGO_PROFILE_RELEASE_OPT_LEVEL"] = "3"
    os.environ["CARGO_PROFILE_RELEASE_LTO"] = "fat"
    os.environ["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"] = "1"
    os.environ["CARGO_PROFILE_RELEASE_STRIP"] = "symbols"
    os.environ["CARGO_PROFILE_RELEASE_PANIC"] = "abort"
    # Prefer the balanced target dir when the caller did not override it.
    os.environ.setdefault(
        "PHASE_INBOUND_PERF_CARGO_TARGET",
        str(ROOT / "rust" / "target" / "compat" / "phase-inbound-tcp-perf-balanced"),
    )

    with tempfile.TemporaryDirectory(prefix="inbound-tcp-perf-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE_INBOUND_PERF_CARGO_TARGET",
            "phase-inbound-tcp-perf-balanced",
            profile="release",
        )
        report["binary-size-mib"] = {
            "go": binary_size_mib(binaries["go"]),
            "rust": binary_size_mib(binaries["rust"]),
        }

        for engine in ["go", "rust"]:
            for protocol in protocols:
                runs: list[dict[str, Any]] = []
                for run_idx in range(RUNS):
                    scratch = root / f"{engine}-bulk-{protocol.name}-r{run_idx}"
                    scratch.mkdir()
                    print(
                        f"bulk {engine}/{protocol.name} run {run_idx + 1}/{RUNS} ...",
                        flush=True,
                    )
                    runs.append(run_bulk(binaries[engine], scratch, protocol))
                report["bulk"][engine][protocol.name] = median_of_runs(
                    runs,
                    [
                        "throughput-mbps",
                        "exchanges-per-sec",
                        "success-rate",
                        "bytes-ok",
                    ],
                )

            if do_latency:
                for protocol in protocols:
                    runs = []
                    for run_idx in range(RUNS):
                        scratch = root / f"{engine}-lat-{protocol.name}-r{run_idx}"
                        scratch.mkdir()
                        print(
                            f"latency {engine}/{protocol.name} run {run_idx + 1}/{RUNS} ...",
                            flush=True,
                        )
                        runs.append(run_latency(binaries[engine], scratch, protocol))
                    report["latency"][engine][protocol.name] = median_of_runs(
                        runs,
                        [
                            "mean-ms",
                            "p50-ms",
                            "p90-ms",
                            "p99-ms",
                            "approx-conn-per-sec",
                            "failures",
                        ],
                    )

            if do_soak:
                for protocol in soak_list:
                    scratch = root / f"{engine}-soak-{protocol.name}"
                    scratch.mkdir()
                    print(
                        f"soak {engine}/{protocol.name} ({SOAK_SECONDS}s) ...",
                        flush=True,
                    )
                    report["soak"][engine][protocol.name] = run_soak(
                        binaries[engine],
                        scratch,
                        protocol,
                        duration=SOAK_SECONDS,
                    )

    for protocol in protocols:
        report["compare-bulk"][protocol.name] = compare_bulk(
            report["bulk"]["go"][protocol.name],
            report["bulk"]["rust"][protocol.name],
        )
        if do_latency:
            report["compare-latency"][protocol.name] = compare_latency(
                report["latency"]["go"][protocol.name],
                report["latency"]["rust"][protocol.name],
            )

    if do_soak:
        for protocol in soak_list:
            go = report["soak"]["go"][protocol.name]
            rust = report["soak"]["rust"][protocol.name]
            report["compare-soak"][protocol.name] = {
                "go-success-rate": go.get("success-rate"),
                "rust-success-rate": rust.get("success-rate"),
                "go-exchanges-per-sec": go.get("exchanges-per-sec"),
                "rust-exchanges-per-sec": rust.get("exchanges-per-sec"),
                "go-server-rss-median-kib": (go.get("server") or {}).get("rss-kib-median"),
                "rust-server-rss-median-kib": (rust.get("server") or {}).get(
                    "rss-kib-median"
                ),
                "go-alive": go.get("server-alive") and go.get("client-alive"),
                "rust-alive": rust.get("server-alive") and rust.get("client-alive"),
            }

    # Backward-compatible top-level compare alias (bulk medians).
    report["compare"] = report["compare-bulk"]
    write_artifacts(report)
    print(
        json.dumps(
            {
                "binary-size-mib": report["binary-size-mib"],
                "compare-bulk": report["compare-bulk"],
                "compare-latency": report["compare-latency"],
                "compare-soak": report["compare-soak"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    print(f"wrote {ARTIFACT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

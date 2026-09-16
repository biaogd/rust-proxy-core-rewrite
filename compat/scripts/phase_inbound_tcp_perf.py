#!/usr/bin/env python3
"""Go/Rust multi-protocol inbound TCP throughput/CPU/RSS benchmark.

Same-engine product outbound → named inbound under concurrent load.
Protocols: trojan-tls, vless-tls, vmess-tls, anytls (reuse), hysteria2, tuic.

Environment:
  PHASE_INBOUND_PERF_SECONDS   load window per case (default 15)
  PHASE_INBOUND_PERF_WORKERS   concurrent tunnels (default 8)
  PHASE_INBOUND_PERF_PAYLOAD   payload bytes (default 262144)
  PHASE_INBOUND_PERF_PROTOCOLS comma list (default: all)
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
from phase_inc_trojan_tls import (
    inbound_yaml as trojan_inbound,
    outbound_client_yaml as trojan_outbound,
    stage_tls_material,
)
from phase_ind_vless_tls import (
    inbound_yaml as vless_inbound,
    outbound_client_yaml as vless_outbound,
)
from phase_ine_vmess_tls import (
    inbound_yaml as vmess_inbound,
    outbound_client_yaml as vmess_outbound,
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
SNI = "dot.phase4.test"


def env_int(name: str, default: int) -> int:
    return max(1, int(os.environ.get(name, str(default))))


LOAD_SECONDS = env_int("PHASE_INBOUND_PERF_SECONDS", 15)
WORKERS = env_int("PHASE_INBOUND_PERF_WORKERS", 8)
PAYLOAD_BYTES = env_int("PHASE_INBOUND_PERF_PAYLOAD", 262_144)
SAMPLE_EVERY = 0.5


def anytls_outbound(mixed_port: int, server_port: int) -> str:
    # Prefer session reuse for bulk Mbps (matches production hot path).
    text = anytls_outbound_base(mixed_port, server_port)
    return text.replace("disable-reuse: true", "disable-reuse: false").replace(
        "log-level: info", "log-level: warning"
    )


def with_warning_logs(yaml_text: str) -> str:
    return yaml_text.replace("log-level: info", "log-level: warning")


@dataclass(frozen=True)
class Protocol:
    name: str
    transport: str  # "tcp" or "quic"
    inbound: Callable[[int, pathlib.Path, pathlib.Path], str]
    outbound: Callable[[int, int], str]


PROTOCOLS: dict[str, Protocol] = {
    "trojan-tls": Protocol("trojan-tls", "tcp", trojan_inbound, trojan_outbound),
    "vless-tls": Protocol("vless-tls", "tcp", vless_inbound, vless_outbound),
    "vmess-tls": Protocol("vmess-tls", "tcp", vmess_inbound, vmess_outbound),
    "anytls": Protocol("anytls", "tcp", anytls_inbound, anytls_outbound),
    "hysteria2": Protocol("hysteria2", "quic", hy2_inbound, hy2_outbound),
    "tuic": Protocol("tuic", "quic", tuic_inbound, tuic_outbound),
}


def selected_protocols() -> list[Protocol]:
    raw = os.environ.get("PHASE_INBOUND_PERF_PROTOCOLS", "").strip()
    if not raw:
        return list(PROTOCOLS.values())
    names = [part.strip() for part in raw.split(",") if part.strip()]
    missing = [name for name in names if name not in PROTOCOLS]
    if missing:
        raise SystemExit(f"unknown protocols: {missing}; known={sorted(PROTOCOLS)}")
    return [PROTOCOLS[name] for name in names]


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


def run_load(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    protocol: Protocol,
) -> dict[str, Any]:
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
    client_home.mkdir()
    client_cfg = scratch / "client.yaml"
    client_cfg.write_text(
        with_warning_logs(protocol.outbound(mixed_port, listen_port))
    )

    payload = bytes((i * 17) & 0xFF for i in range(PAYLOAD_BYTES))
    server, s_out, s_err = launch(binary, server_cfg, scratch)
    client, c_out, c_err = launch(binary, client_cfg, client_home)
    samples: list[dict[str, Any]] = []
    try:
        if protocol.transport == "tcp":
            wait_tcp_listener(server, listen_port)
        else:
            # QUIC: no TCP accept probe; give the UDP socket a moment.
            time.sleep(0.4)
            if server.poll() is not None:
                raise RuntimeError(f"quic server exited: {server.returncode}")
        wait_ready(client, mixed_port)
        wait_route(mixed_port, echo_port, client)

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
            "protocol": protocol.name,
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
        "go-server-cpu-median": go.get("server", {}).get("cpu-percent-median"),
        "rust-server-cpu-median": rust.get("server", {}).get("cpu-percent-median"),
        "go-client-cpu-median": go.get("client", {}).get("cpu-percent-median"),
        "rust-client-cpu-median": rust.get("client", {}).get("cpu-percent-median"),
        "go-server-rss-median-kib": go.get("server", {}).get("rss-kib-median"),
        "rust-server-rss-median-kib": rust.get("server", {}).get("rss-kib-median"),
        "go-client-rss-median-kib": go.get("client", {}).get("rss-kib-median"),
        "rust-client-rss-median-kib": rust.get("client", {}).get("rss-kib-median"),
        "go-success-rate": go.get("success-rate"),
        "rust-success-rate": rust.get("success-rate"),
    }


def main() -> int:
    protocols = selected_protocols()
    report: dict[str, Any] = {
        "load-seconds": LOAD_SECONDS,
        "workers": WORKERS,
        "payload-bytes": PAYLOAD_BYTES,
        "sample-every-seconds": SAMPLE_EVERY,
        "protocols": [p.name for p in protocols],
        "note": "localhost product outbound→named inbound echo; Mbps is host-dependent",
        "go": {},
        "rust": {},
        "compare": {},
    }
    with tempfile.TemporaryDirectory(prefix="inbound-tcp-perf-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE_INBOUND_PERF_CARGO_TARGET",
            "phase-inbound-tcp-perf",
            profile="release",
        )
        for engine in ["go", "rust"]:
            for protocol in protocols:
                scratch = root / f"{engine}-{protocol.name}"
                scratch.mkdir()
                print(f"running {engine}/{protocol.name} ...", flush=True)
                report[engine][protocol.name] = run_load(
                    binaries[engine], scratch, protocol
                )

    for protocol in protocols:
        report["compare"][protocol.name] = compare(
            report["go"][protocol.name], report["rust"][protocol.name]
        )

    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(json.dumps(report, indent=2, sort_keys=True))
    for path in (
        pathlib.Path("/opt/cursor/artifacts/inbound-tcp-perf.json"),
        pathlib.Path("/opt/cursor/artifacts/inbound-tcp-perf-summary.json"),
    ):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.name.endswith("summary.json"):
                path.write_text(
                    json.dumps(
                        {
                            "conditions": {
                                "load-seconds": LOAD_SECONDS,
                                "workers": WORKERS,
                                "payload-bytes": PAYLOAD_BYTES,
                            },
                            "compare": report["compare"],
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                path.write_text(json.dumps(report, indent=2, sort_keys=True))
        except OSError:
            pass
    print(json.dumps(report["compare"], indent=2, sort_keys=True))
    print(f"wrote {ARTIFACT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

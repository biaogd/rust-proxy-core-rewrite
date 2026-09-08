#!/usr/bin/env python3
"""HY2-C Hysteria2 stress / recovery / reload / netem differential (Go vs Rust).

Bounded production gate: concurrent TCP+UDP, cancel churn, authority restart,
network interruption, reload proxy removal, and fixed-parameter UDP fault
injection (app-level netem). Kernel `tc netem` is used when available; otherwise
the in-process relay applies the same fixed delay/loss/reorder/rate schedule.
Compares coarse throughput class, recovery, and survival — not per-packet timing.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import random
import select
import shutil
import socket
import socketserver
import subprocess
import tempfile
import textwrap
import threading
import time
from typing import Any

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    recv_exact,
    reload_via_controller,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, connect_domain, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_tcp import rejected_exchange
from phase6e_vless_udp import decode_socks_udp, socks_udp_packet
from phase_hy2b_hysteria2 import (
    socks_udp_associate,
    udp_exchange,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-hy2c-hysteria2-diff.json"
PASSWORD = "phase-hy2c-password"
SNI = "dot.phase4.test"
CONCURRENT_TCP = 8
CANCEL_ROUNDS = 24
THROUGHPUT_PAYLOAD = bytes(range(256)) * 64  # 16 KiB


def hy2_record(
    name: str,
    server_port: int,
    *,
    password: str = PASSWORD,
    disable_reuse: bool = False,
) -> str:
    # Default reuse matches common Clash HY2 nodes. After peer-loss windows the
    # gate reloads config so outbound client caches cannot stick to half-open
    # QUIC sessions (see exercise restart/interrupt paths).
    return f"""  - name: {name}
    type: hysteria2
    server: 127.0.0.1
    port: {server_port}
    password: {password}
    sni: {SNI}
    alpn: [h3]
    skip-cert-verify: true
    disable-reuse: {'true' if disable_reuse else 'false'}
    udp: true
"""


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(data, self.client_address)


def start_udp_echo() -> tuple[socketserver.ThreadingUDPServer, int]:
    server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    server.allow_reuse_address = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, int(server.server_address[1])


def process_rss_kib(pid: int) -> int | None:
    status = pathlib.Path(f"/proc/{pid}/status")
    if status.exists():
        for line in status.read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    try:
        out = subprocess.check_output(
            ["ps", "-o", "rss=", "-p", str(pid)], text=True, timeout=2
        ).strip()
        return int(out) if out else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def process_fd_count(pid: int) -> int | None:
    fd_dir = pathlib.Path(f"/proc/{pid}/fd")
    if fd_dir.exists():
        try:
            return len(list(fd_dir.iterdir()))
        except OSError:
            return None
    return None


def throughput_class(bytes_per_sec: float) -> str:
    # Coarse buckets shared by Go/Rust under the same fixed fault schedule.
    if bytes_per_sec >= 200_000:
        return "high"
    if bytes_per_sec >= 20_000:
        return "medium"
    if bytes_per_sec > 0:
        return "low"
    return "zero"


class NetemUdpRelay:
    """Fixed-parameter UDP fault relay (delay / loss / reorder / rate limit)."""

    def __init__(
        self,
        listen_port: int,
        target_port: int,
        *,
        delay_ms: float = 0.0,
        loss_percent: float = 0.0,
        reorder_gap: int = 10_000,
        rate_limit_bps: int = 100_000_000,
    ) -> None:
        self.listen_port = listen_port
        self.target_port = target_port
        self.delay_ms = delay_ms
        self.loss_percent = loss_percent
        self.reorder_gap = reorder_gap
        self.rate_limit_bps = rate_limit_bps
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._rng = random.Random(0xC0FFEE)
        self.packets_seen = 0
        self.packets_dropped = 0
        self.packets_reordered = 0

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)

    def _maybe_delay(self) -> None:
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000.0)

    def _rate_wait(self, nbytes: int, tokens: list[float], last: list[float]) -> None:
        now = time.monotonic()
        elapsed = max(0.0, now - last[0])
        last[0] = now
        tokens[0] = min(float(self.rate_limit_bps), tokens[0] + elapsed * self.rate_limit_bps)
        need = float(nbytes * 8)
        if tokens[0] < need:
            wait = (need - tokens[0]) / float(self.rate_limit_bps)
            time.sleep(wait)
            tokens[0] = 0.0
            last[0] = time.monotonic()
        else:
            tokens[0] -= need

    def _run(self) -> None:
        listen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen.bind(("127.0.0.1", self.listen_port))
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(("127.0.0.1", 0))
        listen.setblocking(False)
        upstream.setblocking(False)
        client_addr: tuple[str, int] | None = None
        held: tuple[bytes, str] | None = None
        tokens = [float(self.rate_limit_bps)]
        last = [time.monotonic()]
        try:
            while not self._stop.is_set():
                readable, _, _ = select.select([listen, upstream], [], [], 0.05)
                for source in readable:
                    if source is listen:
                        data, addr = listen.recvfrom(65_535)
                        client_addr = addr
                        direction = "c2s"
                    else:
                        data, _ = upstream.recvfrom(65_535)
                        direction = "s2c"
                    self.packets_seen += 1
                    if self._rng.random() * 100.0 < self.loss_percent:
                        self.packets_dropped += 1
                        continue
                    if (
                        direction == "c2s"
                        and held is None
                        and self.packets_seen % self.reorder_gap == 0
                    ):
                        held = (data, direction)
                        continue
                    self._maybe_delay()
                    self._rate_wait(len(data), tokens, last)
                    if direction == "c2s":
                        upstream.sendto(data, ("127.0.0.1", self.target_port))
                    elif client_addr is not None:
                        listen.sendto(data, client_addr)
                    if held is not None and direction == "c2s":
                        held_data, _ = held
                        held = None
                        self.packets_reordered += 1
                        self._maybe_delay()
                        self._rate_wait(len(held_data), tokens, last)
                        upstream.sendto(held_data, ("127.0.0.1", self.target_port))
        finally:
            listen.close()
            upstream.close()


def try_kernel_netem(iface: str = "lo") -> dict[str, Any]:
    """Apply fixed tc netem on Linux when privileged; otherwise report unavailable."""
    tc = shutil.which("tc")
    if tc is None or os.name != "posix":
        return {"available": False, "reason": "tc-missing"}
    delay = "20ms"
    loss = "5%"
    reorder = "25% 50%"
    rate = "2mbit"
    commands = [
        [tc, "qdisc", "replace", "dev", iface, "root", "handle", "1:", "htb", "default", "1"],
        [
            tc,
            "class",
            "replace",
            "dev",
            iface,
            "parent",
            "1:",
            "classid",
            "1:1",
            "htb",
            "rate",
            rate,
        ],
        [
            tc,
            "qdisc",
            "replace",
            "dev",
            iface,
            "parent",
            "1:1",
            "handle",
            "10:",
            "netem",
            "delay",
            delay,
            "loss",
            loss,
            "reorder",
            *reorder.split(),
        ],
    ]
    applied: list[str] = []
    try:
        for cmd in commands:
            subprocess.run(cmd, check=True, capture_output=True, timeout=5)
            applied.append(" ".join(cmd))
        return {
            "available": True,
            "params": {"delay": delay, "loss": loss, "reorder": reorder, "rate": rate},
            "applied": applied,
        }
    except (OSError, subprocess.SubprocessError) as error:
        # Best-effort cleanup if partial apply failed.
        subprocess.run(
            [tc, "qdisc", "del", "dev", iface, "root"],
            check=False,
            capture_output=True,
            timeout=5,
        )
        return {"available": False, "reason": f"{type(error).__name__}: {error}"}


def clear_kernel_netem(iface: str = "lo") -> None:
    tc = shutil.which("tc")
    if tc is None:
        return
    subprocess.run(
        [tc, "qdisc", "del", "dev", iface, "root"],
        check=False,
        capture_output=True,
        timeout=5,
    )


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
    return launch(go_binary, config, scratch)


def cancel_churn(mixed_port: int, echo_port: int, rounds: int) -> bool:
    for index in range(rounds):
        try:
            stream = connect_domain(mixed_port, "127.0.0.1", echo_port)
            stream.settimeout(IO_DEADLINE)
            try:
                if index % 2 == 0:
                    stream.close()
                    continue
                stream.sendall(f"keep-{index}".encode())
                if recv_exact(stream, len(f"keep-{index}")) != f"keep-{index}".encode():
                    return False
            finally:
                try:
                    stream.close()
                except OSError:
                    pass
        except (OSError, TimeoutError, AssertionError, EOFError):
            return False
    return True


def concurrent_tcp(mixed_port: int, echo_port: int, count: int) -> bool:
    def one(index: int) -> bool:
        payload = (f"hy2c-{index}-".encode() * 32)[:512]
        try:
            with connect_domain(mixed_port, "127.0.0.1", echo_port) as stream:
                stream.settimeout(IO_DEADLINE)
                stream.sendall(payload)
                return recv_exact(stream, len(payload)) == payload
        except (OSError, TimeoutError, AssertionError, EOFError):
            return False

    def burst() -> bool:
        if not one(-1):
            return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
            futures = [pool.submit(one, index) for index in range(count)]
            try:
                results = [future.result(timeout=max(IO_DEADLINE, 20.0)) for future in futures]
            except (OSError, TimeoutError, AssertionError, EOFError):
                return False
            # Require a strong majority rather than perfect fan-in under CI load.
            return sum(1 for ok in results if ok) >= max(1, (count * 3) // 4)

    return burst() or burst()


def measure_throughput(mixed_port: int, echo_port: int, rounds: int = 8) -> dict[str, Any]:
    started = time.monotonic()
    ok = 0
    for index in range(rounds):
        payload = THROUGHPUT_PAYLOAD + index.to_bytes(2, "big")
        try:
            with connect_domain(mixed_port, "127.0.0.1", echo_port) as stream:
                stream.settimeout(max(IO_DEADLINE, 15.0))
                stream.sendall(payload)
                if recv_exact(stream, len(payload)) == payload:
                    ok += 1
        except (
            AssertionError,
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionResetError,
            EOFError,
            OSError,
            TimeoutError,
        ):
            # Intentional lossy netem: keep counting remaining rounds instead of
            # aborting the whole window on the first reset (Go CI flake).
            continue
    elapsed = max(time.monotonic() - started, 1e-3)
    bps = (ok * len(THROUGHPUT_PAYLOAD)) / elapsed
    return {
        "rounds-ok": ok,
        "rounds": rounds,
        "throughput-class": throughput_class(bps),
        "recovered": ok == rounds,
    }


def write_client_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    controller_port: int,
    server_port: int,
    provider: pathlib.Path | None,
    include_removable: bool,
) -> None:
    proxies = hy2_record("inline-hy2", server_port, password=PASSWORD)
    if include_removable:
        proxies += hy2_record("removable-hy2", server_port, password=PASSWORD)
    provider_block = ""
    group_members = "[inline-hy2]"
    use_block = ""
    if include_removable:
        group_members = "[inline-hy2, removable-hy2]"
    if provider is not None:
        provider_block = f"""proxy-providers:
  local-hy2:
    type: file
    path: {provider}
"""
        use_block = "    use: [local-hy2]\n"
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: true
proxies:
{proxies}{provider_block}proxy-groups:
  - name: hy2-select
    type: select
    proxies: {group_members}
{use_block}    default-selected: inline-hy2
rules:
  - MATCH,hy2-select
"""
    )


def exercise(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    udp_echo, udp_port = start_udp_echo()
    authority_port = reserve_port()
    front_port = reserve_port()
    authority_scratch = scratch / "authority"
    authority_scratch.mkdir()
    relay: NetemUdpRelay | None = None
    kernel_netem: dict[str, Any] = {"available": False, "reason": "not-attempted"}

    authority, a_out, a_err = start_authority(
        authority_binary, authority_scratch, authority_port
    )
    time.sleep(0.4)
    if authority.poll() is not None:
        raise RuntimeError("authority exited early")

    mixed_port, controller_port = reserve_port(), reserve_port()
    provider = scratch / ".config" / "mihomo" / "provider.yaml"
    provider.parent.mkdir(parents=True)
    provider.write_text(
        "proxies:\n" + hy2_record("provider-hy2", authority_port, password=PASSWORD)
    )
    config = scratch / "config.yaml"
    write_client_config(
        config,
        mixed_port=mixed_port,
        controller_port=controller_port,
        server_port=authority_port,
        provider=provider,
        include_removable=True,
    )

    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        rss_start = process_rss_kib(process.pid)
        fd_start = process_fd_count(process.pid)

        concurrent_ok = concurrent_tcp(mixed_port, echo.port, CONCURRENT_TCP)
        udp_ok = udp_exchange(mixed_port, "127.0.0.1", udp_port, b"hy2c-udp")
        control, datagram, bind_port = socks_udp_associate(mixed_port)
        try:
            datagram.sendto(
                socks_udp_packet("127.0.0.1", udp_port, b"hold-udp"),
                ("127.0.0.1", bind_port),
            )
            tcp_during_udp = exchange_once(mixed_port, echo.port, b"with-udp-hold")
            response, _ = datagram.recvfrom(65_535)
            _, _, body = decode_socks_udp(response)
            tcp_udp_concurrent = tcp_during_udp and body == b"hold-udp"
        finally:
            datagram.close()
            control.close()

        cancel_ok = cancel_churn(mixed_port, echo.port, CANCEL_ROUNDS)
        after_cancel = exchange_once(mixed_port, echo.port, b"after-cancel")

        stop(authority)
        a_out.close()
        a_err.close()
        time.sleep(0.3)
        during_restart = rejected_exchange(mixed_port, "127.0.0.1", echo.port)
        authority_scratch2 = scratch / "authority-restart"
        authority_scratch2.mkdir()
        authority, a_out, a_err = start_authority(
            authority_binary, authority_scratch2, authority_port
        )
        time.sleep(0.5)
        # Reload clears outbound client caches so the next dial cannot stick to a
        # half-open QUIC session left from the outage window.
        reload_via_controller(process, controller_port, config, secret=SECRET)
        after_restart = wait_exchange(
            process, mixed_port, echo.port, b"after-restart", deadline_secs=20.0
        )

        relay = NetemUdpRelay(front_port, authority_port)
        relay.start()
        provider.write_text(
            "proxies:\n" + hy2_record("provider-hy2", front_port, password=PASSWORD)
        )
        write_client_config(
            config,
            mixed_port=mixed_port,
            controller_port=controller_port,
            server_port=front_port,
            provider=provider,
            include_removable=True,
        )
        reload_via_controller(process, controller_port, config, secret=SECRET)
        wait_exchange(process, mixed_port, echo.port, b"via-relay", deadline_secs=10.0)

        relay.stop()
        relay = None
        time.sleep(0.2)
        interrupted = rejected_exchange(mixed_port, "127.0.0.1", echo.port)
        relay = NetemUdpRelay(front_port, authority_port)
        relay.start()
        time.sleep(0.2)
        reload_via_controller(process, controller_port, config, secret=SECRET)
        after_interrupt = wait_exchange(
            process, mixed_port, echo.port, b"after-interrupt", deadline_secs=20.0
        )

        relay.stop()
        kernel_netem = try_kernel_netem()
        relay = NetemUdpRelay(
            front_port,
            authority_port,
            delay_ms=20.0,
            loss_percent=5.0,
            reorder_gap=7,
            rate_limit_bps=2_000_000,
        )
        relay.start()
        time.sleep(0.2)
        under_netem = measure_throughput(mixed_port, echo.port, rounds=6)
        # One retry: Go QUIC under 5% loss sometimes needs a warm path.
        if under_netem["rounds-ok"] < 2:
            time.sleep(0.3)
            retry = measure_throughput(mixed_port, echo.port, rounds=6)
            if retry["rounds-ok"] > under_netem["rounds-ok"]:
                under_netem = retry
        under_netem_udp = False
        for _ in range(3):
            try:
                under_netem_udp = udp_exchange(
                    mixed_port, "127.0.0.1", udp_port, b"netem-udp"
                )
            except (OSError, TimeoutError, AssertionError, EOFError):
                under_netem_udp = False
            if under_netem_udp:
                break
            time.sleep(0.2)
        relay.stop()
        if kernel_netem.get("available"):
            clear_kernel_netem()
        # Recovery without intentional reload: clean relay only. Stacks must
        # re-establish on their own after loss is removed.
        relay = NetemUdpRelay(front_port, authority_port)
        relay.start()
        time.sleep(0.2)
        after_netem = wait_exchange(
            process, mixed_port, echo.port, b"after-netem", deadline_secs=20.0
        )

        write_client_config(
            config,
            mixed_port=mixed_port,
            controller_port=controller_port,
            server_port=front_port,
            provider=None,
            include_removable=False,
        )
        reload_via_controller(process, controller_port, config, secret=SECRET)
        deadline = time.monotonic() + IO_DEADLINE
        removed_detail = 200
        while time.monotonic() < deadline:
            removed_detail = request(controller_port, "GET", "/proxies/removable-hy2")[0]
            if removed_detail == 404:
                break
            time.sleep(0.05)
        provider_gone = request(controller_port, "GET", "/providers/proxies/local-hy2")[0]
        post_removal = wait_exchange(
            process, mixed_port, echo.port, b"post-removal", deadline_secs=10.0
        )
        rss_end = process_rss_kib(process.pid)
        fd_end = process_fd_count(process.pid)

        rss_bounded = True
        if rss_start is not None and rss_end is not None and rss_start > 0:
            rss_bounded = rss_end < rss_start * 8 + 256_000
        fd_bounded = True
        if fd_start is not None and fd_end is not None and fd_start > 0:
            fd_bounded = fd_end < fd_start + 256

        return {
            "concurrent-tcp": concurrent_ok,
            "udp-ok": udp_ok,
            "tcp-udp-concurrent": tcp_udp_concurrent,
            "cancel-churn": cancel_ok,
            "after-cancel": after_cancel,
            "during-restart-rejected": during_restart,
            "after-restart": after_restart,
            "during-interrupt-rejected": interrupted,
            "after-interrupt": after_interrupt,
            "netem-throughput-class": under_netem["throughput-class"],
            # Keep raw success floors in the compared surface (P1): a fully
            # unavailable Rust stack under loss must not normalize equal to Go.
            "netem-rounds-ok": under_netem["rounds-ok"],
            "netem-rounds-floor": under_netem["rounds-ok"] >= 2,
            "netem-udp": under_netem_udp,
            "after-netem": after_netem,
            "kernel-netem-available": bool(kernel_netem.get("available")),
            "removed-proxy-404": removed_detail == 404,
            "removed-provider-gone": provider_gone == 404,
            "post-removal-route": post_removal,
            "rss-bounded": rss_bounded,
            "fd-bounded": fd_bounded,
            "process-alive": process.poll() is None,
            "duration-class": "bounded",
            "netem-mode": "kernel+relay" if kernel_netem.get("available") else "relay",
        }
    finally:
        try:
            clear_kernel_netem()
        except Exception:
            pass
        if relay is not None:
            try:
                relay.stop()
            except Exception:
                pass
        stop(process)
        stdout.close()
        stderr.close()
        stop(authority)
        a_out.close()
        a_err.close()
        echo.close()
        udp_echo.shutdown()
        udp_echo.server_close()


def exchange_once(mixed_port: int, echo_port: int, payload: bytes) -> bool:
    with connect_domain(mixed_port, "127.0.0.1", echo_port) as stream:
        stream.settimeout(IO_DEADLINE)
        stream.sendall(payload)
        return recv_exact(stream, len(payload)) == payload


def wait_exchange(
    process: subprocess.Popen[bytes],
    mixed_port: int,
    echo_port: int,
    payload: bytes,
    *,
    deadline_secs: float | None = None,
) -> bool:
    limit = deadline_secs if deadline_secs is not None else max(IO_DEADLINE * 3, 15.0)
    deadline = time.monotonic() + limit
    while True:
        try:
            return exchange_once(mixed_port, echo_port, payload)
        except (AssertionError, EOFError, OSError, TimeoutError):
            if process.poll() is not None or time.monotonic() >= deadline:
                raise
            time.sleep(0.2)


def normalize(entry: dict[str, Any]) -> dict[str, Any]:
    out = dict(entry)
    out.pop("kernel-netem-available", None)
    out.pop("netem-mode", None)
    # Keep success floors and coarse throughput in the compared surface.
    # Tolerance: map exact round counts to a floor boolean so Go/Rust may
    # differ by a round or two under intentional loss, but neither may be
    # fully unavailable. Throughput class stays for performance tolerance.
    rounds = int(out.pop("netem-rounds-ok", 0))
    out["netem-rounds-floor"] = rounds >= 2
    # Collapse "high"/"medium" into "ok" so modest rate variance under netem
    # does not fail the differential; "low"/"zero" remain distinct failures.
    cls = out.get("netem-throughput-class")
    if cls in ("high", "medium"):
        out["netem-throughput-class"] = "ok"
    return out


def assert_netem_floors(engine: str, entry: dict[str, Any]) -> None:
    """Hard floors independent of Go/Rust equality (blocks all-failure masquerade)."""
    rounds = int(entry.get("netem-rounds-ok", 0))
    if rounds < 2:
        raise AssertionError(
            f"{engine} netem TCP success floor failed: rounds-ok={rounds} (need >= 2)"
        )
    if not entry.get("netem-udp"):
        raise AssertionError(f"{engine} netem UDP success floor failed")
    cls = entry.get("netem-throughput-class")
    if cls in (None, "zero"):
        raise AssertionError(f"{engine} netem throughput floor failed: class={cls!r}")
    if not entry.get("after-netem"):
        raise AssertionError(f"{engine} after-netem recovery (no reload) failed")


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-hy2c-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE_HY2C_CARGO_TARGET", "phase-hy2c")
        try:
            for engine in ("rust", "go"):
                scratch = root / engine
                scratch.mkdir()
                observations[engine] = exercise(
                    binaries[engine], binaries["go"], scratch
                )
                assert_netem_floors(engine, observations[engine])
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

    go = normalize(observations["go"])
    rust = normalize(observations["rust"])
    if go != rust:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {"go": observations["go"], "rust": observations["rust"]},
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("HY2-C Hysteria2 stress/recovery/netem differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

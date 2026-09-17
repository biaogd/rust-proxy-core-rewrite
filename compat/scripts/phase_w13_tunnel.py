#!/usr/bin/env python3
"""W1.3 static tunnels TCP (+ UDP) config and DIRECT echo differential.

Unprivileged:
  - Go and Rust `-t` accept `tunnels:` one-liner forms
  - Missing tunnel proxy is rejected
  - TCP tunnel → fixed target echo (MATCH,DIRECT) must match Go/Rust payload
  - UDP tunnel → fixed target echo must match Go/Rust payload
"""

from __future__ import annotations

import json
import pathlib
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from phase1 import ROOT, assert_go_oracle_baseline, terminate_process
from phase3 import launch, stop
from phase5b1a import build_binaries

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-w13-tunnel-diff.json"
SCRIPT = pathlib.Path(__file__).resolve()
TCP_PAYLOAD = b"phase-w13-tunnel-tcp-echo\n"
UDP_PAYLOAD = b"phase-w13-tunnel-udp-echo"


class _TcpEcho(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request.recv(65535)
        if data:
            self.request.sendall(data)


class _UdpEcho(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0]
        sock = self.request[1]
        sock.sendto(data, self.client_address)


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def reserve_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def write_config(path: pathlib.Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


def validate_config(binary: pathlib.Path, config: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), "-t", "-f", str(config), "-d", str(config.parent)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def tunnel_yaml(*, tunnel_listen: int, target_port: int, udp_listen: int, udp_target: int) -> str:
    return (
        "mode: rule\n"
        "log-level: info\n"
        "ipv6: false\n"
        "tunnels:\n"
        f"  - tcp,127.0.0.1:{tunnel_listen},127.0.0.1:{target_port}\n"
        f"  - udp,127.0.0.1:{udp_listen},127.0.0.1:{udp_target}\n"
        "rules:\n"
        "  - MATCH,DIRECT\n"
    )


def bad_proxy_yaml(*, tunnel_listen: int, target_port: int) -> str:
    return (
        "mode: rule\n"
        "ipv6: false\n"
        "tunnels:\n"
        f"  - tcp,127.0.0.1:{tunnel_listen},127.0.0.1:{target_port},no-such-proxy\n"
        "rules:\n"
        "  - MATCH,DIRECT\n"
    )


def wait_tcp(host: str, port: int, deadline: float = 15.0) -> None:
    end = time.time() + deadline
    last: Exception | None = None
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as error:
            last = error
            time.sleep(0.05)
    raise TimeoutError(f"{host}:{port} not ready: {last}")


def tcp_echo_through(listen_port: int) -> bytes:
    with socket.create_connection(("127.0.0.1", listen_port), timeout=5.0) as client:
        client.settimeout(5.0)
        client.sendall(TCP_PAYLOAD)
        received = b""
        while len(received) < len(TCP_PAYLOAD):
            chunk = client.recv(64)
            if not chunk:
                break
            received += chunk
        return received


def udp_echo_through(listen_port: int) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5.0)
        client.sendto(UDP_PAYLOAD, ("127.0.0.1", listen_port))
        data, _ = client.recvfrom(65535)
        return data


def run_cases(binaries: dict[str, pathlib.Path]) -> dict[str, Any]:
    results: dict[str, Any] = {"platform": sys.platform, "cases": {}}
    with tempfile.TemporaryDirectory(prefix="phase-w13-tunnel-") as tmp:
        scratch = pathlib.Path(tmp)

        bad_path = scratch / "bad-proxy.yaml"
        write_config(
            bad_path,
            bad_proxy_yaml(tunnel_listen=reserve_port(), target_port=reserve_port()),
        )
        for name, binary in binaries.items():
            validated = validate_config(binary, bad_path)
            results["cases"][f"{name}-reject-missing-proxy"] = {
                "returncode": validated.returncode,
                "stderr": validated.stderr[-400:],
            }
            if validated.returncode == 0:
                raise AssertionError(f"{name} accepted missing tunnel proxy")

        for name, binary in binaries.items():
            home = scratch / f"home-{name}"
            home.mkdir()
            cfg = home / "config.yaml"
            target_port = reserve_port()
            tunnel_listen = reserve_port()
            udp_target = reserve_udp_port()
            udp_listen = reserve_udp_port()
            write_config(
                cfg,
                tunnel_yaml(
                    tunnel_listen=tunnel_listen,
                    target_port=target_port,
                    udp_listen=udp_listen,
                    udp_target=udp_target,
                ),
            )
            validated = validate_config(binary, cfg)
            results["cases"][f"{name}-validate-tunnels"] = {
                "returncode": validated.returncode,
                "stderr": validated.stderr[-400:],
            }
            if validated.returncode != 0:
                raise AssertionError(f"{name} rejected tunnels: {validated.stderr}")

            tcp_server = socketserver.ThreadingTCPServer(("127.0.0.1", target_port), _TcpEcho)
            tcp_server.allow_reuse_address = True
            tcp_thread = threading.Thread(target=tcp_server.serve_forever, daemon=True)
            tcp_thread.start()

            udp_server = socketserver.ThreadingUDPServer(("127.0.0.1", udp_target), _UdpEcho)
            udp_server.allow_reuse_address = True
            udp_thread = threading.Thread(target=udp_server.serve_forever, daemon=True)
            udp_thread.start()

            process, _stdout, _stderr = launch(binary, cfg, home)
            try:
                wait_tcp("127.0.0.1", tunnel_listen)
                tcp_got = tcp_echo_through(tunnel_listen)
                results["cases"][f"{name}-tcp-echo"] = tcp_got.decode("utf-8", errors="replace")
                if tcp_got != TCP_PAYLOAD:
                    raise AssertionError(f"{name} TCP tunnel mismatch: {tcp_got!r}")

                udp_got = udp_echo_through(udp_listen)
                results["cases"][f"{name}-udp-echo"] = udp_got.decode("utf-8", errors="replace")
                if udp_got != UDP_PAYLOAD:
                    raise AssertionError(f"{name} UDP tunnel mismatch: {udp_got!r}")
            finally:
                stop(process)
                terminate_process(process)
                tcp_server.shutdown()
                udp_server.shutdown()
                tcp_server.server_close()
                udp_server.server_close()
    return results


def main() -> int:
    assert_go_oracle_baseline()
    with tempfile.TemporaryDirectory(prefix="phase-w13-build-") as tmp:
        binaries = build_binaries(pathlib.Path(tmp))
        try:
            observation = {
                "script": str(SCRIPT),
                "unprivileged": run_cases(binaries),
            }
        except Exception as error:  # noqa: BLE001
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps({"error": str(error)}, indent=2) + "\n",
                encoding="utf-8",
            )
            print(f"W1.3 tunnel gate failed: {error}", file=sys.stderr)
            return 1

    print(json.dumps(observation, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Go/Rust differential for 6I-A WireGuard userspace outbound TCP."""

from __future__ import annotations

import concurrent.futures
import http.server
import json
import os
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import Any

from hy2_support import build_binaries
from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    cargo_target_path,
    recv_exact,
    reload_via_controller,
    reserve_port,
    wait_ready,
)
from phase3 import launch, stop
from phase5b1a import connect_domain, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_tcp import rejected_exchange


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6i-wireguard-tcp-diff.json"
LARGE_PAYLOAD = bytes(range(256)) * 512
CLIENT_IP = "10.0.0.2"


def reachable_ipv4() -> str:
    """Inner TCP dest for Go mipstack: 127.0.0.0/8 is unreachable through WG."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("1.1.1.1", 80))
        ip = sock.getsockname()[0]
    if ip.startswith("127."):
        raise RuntimeError("WireGuard inner TCP needs a non-loopback IPv4")
    return ip


def listen_ipv4(handler: type[socketserver.BaseRequestHandler]) -> tuple[
    socketserver.ThreadingTCPServer, threading.Thread, int
]:
    server = socketserver.ThreadingTCPServer(("0.0.0.0", 0), handler)
    server.allow_reuse_address = True
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, port


def unused_port_on(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


def generate_keypair(binary: pathlib.Path, scratch: pathlib.Path) -> tuple[str, str]:
    result = subprocess.run(
        [str(binary), "generate", "wg-keypair"],
        cwd=scratch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        timeout=IO_DEADLINE,
    )
    lines = result.stdout.decode().splitlines()
    return lines[0].removeprefix("PrivateKey: "), lines[1].removeprefix("PublicKey: ")


def authority_binary() -> pathlib.Path:
    target = cargo_target_path("PHASE6IWG_CARGO_TARGET", "phase-6ia")
    profile = os.environ.get("HY2_BUILD_PROFILE", "debug")
    suffix = ".exe" if os.name == "nt" else ""
    return target / profile / f"rewrite-wireguard-authority{suffix}"


def wg_record(
    name: str,
    server_port: int,
    private_key: str,
    public_key: str,
    *,
    extra: str = "",
) -> str:
    return f"""  - name: {name}
    type: wireguard
    server: 127.0.0.1
    port: {server_port}
    private-key: {private_key}
    public-key: {public_key}
    ip: {CLIENT_IP}
{extra}"""


def exchange(
    port: int,
    host: str,
    target_port: int,
    payload: bytes,
    *,
    half_close: bool = False,
    timeout: float | None = None,
) -> bool:
    stream_timeout = IO_DEADLINE if timeout is None else timeout
    with connect_domain(port, host, target_port) as stream:
        stream.settimeout(stream_timeout)
        stream.sendall(payload)
        if half_close:
            first = recv_exact(stream, 1)
            stream.shutdown(socket.SHUT_WR)
            rest = recv_exact(stream, len(payload) - 1) if len(payload) > 1 else b""
            return first + rest == payload
        return recv_exact(stream, len(payload)) == payload


def wait_exchange(
    process: subprocess.Popen[bytes],
    port: int,
    host: str,
    target_port: int,
    payload: bytes,
    *,
    deadline_secs: float | None = None,
) -> bool:
    limit = deadline_secs if deadline_secs is not None else max(IO_DEADLINE * 4, 20.0)
    attempt_timeout = min(IO_DEADLINE, 3.0)
    deadline = time.monotonic() + limit
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            return exchange(port, host, target_port, payload, timeout=attempt_timeout)
        except (
            AssertionError,
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionResetError,
            EOFError,
            OSError,
            TimeoutError,
        ) as error:
            last_error = error
            time.sleep(0.15)
    if last_error is not None:
        raise last_error
    raise TimeoutError("wait_exchange exhausted without a successful exchange")


def config_validation(binary: pathlib.Path, scratch: pathlib.Path, body: str) -> bool:
    scratch.mkdir(parents=True, exist_ok=True)
    config = scratch / f"validate-{len(list(scratch.glob('validate-*')))}.yaml"
    config.write_text(
        f"""mixed-port: 0
mode: rule
log-level: info
ipv6: false
{body}
rules:
  - MATCH,DIRECT
"""
    )
    result = subprocess.run(
        [str(binary), "-t", "-f", str(config)],
        cwd=scratch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=IO_DEADLINE,
    )
    return result.returncode == 0


def proxy_snapshot(
    controller_port: int, name: str, provider: str | None = None
) -> dict[str, Any]:
    path = (
        f"/providers/proxies/{provider}/{name}"
        if provider is not None
        else f"/proxies/{name}"
    )
    status, body = request(controller_port, "GET", path)
    if status != 200:
        raise AssertionError((status, body))
    value = json.loads(body)
    return {
        "name": value["name"],
        "type": value["type"],
        "udp": value["udp"],
        "uot": value.get("uot", False),
    }


def start_authority(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    listen_port: int,
    private_key: str,
    peer_public_key: str,
) -> tuple[subprocess.Popen[bytes], Any, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    stdout_path = scratch / "authority-stdout.log"
    stderr_path = scratch / "authority-stderr.log"
    stdout = stdout_path.open("wb")
    stderr = stderr_path.open("wb")
    process = subprocess.Popen(
        [
            str(binary),
            f"127.0.0.1:{listen_port}",
            private_key,
            peer_public_key,
        ],
        cwd=scratch,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            logs = ""
            for path in (stdout_path, stderr_path):
                if path.exists():
                    logs += f"\n[{path.name}]\n{path.read_text(errors='replace')[-4000:]}"
            raise RuntimeError(
                f"WireGuard authority exited with {process.returncode}:{logs}"
            )
        if stdout_path.exists() and "READY" in stdout_path.read_text(errors="replace"):
            return process, stdout, stderr
        time.sleep(0.02)
    raise TimeoutError("WireGuard authority did not become ready")


def cancel_one_keep_other(mixed_port: int, host: str, echo_port: int) -> bool:
    first = connect_domain(mixed_port, host, echo_port)
    first.settimeout(IO_DEADLINE)
    second = connect_domain(mixed_port, host, echo_port)
    second.settimeout(IO_DEADLINE)
    try:
        first.sendall(b"cancel-me")
        second.sendall(b"keep-alive-stream")
        first.close()
        return recv_exact(second, len(b"keep-alive-stream")) == b"keep-alive-stream"
    finally:
        try:
            second.close()
        except OSError:
            pass


def exercise(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    client_private: str,
    client_public: str,
    server_private: str,
    server_public: str,
) -> dict[str, Any]:
    inner_host = reachable_ipv4()
    echo, echo_thread, echo_port = listen_ipv4(EchoHandler)
    _ = echo_thread

    health, health_thread, health_port = listen_ipv4(HealthHandler)
    _ = health_thread

    mixed_port, controller_port, authority_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    wrong_rule_port = unused_port_on(inner_host)
    authority_scratch = scratch / "authority"
    wg_process, authority_stdout, authority_stderr = start_authority(
        authority,
        authority_scratch,
        authority_port,
        server_private,
        client_public,
    )

    provider = scratch / ".config" / "mihomo" / "provider.yaml"
    provider.parent.mkdir(parents=True)
    provider.write_text(
        "proxies:\n"
        + wg_record("provider-wg", authority_port, client_private, server_public)
    )

    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
hosts:
  echo.wg.test: {inner_host}
proxies:
{wg_record("inline-wg", authority_port, client_private, server_public)}
{wg_record("wg-wrong-key", authority_port, client_private, client_public)}
proxy-providers:
  local-wg:
    type: file
    path: {provider}
proxy-groups:
  - name: wg-select
    type: select
    proxies: [inline-wg]
    use: [local-wg]
    default-selected: inline-wg
  - name: wg-health
    type: url-test
    proxies: [inline-wg]
    url: http://{inner_host}:{health_port}/
    interval: 3600
    tolerance: 50
rules:
  - DST-PORT,{wrong_rule_port},wg-wrong-key
  - MATCH,wg-select
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        time.sleep(0.3)

        domain_small = wait_exchange(
            process, mixed_port, "echo.wg.test", echo_port, b"wg-domain"
        )
        ipv4_large = False
        for _ in range(5):
            try:
                ipv4_large = exchange(mixed_port, inner_host, echo_port, LARGE_PAYLOAD)
                if ipv4_large:
                    break
            except (
                AssertionError,
                BrokenPipeError,
                ConnectionAbortedError,
                ConnectionResetError,
                EOFError,
                OSError,
                TimeoutError,
            ):
                ipv4_large = False
                time.sleep(0.1)

        half_close = exchange(
            mixed_port,
            inner_host,
            echo_port,
            b"wg-half-close",
            half_close=True,
        )
        reuse_second = exchange(mixed_port, inner_host, echo_port, b"wg-reuse")

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [
                pool.submit(
                    exchange, mixed_port, inner_host, echo_port, f"c{i}".encode()
                )
                for i in range(4)
            ]
            concurrent_ok = all(future.result(timeout=IO_DEADLINE) for future in futures)
        cancel_isolated = cancel_one_keep_other(mixed_port, inner_host, echo_port)

        wrong_key = rejected_exchange(mixed_port, inner_host, wrong_rule_port)
        survived_wrong_key = process.poll() is None
        after_auth_fail = exchange(mixed_port, inner_host, echo_port, b"after-auth-fail")

        refused_target = unused_port_on(inner_host)
        target_refused = rejected_exchange(mixed_port, inner_host, refused_target)
        survived_target_refused = process.poll() is None
        after_refused = exchange(mixed_port, inner_host, echo_port, b"after-refused")

        selected = request(
            controller_port,
            "PUT",
            "/proxies/wg-select",
            {"name": "provider-wg"},
        )
        if selected[0] != 204:
            raise AssertionError(selected)
        provider_route = wait_exchange(
            process, mixed_port, inner_host, echo_port, b"provider-route"
        )
        inline_snapshot = proxy_snapshot(controller_port, "inline-wg")
        provider_snapshot = proxy_snapshot(controller_port, "provider-wg", "local-wg")

        health_query = f"url=http://{inner_host}:{health_port}/&timeout=5000"
        health_status, health_body = request(
            controller_port, "GET", f"/group/wg-health/delay?{health_query}"
        )
        health_ok = health_status == 200 and b"inline-wg" in health_body

        reload_via_controller(process, controller_port, config, secret=SECRET)
        after_reload = wait_exchange(
            process, mixed_port, "echo.wg.test", echo_port, b"after-reload"
        )

        return {
            "domain-small": domain_small,
            "ipv4-large": ipv4_large,
            "half-close": half_close,
            "reuse-second": reuse_second,
            "concurrent-ok": concurrent_ok,
            "cancel-isolated": cancel_isolated,
            "wrong-key-rejected": wrong_key,
            "survived-wrong-key": survived_wrong_key,
            "after-auth-fail": after_auth_fail,
            "target-refused": target_refused,
            "survived-target-refused": survived_target_refused,
            "after-refused": after_refused,
            "provider-route": provider_route,
            "inline-snapshot": inline_snapshot,
            "provider-snapshot": {
                "name": provider_snapshot["name"],
                "type": provider_snapshot["type"],
                "udp": provider_snapshot["udp"],
            },
            "health-ok": health_ok,
            "after-reload": after_reload,
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop(wg_process)
        authority_stdout.close()
        authority_stderr.close()
        echo.shutdown()
        echo.server_close()
        health.shutdown()
        health.server_close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-6ia-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6IWG_CARGO_TARGET", "phase-6ia")
        authority = authority_binary()
        if not authority.exists():
            raise RuntimeError(f"rewrite-wireguard-authority was not built: {authority}")
        key_scratch = root / "keys"
        key_scratch.mkdir()
        client_private, client_public = generate_keypair(binaries["rust"], key_scratch)
        server_private, server_public = generate_keypair(binaries["rust"], key_scratch)
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(
                    binaries[name],
                    authority,
                    scratch,
                    client_private,
                    client_public,
                    server_private,
                    server_public,
                )
            observations["rust-amnezia-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-amnezia",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: wireguard\n"
                "    server: 127.0.0.1\n"
                "    port: 51820\n"
                f"    private-key: {client_private}\n"
                f"    public-key: {server_public}\n"
                "    ip: 10.0.0.2\n"
                "    amnezia-wg-option:\n"
                "      jc: 4\n",
            )
            observations["rust-peers-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-peers",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: wireguard\n"
                "    server: 127.0.0.1\n"
                "    port: 51820\n"
                f"    private-key: {client_private}\n"
                f"    public-key: {server_public}\n"
                "    ip: 10.0.0.2\n"
                "    peers:\n"
                "      - server: 127.0.0.1\n"
                "        port: 51820\n"
                f"        public-key: {server_public}\n"
                "        allowed-ips: [0.0.0.0/0]\n",
            )
            observations["rust-ipv6-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-ipv6",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: wireguard\n"
                "    server: 127.0.0.1\n"
                "    port: 51820\n"
                f"    private-key: {client_private}\n"
                f"    public-key: {server_public}\n"
                "    ip: 10.0.0.2\n"
                "    ipv6: fd00::2\n",
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
    if (
        go != rust
        or not observations.get("rust-amnezia-rejected", False)
        or not observations.get("rust-peers-rejected", False)
        or not observations.get("rust-ipv6-rejected", False)
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {
                    "go": go,
                    "rust": rust,
                    "rust-amnezia-rejected": observations.get("rust-amnezia-rejected"),
                    "rust-peers-rejected": observations.get("rust-peers-rejected"),
                    "rust-ipv6-rejected": observations.get("rust-ipv6-rejected"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("6I-A WireGuard TCP differential passed")
    print(json.dumps(rust, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

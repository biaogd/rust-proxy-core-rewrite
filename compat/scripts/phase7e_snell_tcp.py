#!/usr/bin/env python3
"""Go/Rust differential for 7E-A Snell versions 1/3 TCP outbound."""

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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase7e-snell-tcp-diff.json"
LARGE_PAYLOAD = bytes(range(256)) * 512
PSK = "password"
PSK_V3 = "phase7e-psk"


def unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
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


def authority_binary() -> pathlib.Path:
    target = cargo_target_path("PHASE7ESNELL_CARGO_TARGET", "phase-7ea")
    profile = os.environ.get("HY2_BUILD_PROFILE", "debug")
    suffix = ".exe" if os.name == "nt" else ""
    return target / profile / f"rewrite-snell-authority{suffix}"


def snell_record(
    name: str,
    server_port: int,
    psk: str,
    *,
    version: int | None = None,
    extra: str = "",
) -> str:
    version_line = f"    version: {version}\n" if version is not None else ""
    return f"""  - name: {name}
    type: snell
    server: 127.0.0.1
    port: {server_port}
    psk: {psk}
{version_line}{extra}"""


def exchange(
    port: int,
    host: str,
    target_port: int,
    payload: bytes,
    *,
    timeout: float | None = None,
) -> bool:
    stream_timeout = IO_DEADLINE if timeout is None else timeout
    with connect_domain(port, host, target_port) as stream:
        stream.settimeout(stream_timeout)
        stream.sendall(payload)
        return recv_exact(stream, len(payload)) == payload


def wait_exchange(
    process: subprocess.Popen[bytes],
    port: int,
    host: str,
    target_port: int,
    payload: bytes,
) -> bool:
    deadline = time.monotonic() + max(IO_DEADLINE * 4, 20.0)
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            return exchange(port, host, target_port, payload, timeout=min(IO_DEADLINE, 3.0))
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
    }


def start_authority(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    listen_port: int,
    psk: str,
    version: int,
) -> tuple[subprocess.Popen[bytes], Any, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    stdout_path = scratch / "authority-stdout.log"
    stderr_path = scratch / "authority-stderr.log"
    stdout = stdout_path.open("wb")
    stderr = stderr_path.open("wb")
    process = subprocess.Popen(
        [str(binary), f"127.0.0.1:{listen_port}", psk, str(version)],
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
                f"Snell authority exited with {process.returncode}:{logs}"
            )
        if stdout_path.exists() and "READY" in stdout_path.read_text(errors="replace"):
            return process, stdout, stderr
        time.sleep(0.02)
    raise TimeoutError("Snell authority did not become ready")


def listen_echo() -> tuple[socketserver.ThreadingTCPServer, threading.Thread, int]:
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    server.allow_reuse_address = True
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, port


def listen_health() -> tuple[socketserver.ThreadingTCPServer, threading.Thread, int]:
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), HealthHandler)
    server.allow_reuse_address = True
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, port


def exercise(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    echo, echo_thread, echo_port = listen_echo()
    _ = echo_thread
    health, health_thread, health_port = listen_health()
    _ = health_thread

    mixed_port, controller_port, v1_port, v3_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    wrong_rule_port = unused_port()
    v1_process, v1_stdout, v1_stderr = start_authority(
        authority, scratch / "authority-v1", v1_port, PSK, 1
    )
    v3_process, v3_stdout, v3_stderr = start_authority(
        authority, scratch / "authority-v3", v3_port, PSK_V3, 3
    )

    provider = scratch / ".config" / "mihomo" / "provider.yaml"
    provider.parent.mkdir(parents=True)
    provider.write_text("proxies:\n" + snell_record("provider-snell", v1_port, PSK))

    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
hosts:
  echo.snell.test: 127.0.0.1
proxies:
{snell_record("inline-snell", v1_port, PSK)}
{snell_record("snell-v3", v3_port, PSK_V3, version=3)}
{snell_record("snell-wrong-psk", v1_port, "wrong-password")}
proxy-providers:
  local-snell:
    type: file
    path: {provider}
proxy-groups:
  - name: snell-select
    type: select
    proxies: [inline-snell]
    use: [local-snell]
    default-selected: inline-snell
  - name: snell-health
    type: url-test
    proxies: [inline-snell]
    url: http://127.0.0.1:{health_port}/
    interval: 3600
    tolerance: 50
rules:
  - DST-PORT,{echo_port},snell-v3
  - DST-PORT,{wrong_rule_port},snell-wrong-psk
  - MATCH,snell-select
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        time.sleep(0.3)

        # DST-PORT,{echo_port},snell-v3 wins for the echo port, so v1 tests
        # use a second echo listener.
        echo_v1, echo_v1_thread, echo_v1_port = listen_echo()
        _ = echo_v1_thread
        try:
            domain_small = wait_exchange(
                process, mixed_port, "echo.snell.test", echo_v1_port, b"snell-v1"
            )
            ipv4_large = exchange(mixed_port, "127.0.0.1", echo_v1_port, LARGE_PAYLOAD)
            v3_small = exchange(mixed_port, "127.0.0.1", echo_port, b"snell-v3")
            reuse_second = exchange(mixed_port, "127.0.0.1", echo_v1_port, b"snell-reuse")
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                futures = [
                    pool.submit(
                        exchange, mixed_port, "127.0.0.1", echo_v1_port, f"c{i}".encode()
                    )
                    for i in range(4)
                ]
                concurrent_ok = all(
                    future.result(timeout=IO_DEADLINE) for future in futures
                )

            wrong_psk = rejected_exchange(mixed_port, "127.0.0.1", wrong_rule_port)
            survived_wrong_psk = process.poll() is None
            after_auth_fail = exchange(
                mixed_port, "127.0.0.1", echo_v1_port, b"after-auth-fail"
            )

            refused_target = unused_port()
            target_refused = rejected_exchange(mixed_port, "127.0.0.1", refused_target)
            survived_target_refused = process.poll() is None
            after_refused = exchange(
                mixed_port, "127.0.0.1", echo_v1_port, b"after-refused"
            )

            selected = request(
                controller_port,
                "PUT",
                "/proxies/snell-select",
                {"name": "provider-snell"},
            )
            if selected[0] != 204:
                raise AssertionError(selected)
            provider_route = wait_exchange(
                process, mixed_port, "127.0.0.1", echo_v1_port, b"provider-route"
            )
            inline_snapshot = proxy_snapshot(controller_port, "inline-snell")
            provider_snapshot = proxy_snapshot(
                controller_port, "provider-snell", "local-snell"
            )

            health_query = f"url=http://127.0.0.1:{health_port}/&timeout=5000"
            health_status, health_body = request(
                controller_port, "GET", f"/group/snell-health/delay?{health_query}"
            )
            health_ok = health_status == 200 and b"inline-snell" in health_body

            reload_via_controller(process, controller_port, config, secret=SECRET)
            after_reload = wait_exchange(
                process, mixed_port, "echo.snell.test", echo_v1_port, b"after-reload"
            )
        finally:
            echo_v1.shutdown()
            echo_v1.server_close()

        return {
            "domain-small": domain_small,
            "ipv4-large": ipv4_large,
            "v3-small": v3_small,
            "reuse-second": reuse_second,
            "concurrent-ok": concurrent_ok,
            "wrong-psk-rejected": wrong_psk,
            "survived-wrong-psk": survived_wrong_psk,
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
        stop(v1_process)
        stop(v3_process)
        v1_stdout.close()
        v1_stderr.close()
        v3_stdout.close()
        v3_stderr.close()
        echo.shutdown()
        echo.server_close()
        health.shutdown()
        health.server_close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-7ea-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE7ESNELL_CARGO_TARGET", "phase-7ea")
        authority = authority_binary()
        if not authority.exists():
            raise RuntimeError(f"rewrite-snell-authority was not built: {authority}")
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], authority, scratch)
            observations["rust-udp-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-udp",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK}\n"
                "    udp: true\n",
            )
            observations["rust-reuse-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-reuse",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK}\n"
                "    reuse: true\n",
            )
            observations["rust-obfs-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-obfs",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK}\n"
                "    obfs-opts:\n"
                "      mode: http\n",
            )
            observations["rust-v4-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-v4",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK}\n"
                "    version: 4\n",
            )
            observations["rust-v1-accepted"] = config_validation(
                binaries["rust"],
                root / "rust-validate-v1",
                "proxies:\n"
                "  - name: ok\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK}\n",
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
    rust_only = [
        "rust-udp-rejected",
        "rust-reuse-rejected",
        "rust-obfs-rejected",
        "rust-v4-rejected",
        "rust-v1-accepted",
    ]
    if go != rust or not all(observations.get(key) for key in rust_only):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {
                    "go": go,
                    "rust": rust,
                    **{key: observations.get(key) for key in rust_only},
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("7E-A Snell TCP differential passed")
    print(json.dumps(rust, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

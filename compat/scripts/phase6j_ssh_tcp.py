#!/usr/bin/env python3
"""Go/Rust differential for 6J-A SSH outbound TCP."""

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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6j-ssh-tcp-diff.json"
LARGE_PAYLOAD = bytes(range(256)) * 512
USERNAME = "alice"
PASSWORD = "secret"
WRONG_PASSWORD = "wrong-secret"


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


def unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def authority_binary() -> pathlib.Path:
    target = cargo_target_path("PHASE6JSSH_CARGO_TARGET", "phase-6ja")
    profile = os.environ.get("HY2_BUILD_PROFILE", "debug")
    suffix = ".exe" if os.name == "nt" else ""
    return target / profile / f"rewrite-ssh-authority{suffix}"


def ssh_record(
    name: str, server_port: int, *, extra: str = "", password: str | None = PASSWORD
) -> str:
    password_line = f"    password: {password}\n" if password is not None else ""
    return f"""  - name: {name}
    type: ssh
    server: 127.0.0.1
    port: {server_port}
    username: {USERNAME}
{password_line}{extra}"""


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
    *,
    authorized_key: str | None = None,
) -> tuple[subprocess.Popen[bytes], Any, Any, str]:
    scratch.mkdir(parents=True, exist_ok=True)
    stdout_path = scratch / "authority-stdout.log"
    stderr_path = scratch / "authority-stderr.log"
    stdout = stdout_path.open("wb")
    stderr = stderr_path.open("wb")
    command = [str(binary), f"127.0.0.1:{listen_port}", USERNAME, PASSWORD]
    if authorized_key:
        command.append(authorized_key)
    process = subprocess.Popen(
        command,
        cwd=scratch,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    deadline = time.monotonic() + IO_DEADLINE
    host_key = ""
    while time.monotonic() < deadline:
        if process.poll() is not None:
            logs = ""
            for path in (stdout_path, stderr_path):
                if path.exists():
                    logs += f"\n[{path.name}]\n{path.read_text(errors='replace')[-4000:]}"
            raise RuntimeError(f"SSH authority exited with {process.returncode}:{logs}")
        if stdout_path.exists():
            text = stdout_path.read_text(errors="replace")
            if "READY" in text:
                for line in text.splitlines():
                    if line.startswith("HOST_KEY "):
                        host_key = line.removeprefix("HOST_KEY ").strip()
                return process, stdout, stderr, host_key
        time.sleep(0.02)
    raise TimeoutError("SSH authority did not become ready")


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


def listen_local(handler: type[socketserver.BaseRequestHandler]) -> tuple[
    socketserver.ThreadingTCPServer, threading.Thread, int
]:
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
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
    echo, echo_thread, echo_port = listen_local(EchoHandler)
    _ = echo_thread
    health, health_thread, health_port = listen_local(HealthHandler)
    _ = health_thread

    mixed_port, controller_port, authority_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    wrong_rule_port = unused_port()
    authority_scratch = scratch / "authority"
    ssh_process, authority_stdout, authority_stderr, host_key = start_authority(
        authority, authority_scratch, authority_port
    )

    provider = scratch / ".config" / "mihomo" / "provider.yaml"
    provider.parent.mkdir(parents=True)
    provider.write_text("proxies:\n" + ssh_record("provider-ssh", authority_port))

    host_key_extra = f"    host-key:\n      - {host_key}\n" if host_key else ""
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
hosts:
  echo.ssh.test: 127.0.0.1
proxies:
{ssh_record("inline-ssh", authority_port, extra=host_key_extra)}
{ssh_record("ssh-wrong-pass", authority_port, password=WRONG_PASSWORD)}
proxy-providers:
  local-ssh:
    type: file
    path: {provider}
proxy-groups:
  - name: ssh-select
    type: select
    proxies: [inline-ssh]
    use: [local-ssh]
    default-selected: inline-ssh
  - name: ssh-health
    type: url-test
    proxies: [inline-ssh]
    url: http://127.0.0.1:{health_port}/
    interval: 3600
    tolerance: 50
rules:
  - DST-PORT,{wrong_rule_port},ssh-wrong-pass
  - MATCH,ssh-select
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        time.sleep(0.3)

        domain_small = wait_exchange(
            process, mixed_port, "echo.ssh.test", echo_port, b"ssh-domain"
        )
        ipv4_large = False
        for _ in range(5):
            try:
                ipv4_large = exchange(mixed_port, "127.0.0.1", echo_port, LARGE_PAYLOAD)
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
            "127.0.0.1",
            echo_port,
            b"ssh-half-close",
            half_close=True,
        )
        reuse_second = exchange(mixed_port, "127.0.0.1", echo_port, b"ssh-reuse")

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [
                pool.submit(
                    exchange, mixed_port, "127.0.0.1", echo_port, f"c{i}".encode()
                )
                for i in range(4)
            ]
            concurrent_ok = all(future.result(timeout=IO_DEADLINE) for future in futures)
        cancel_isolated = cancel_one_keep_other(mixed_port, "127.0.0.1", echo_port)

        wrong_pass = rejected_exchange(mixed_port, "127.0.0.1", wrong_rule_port)
        survived_wrong_pass = process.poll() is None
        after_auth_fail = exchange(mixed_port, "127.0.0.1", echo_port, b"after-auth-fail")

        refused_target = unused_port()
        target_refused = rejected_exchange(mixed_port, "127.0.0.1", refused_target)
        survived_target_refused = process.poll() is None
        after_refused = exchange(mixed_port, "127.0.0.1", echo_port, b"after-refused")

        selected = request(
            controller_port,
            "PUT",
            "/proxies/ssh-select",
            {"name": "provider-ssh"},
        )
        if selected[0] != 204:
            raise AssertionError(selected)
        provider_route = wait_exchange(
            process, mixed_port, "127.0.0.1", echo_port, b"provider-route"
        )
        inline_snapshot = proxy_snapshot(controller_port, "inline-ssh")
        provider_snapshot = proxy_snapshot(controller_port, "provider-ssh", "local-ssh")

        health_query = f"url=http://127.0.0.1:{health_port}/&timeout=5000"
        health_status, health_body = request(
            controller_port, "GET", f"/group/ssh-health/delay?{health_query}"
        )
        health_ok = health_status == 200 and b"inline-ssh" in health_body

        reload_via_controller(process, controller_port, config, secret=SECRET)
        after_reload = wait_exchange(
            process, mixed_port, "echo.ssh.test", echo_port, b"after-reload"
        )

        return {
            "domain-small": domain_small,
            "ipv4-large": ipv4_large,
            "half-close": half_close,
            "reuse-second": reuse_second,
            "concurrent-ok": concurrent_ok,
            "cancel-isolated": cancel_isolated,
            "wrong-pass-rejected": wrong_pass,
            "survived-wrong-pass": survived_wrong_pass,
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
        stop(ssh_process)
        authority_stdout.close()
        authority_stderr.close()
        echo.shutdown()
        echo.server_close()
        health.shutdown()
        health.server_close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-6ja-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6JSSH_CARGO_TARGET", "phase-6ja")
        authority = authority_binary()
        if not authority.exists():
            raise RuntimeError(f"rewrite-ssh-authority was not built: {authority}")
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
                "    type: ssh\n"
                "    server: 127.0.0.1\n"
                "    port: 22\n"
                f"    username: {USERNAME}\n"
                f"    password: {PASSWORD}\n"
                "    udp: true\n",
            )
            observations["rust-dialer-proxy-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-dialer",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: ssh\n"
                "    server: 127.0.0.1\n"
                "    port: 22\n"
                f"    username: {USERNAME}\n"
                f"    password: {PASSWORD}\n"
                "    dialer-proxy: other\n",
            )
            observations["rust-host-key-accepted"] = config_validation(
                binaries["rust"],
                root / "rust-validate-host-key",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: ssh\n"
                "    server: 127.0.0.1\n"
                "    port: 22\n"
                f"    username: {USERNAME}\n"
                f"    password: {PASSWORD}\n"
                "    host-key:\n"
                "      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIkBPFDYJnKqQmG9M8V7XJk7/99afMObZ6Aph1lh6mb7 comment\n",
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
        or not observations.get("rust-udp-rejected", False)
        or not observations.get("rust-dialer-proxy-rejected", False)
        or not observations.get("rust-host-key-accepted", False)
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {
                    "go": go,
                    "rust": rust,
                    "rust-udp-rejected": observations.get("rust-udp-rejected"),
                    "rust-dialer-proxy-rejected": observations.get(
                        "rust-dialer-proxy-rejected"
                    ),
                    "rust-host-key-accepted": observations.get("rust-host-key-accepted"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("6J-A SSH TCP differential passed")
    print(json.dumps(rust, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

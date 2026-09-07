#!/usr/bin/env python3
"""Go/Rust differential for HY2-A Hysteria2 outbound TCP (Go HY2 inbound authority)."""

from __future__ import annotations

import concurrent.futures
import http.server
import json
import pathlib
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
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, connect_domain, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_tcp import rejected_exchange


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-hy2a-hysteria2-tcp-diff.json"
PASSWORD = "phase-hy2a-password"
LARGE_PAYLOAD = bytes(range(256)) * 512
SNI = "dot.phase4.test"


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


def trust_roots() -> str:
    root = ROOT_CERTIFICATE.read_text().strip()
    return "tls:\n  custom-certifactes:\n    - |-\n" + textwrap.indent(root, "      ") + "\n"


def hy2_record(
    name: str,
    server_port: int,
    *,
    password: str = PASSWORD,
    skip_verify: bool = True,
    disable_reuse: bool = False,
) -> str:
    skip = "true" if skip_verify else "false"
    reuse = "true" if disable_reuse else "false"
    return f"""  - name: {name}
    type: hysteria2
    server: 127.0.0.1
    port: {server_port}
    password: {password}
    sni: {SNI}
    alpn: [h3]
    skip-cert-verify: {skip}
    disable-reuse: {reuse}
"""


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
            # Prove half-close after application data is flowing: read one byte,
            # SHUT_WR, then drain the remainder (Go HY2 FastOpen races if FIN
            # precedes the first relay write).
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
    # Outer budget must exceed a single SOCKS attempt timeout so Windows/CI
    # cold-start can retry after TimeoutError / WinError 10053/10054.
    limit = deadline_secs if deadline_secs is not None else max(IO_DEADLINE * 4, 20.0)
    attempt_timeout = min(IO_DEADLINE, 3.0)
    deadline = time.monotonic() + limit
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            return exchange(
                port, host, target_port, payload, timeout=attempt_timeout
            )
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


def cancel_one_keep_other(mixed_port: int, echo_port: int) -> bool:
    first = connect_domain(mixed_port, "127.0.0.1", echo_port)
    first.settimeout(IO_DEADLINE)
    second = connect_domain(mixed_port, "127.0.0.1", echo_port)
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
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    echo_port = echo.port
    echo6 = None
    echo6_port = None
    try:
        echo6 = start_server(EchoHandler, ipv6=True)
        echo6_port = echo6.port
    except OSError:
        pass

    health = socketserver.ThreadingTCPServer(("127.0.0.1", 0), HealthHandler)
    health.allow_reuse_address = True
    health_port = int(health.server_address[1])
    health_thread = threading.Thread(target=health.serve_forever, daemon=True)
    health_thread.start()

    mixed_port, controller_port, authority_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    wrong_rule_port = reserve_port()
    authority_scratch = scratch / "authority"
    authority_scratch.mkdir()
    authority, authority_stdout, authority_stderr = start_authority(
        authority_binary, authority_scratch, authority_port
    )
    time.sleep(0.4)
    if authority.poll() is not None:
        logs = ""
        for name in ("stdout.log", "stderr.log"):
            path = authority_scratch / name
            if path.exists():
                logs += f"\n[{name}]\n{path.read_text(errors='replace')[-4000:]}"
        raise RuntimeError(f"authority exited early:{logs}")

    provider = scratch / ".config" / "mihomo" / "provider.yaml"
    provider.parent.mkdir(parents=True)
    provider.write_text("proxies:\n" + hy2_record("provider-hy2", authority_port))

    config = scratch / "config.yaml"
    config.write_text(
        trust_roots()
        + f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: true
hosts:
  echo.hy2a.test: 127.0.0.1
proxies:
{hy2_record("inline-hy2", authority_port)}
{hy2_record("hy2-wrong-password", authority_port, password="wrong-password")}
proxy-providers:
  local-hy2:
    type: file
    path: {provider}
proxy-groups:
  - name: hy2-select
    type: select
    proxies: [inline-hy2]
    use: [local-hy2]
    default-selected: inline-hy2
  - name: hy2-health
    type: url-test
    proxies: [inline-hy2]
    url: http://127.0.0.1:{health_port}/
    interval: 3600
    tolerance: 50
rules:
  - DST-PORT,{wrong_rule_port},hy2-wrong-password
  - MATCH,hy2-select
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    bad_process = None
    bad_stdout = None
    bad_stderr = None
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        time.sleep(0.3)

        domain_small = wait_exchange(
            process, mixed_port, "echo.hy2a.test", echo_port, b"hy2a-domain"
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
        ipv6_ok = True
        if echo6_port is not None:
            ipv6_ok = exchange(mixed_port, "::1", echo6_port, b"hy2a-ipv6")

        half_close = exchange(
            mixed_port,
            "127.0.0.1",
            echo_port,
            b"hy2a-half-close",
            half_close=True,
        )
        reuse_second = exchange(mixed_port, "127.0.0.1", echo_port, b"hy2a-reuse")

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [
                pool.submit(
                    exchange, mixed_port, "127.0.0.1", echo_port, f"c{i}".encode()
                )
                for i in range(4)
            ]
            concurrent_ok = all(future.result(timeout=IO_DEADLINE) for future in futures)
        cancel_isolated = cancel_one_keep_other(mixed_port, echo_port)

        wrong_password = rejected_exchange(mixed_port, "127.0.0.1", wrong_rule_port)
        survived_wrong_password = process.poll() is None
        after_auth_fail = exchange(mixed_port, "127.0.0.1", echo_port, b"after-auth-fail")

        refused_target = reserve_port()
        target_refused = rejected_exchange(mixed_port, "127.0.0.1", refused_target)
        survived_target_refused = process.poll() is None
        after_refused = exchange(mixed_port, "127.0.0.1", echo_port, b"after-refused")

        selected = request(
            controller_port,
            "PUT",
            "/proxies/hy2-select",
            {"name": "provider-hy2"},
        )
        if selected[0] != 204:
            raise AssertionError(selected)
        provider_route = exchange(mixed_port, "127.0.0.1", echo_port, b"provider-route")
        inline_snapshot = proxy_snapshot(controller_port, "inline-hy2")
        provider_snapshot = proxy_snapshot(
            controller_port, "provider-hy2", "local-hy2"
        )

        health_query = f"url=http://127.0.0.1:{health_port}/&timeout=5000"
        health_status, health_body = request(
            controller_port, "GET", f"/group/hy2-health/delay?{health_query}"
        )
        health_ok = health_status == 200 and b"inline-hy2" in health_body

        reload_via_controller(process, controller_port, config, secret=SECRET)
        after_reload = wait_exchange(
            process, mixed_port, "echo.hy2a.test", echo_port, b"after-reload"
        )

        bad_cert_port = reserve_port()
        bad_scratch = scratch / "bad-cert"
        bad_scratch.mkdir()
        bad_config = bad_scratch / "config.yaml"
        bad_config.write_text(
            f"""mixed-port: {bad_cert_port}
mode: rule
log-level: info
ipv6: false
proxies:
{hy2_record("bad-cert-hy2", authority_port, skip_verify=False)}
rules:
  - MATCH,bad-cert-hy2
"""
        )
        bad_process, bad_stdout, bad_stderr = launch(binary, bad_config, bad_scratch)
        wait_ready(bad_process, bad_cert_port)
        bad_cert_rejected = rejected_exchange(bad_cert_port, "127.0.0.1", echo_port)

        return {
            "domain-small": domain_small,
            "ipv4-large": ipv4_large,
            "ipv6": ipv6_ok,
            "half-close": half_close,
            "reuse-second": reuse_second,
            "concurrent-ok": concurrent_ok,
            "cancel-isolated": cancel_isolated,
            "wrong-password-rejected": wrong_password,
            "survived-wrong-password": survived_wrong_password,
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
            "bad-cert-rejected": bad_cert_rejected,
            "process-alive": process.poll() is None,
        }
    finally:
        if bad_process is not None:
            stop(bad_process)
        if bad_stdout is not None:
            bad_stdout.close()
        if bad_stderr is not None:
            bad_stderr.close()
        stop(process)
        stdout.close()
        stderr.close()
        stop(authority)
        authority_stdout.close()
        authority_stderr.close()
        echo.close()
        if echo6 is not None:
            echo6.close()
        health.shutdown()
        health.server_close()


def normalize(entry: dict[str, Any]) -> dict[str, Any]:
    out = dict(entry)
    for key in ("inline-snapshot", "provider-snapshot"):
        snap = dict(out[key])
        snap.pop("udp", None)
        out[key] = snap
    return out


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-hy2a-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE_HY2A_CARGO_TARGET", "phase-hy2a")
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(
                    binaries[name], binaries["go"], scratch
                )
            # HY2-B accepts up/down; keep a hard-reject assertion for deferred knobs.
            observations["rust-deferred-gecko-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: hysteria2\n"
                "    server: 127.0.0.1\n"
                "    port: 443\n"
                "    password: x\n"
                "    obfs: gecko\n"
                "    obfs-password: abcd\n",
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

    go = normalize(observations["go"])
    rust = normalize(observations["rust"])
    if go != rust or not observations.get("rust-deferred-gecko-rejected", False):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {
                    "go": go,
                    "rust": rust,
                    "rust-deferred-gecko-rejected": observations.get(
                        "rust-deferred-gecko-rejected"
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("HY2-A Hysteria2 TCP differential passed")
    print(json.dumps(rust, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

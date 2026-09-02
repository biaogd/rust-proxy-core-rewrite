#!/usr/bin/env python3
"""Go/Rust differential for Phase 6E-C VLESS WebSocket/WSS TCP."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import textwrap
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_tcp import (
    LARGE_PAYLOAD,
    STANDARD_UUID,
    config_validation,
    exchange,
    rejected_exchange,
    vless_record,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-websocket-diff.json"


def build_authority(output: pathlib.Path) -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    binary = output / f"vless-authority{suffix}"
    subprocess.run(
        [
            "go",
            "build",
            "-trimpath",
            "-o",
            str(binary),
            "./compat/helpers/vless_authority",
        ],
        cwd=ROOT,
        check=True,
    )
    return binary


def start_authority(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    port: int,
    *,
    log_name: str,
    transport: str = "ws",
    certificate: pathlib.Path | None = None,
    private_key: pathlib.Path | None = None,
    expected_ws_host: str = "",
    expected_ws_path: str = "",
    expected_header: str = "",
    expected_http_method: str = "",
    expected_http_host: str = "",
    expected_http_path: str = "",
    expected_http_header: str = "",
) -> tuple[Any, Any, Any, pathlib.Path]:
    stdout_path = scratch / f"{log_name}-stdout.log"
    stdout = stdout_path.open("wb")
    stderr = (scratch / f"{log_name}-stderr.log").open("wb")
    command = [
        str(binary),
        "-listen",
        f"127.0.0.1:{port}",
        "-uuid",
        STANDARD_UUID,
        "-transport",
        transport,
        "-expected-ws-host",
        expected_ws_host,
        "-expected-ws-path",
        expected_ws_path,
        "-expected-header",
        expected_header,
        "-expected-http-method",
        expected_http_method,
        "-expected-http-host",
        expected_http_host,
        "-expected-http-path",
        expected_http_path,
        "-expected-http-header",
        expected_http_header,
    ]
    if certificate is not None and private_key is not None:
        command.extend(("-tls-cert", str(certificate), "-tls-key", str(private_key)))
    process = subprocess.Popen(
        command,
        cwd=scratch,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"VLESS authority exited with {process.returncode}")
        if "READY " in stdout_path.read_text(errors="replace"):
            return process, stdout, stderr, stdout_path
        time.sleep(0.02)
    raise TimeoutError("VLESS authority did not become ready")


def trusted_roots() -> str:
    root = pathlib.Path(ROOT_CERTIFICATE).read_text().strip()
    return "tls:\n  custom-certifactes:\n    - |-\n" + textwrap.indent(root, "      ") + "\n"


def ws_record(
    name: str,
    authority_port: int,
    *,
    tls_fields: str = "",
    path: str,
    host: str,
    custom_header: str | None = None,
) -> str:
    header_lines = f"        Host: {host}\n"
    if custom_header is not None:
        header_name, header_value = custom_header.split("=", 1)
        header_lines += f"        {header_name}: {header_value}\n"
    return vless_record(
        name,
        authority_port,
        network="ws",
        extra=(
            f"{tls_fields}"
            "    ws-opts:\n"
            f"      path: {path}\n"
            "      headers:\n"
            f"{header_lines}"
        ),
    )


def wait_exchange(
    process: Any,
    mixed_port: int,
    host: str,
    port: int,
    payload: bytes,
    *,
    half_close: bool = False,
) -> bool:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during VLESS WS readiness: {process.returncode}")
        try:
            if exchange(mixed_port, host, port, payload, half_close=half_close):
                return True
        except (AssertionError, EOFError, OSError):
            pass
        time.sleep(0.02)
    raise TimeoutError("VLESS WebSocket route did not become ready")


def wait_observations(
    authorities: list[tuple[Any, pathlib.Path]], expected: set[str]
) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed: set[str] = set()
        for process, output in authorities:
            if process.poll() is not None:
                raise RuntimeError("VLESS WebSocket authority exited")
            observed.update(
                line.strip()
                for line in output.read_text(errors="replace").splitlines()
                if line.startswith(("TLS ", "WS ", "HEADER ", "CONNECT "))
            )
        if expected <= observed:
            return sorted(expected)
        time.sleep(0.02)
    raise TimeoutError(f"missing VLESS WebSocket observations: {sorted(expected - observed)}")


def launch_single_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authority_port: int,
    *,
    skip: bool,
    servername: str,
) -> tuple[Any, Any, Any, int]:
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        trusted_roots()
        + f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
{ws_record(
    "wss-case",
    authority_port,
    tls_fields=(
        "    tls: true\n"
        f"    servername: {servername}\n"
        f"    skip-cert-verify: {str(skip).lower()}\n"
    ),
    path="/case",
    host="case.phase6e.test",
)}rules:
  - MATCH,wss-case
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    wait_ready(process, mixed_port)
    return process, stdout, stderr, mixed_port


def exercise(binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    ws_port, wss_port, header_port = reserve_port(), reserve_port(), reserve_port()
    authorities: list[tuple[Any, pathlib.Path]] = []
    handles = []
    for name, port, tls, host, path, header in [
        ("ws", ws_port, False, "phase6e-ws.example", "/vless?token=1", ""),
        ("wss", wss_port, True, "", "", ""),
        ("header", header_port, False, "header.phase6e.test", "/header", "X-Phase=6e-c"),
    ]:
        process, stdout, stderr, output = start_authority(
            authority_binary,
            scratch,
            port,
            log_name=f"authority-{name}",
            certificate=pathlib.Path(SERVER_CERTIFICATE) if tls else None,
            private_key=pathlib.Path(SERVER_KEY) if tls else None,
            expected_ws_host=host,
            expected_ws_path=path,
            expected_header=header,
        )
        authorities.append((process, output))
        handles.append((process, stdout, stderr))

    mixed_port, controller_port = reserve_port(), reserve_port()
    provider = scratch / ".config" / "mihomo" / "provider.yaml"
    provider.parent.mkdir(parents=True)
    provider.write_text(
        "proxies:\n"
        + ws_record(
            "provider-vless-ws",
            ws_port,
            path="/vless?token=1",
            host="phase6e-ws.example",
        )
    )
    config = scratch / "config.yaml"
    config.write_text(
        trusted_roots()
        + f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
proxies:
{ws_record("inline-vless-ws", ws_port, path="/vless?token=1", host="phase6e-ws.example")}{ws_record("vless-wss", wss_port, tls_fields="    tls: true\n    servername: dot.phase4.test\n", path="/secure-vless", host="dot.phase4.test")}{ws_record("vless-wss-name", wss_port, tls_fields="    tls: true\n    servername: explicit.phase6e.test\n    name-cert-verify: dot.phase4.test\n", path="/name-override", host="front.phase6e.test")}{ws_record("vless-header", header_port, path="/header", host="header.phase6e.test", custom_header="X-Phase=6e-c")}proxy-providers:
  local-vless-ws:
    type: file
    path: {provider}
proxy-groups:
  - name: vless-select
    type: select
    proxies: [inline-vless-ws]
    use: [local-vless-ws]
    default-selected: inline-vless-ws
rules:
  - DST-PORT,26101,vless-wss
  - DST-PORT,26102,vless-wss-name
  - DST-PORT,26103,vless-header
  - MATCH,vless-select
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    opened: list[tuple[Any, Any, Any]] = []
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        matrix = {
            "ws-first-packet": wait_exchange(
                process, mixed_port, "ws.phase6e", 26001, b"vless-ws-ready"
            ),
            "ws-large": wait_exchange(process, mixed_port, "ws-large.phase6e", 26002, LARGE_PAYLOAD),
            "ws-half-close": exchange(
                mixed_port,
                "ws-half.phase6e",
                26003,
                b"vless-ws-half",
                half_close=True,
            ),
            "wss-large": wait_exchange(
                process, mixed_port, "wss.phase6e", 26101, LARGE_PAYLOAD
            ),
            "wss-name-override": wait_exchange(
                process, mixed_port, "wss-name.phase6e", 26102, b"name-override"
            ),
            "header-route": wait_exchange(
                process, mixed_port, "header.phase6e", 26103, b"custom-header"
            ),
        }

        selected = request(
            controller_port,
            "PUT",
            "/proxies/vless-select",
            {"name": "provider-vless-ws"},
        )
        if selected[0] != 204:
            raise AssertionError(selected)
        provider_route = wait_exchange(
            process, mixed_port, "provider.phase6e", 26004, b"provider-vless-ws"
        )

        bad_handshake = rejected_exchange(mixed_port, "bad-handshake.phase6e", 26005)
        survived_bad_handshake = process.poll() is None

        skip_dir = scratch / "skip"
        skip_dir.mkdir()
        skip_process, skip_stdout, skip_stderr, skip_port = launch_single_case(
            binary,
            skip_dir,
            wss_port,
            skip=True,
            servername="skip.phase6e.test",
        )
        opened.append((skip_process, skip_stdout, skip_stderr))
        skip_route = wait_exchange(skip_process, skip_port, "skip.phase6e", 443, b"skip")
        stop(skip_process)

        untrusted_dir = scratch / "untrusted"
        untrusted_dir.mkdir()
        untrusted_process, untrusted_stdout, untrusted_stderr, untrusted_port = launch_single_case(
            binary,
            untrusted_dir,
            wss_port,
            skip=False,
            servername="dot.phase4.test",
        )
        opened.append((untrusted_process, untrusted_stdout, untrusted_stderr))
        untrusted_rejected = rejected_exchange(untrusted_port, "untrusted.phase6e", 443)
        survived_untrusted = untrusted_process.poll() is None
        stop(untrusted_process)

        validation = {
            "ws-valid": config_validation(
                binary,
                scratch,
                "proxies:\n"
                + ws_record(
                    "ok",
                    ws_port,
                    path="/vless?token=1",
                    host="phase6e-ws.example",
                ),
            ),
        }

        expected = {
            "WS phase6e-ws.example /vless?token=1",
            "WS dot.phase4.test /secure-vless",
            "WS front.phase6e.test /name-override",
            "WS header.phase6e.test /header",
            "WS case.phase6e.test /case",
            "HEADER X-Phase=6e-c",
            "TLS dot.phase4.test",
            "TLS explicit.phase6e.test",
            "TLS skip.phase6e.test",
            "CONNECT ws.phase6e:26001",
            "CONNECT ws-large.phase6e:26002",
            "CONNECT ws-half.phase6e:26003",
            "CONNECT wss.phase6e:26101",
            "CONNECT wss-name.phase6e:26102",
            "CONNECT header.phase6e:26103",
            "CONNECT provider.phase6e:26004",
        }
        return {
            "matrix": matrix,
            "provider-route": provider_route,
            "bad-handshake-rejected": bad_handshake,
            "survived-bad-handshake": survived_bad_handshake,
            "skip-route": skip_route,
            "untrusted-rejected": untrusted_rejected,
            "survived-untrusted": survived_untrusted,
            "validation": validation,
            "process-alive": process.poll() is None,
            "authority": wait_observations(authorities, expected),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        for child, child_stdout, child_stderr in opened:
            stop(child)
            child_stdout.close()
            child_stderr.close()
        for authority, authority_stdout, authority_stderr in handles:
            stop(authority)
            authority_stdout.close()
            authority_stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6e-vless-websocket-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6EVLESSWS_CARGO_TARGET", "phase6e-c-vless")
        authority = build_authority(root)
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, authority, scratch)
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
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6E-C VLESS WebSocket/WSS TCP differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

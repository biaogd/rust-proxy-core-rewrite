#!/usr/bin/env python3
"""Go/Rust differential for Shadowsocks v2ray-plugin WebSocket over TLS."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import textwrap
from typing import Any

from phase1 import EchoHandler, HalfCloseHandler, ROOT, cargo_target_path, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks import CIPHER, PASSWORD
from phase6c_shadowsocks_ciphers import LARGE_PAYLOAD, echo, half_close, wait_route
from phase6c_shadowsocks_v2ray_websocket import start_authority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-v2ray-websocket-tls-diff.json"
HOST = "dot.phase4.test"
PATH = "/wss"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSSV2RAYWSTLS_CARGO_TARGET", "phase6c-shadowsocks-v2ray-websocket-tls"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-websocket-authority{suffix}"


def config_text(
    mixed_port: int,
    authority_port: int,
    *,
    skip_certificate_verification: bool,
    trust_root: bool,
) -> str:
    tls_roots = ""
    if trust_root:
        root = pathlib.Path(ROOT_CERTIFICATE).read_text().strip()
        tls_roots = "tls:\n  custom-certifactes:\n    - |-\n" + textwrap.indent(root, "      ") + "\n"
    return f"""{tls_roots}mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {CIPHER}
    password: {PASSWORD}
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      host: {HOST}
      path: {PATH}
      mux: false
      tls: true
      skip-cert-verify: {str(skip_certificate_verification).lower()}
rules:
  - MATCH,local-ss
"""


def safe_echo(mixed_port: int, echo_port: int, payload: bytes) -> bool:
    try:
        return echo(mixed_port, "localhost", echo_port, payload)
    except (EOFError, OSError):
        return False


def launch_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authority_port: int,
    echo_port: int,
    *,
    skip_certificate_verification: bool,
    trust_root: bool,
) -> tuple[subprocess.Popen[bytes], Any, Any, int]:
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        config_text(
            mixed_port,
            authority_port,
            skip_certificate_verification=skip_certificate_verification,
            trust_root=trust_root,
        )
    )
    process, stdout, stderr = launch(binary, config, scratch)
    wait_ready(process, mixed_port)
    return process, stdout, stderr, mixed_port


def exercise(binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo_server = start_server(EchoHandler)
    half_close_server = start_server(HalfCloseHandler)
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority,
        scratch,
        authority_port,
        host=HOST,
        path=PATH,
        certificate=pathlib.Path(SERVER_CERTIFICATE),
        private_key=pathlib.Path(SERVER_KEY),
    )
    opened: list[tuple[subprocess.Popen[bytes], Any, Any]] = []
    try:
        trusted_dir = scratch / "trusted"
        trusted_dir.mkdir()
        process, stdout, stderr, mixed_port = launch_case(
            binary,
            trusted_dir,
            authority_port,
            echo_server.port,
            skip_certificate_verification=False,
            trust_root=True,
        )
        opened.append((process, stdout, stderr))
        wait_route(process, mixed_port, echo_server.port)
        try:
            half_close_result = half_close(mixed_port, half_close_server.port)
        except (EOFError, OSError):
            half_close_result = False
        trusted = {
            "domain": safe_echo(mixed_port, echo_server.port, b"wss"),
            "ipv4-large": echo(mixed_port, "127.0.0.1", echo_server.port, LARGE_PAYLOAD),
            "half-close": half_close_result,
            "process-alive": process.poll() is None,
        }
        stop(process)

        skip_dir = scratch / "skip"
        skip_dir.mkdir()
        process, stdout, stderr, skip_port = launch_case(
            binary,
            skip_dir,
            authority_port,
            echo_server.port,
            skip_certificate_verification=True,
            trust_root=False,
        )
        opened.append((process, stdout, stderr))
        wait_route(process, skip_port, echo_server.port)
        skip_route = safe_echo(skip_port, echo_server.port, b"skip")
        stop(process)

        rejected_dir = scratch / "untrusted"
        rejected_dir.mkdir()
        process, stdout, stderr, rejected_port = launch_case(
            binary,
            rejected_dir,
            authority_port,
            echo_server.port,
            skip_certificate_verification=False,
            trust_root=False,
        )
        opened.append((process, stdout, stderr))
        untrusted_rejected = not safe_echo(rejected_port, echo_server.port, b"reject")
        stop(process)
        return {"trusted": trusted, "skip-route": skip_route, "untrusted-rejected": untrusted_rejected}
    finally:
        for process, stdout, stderr in opened:
            stop(process)
            stdout.close()
            stderr.close()
        stop(authority_process)
        authority_stdout.close()
        authority_stderr.close()
        echo_server.close()
        half_close_server.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-v2ray-wss-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE6CSSV2RAYWSTLS_CARGO_TARGET", "phase6c-shadowsocks-v2ray-websocket-tls"
        )
        authority = authority_binary()
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, authority, scratch)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {"error": f"{type(error).__name__}: {error}", "observations": observations, "debug": debug_files(root)},
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
    print("Phase 6C-M4 Shadowsocks v2ray-plugin WebSocket TLS differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

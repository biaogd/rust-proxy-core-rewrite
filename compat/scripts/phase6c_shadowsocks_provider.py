#!/usr/bin/env python3
"""Go/Rust differential for Phase 6C-D Shadowsocks provider/group use."""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
from typing import Any

from phase1 import (
    EchoHandler,
    ROOT,
    cargo_target_path,
    recv_exact,
    reserve_port,
    start_server,
    wait_ready,
)
from phase5b1a import build_binaries, connect_domain, debug_files
from phase5c_nested_selector import group_summary, provider_summary, select
from phase5d_proxies import request
from phase5d_streams import wait_controller
from phase6a_simple_adapters import UdpServer, wait_udp_echo
from phase6c_shadowsocks import start_authority
from phase3 import launch, stop


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-provider-diff.json"
CIPHER = "aes-128-gcm"
INLINE_PASSWORD = "phase6c-inline-provider-password"
FILE_PASSWORD = "phase6c-file-provider-password"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSSPROVIDER_CARGO_TARGET", "phase6c-shadowsocks-provider"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def tcp_echo(mixed_port: int, echo_port: int, payload: bytes) -> bool:
    with connect_domain(mixed_port, "localhost", echo_port) as stream:
        stream.sendall(payload)
        return recv_exact(stream, len(payload)) == payload


def adapter_summary(controller_port: int, path: str) -> dict[str, Any]:
    status, body = request(controller_port, "GET", path)
    if status != 200:
        raise AssertionError((status, body))
    value = json.loads(body)
    return {
        "name": value["name"],
        "type": value["type"],
        "udp": value["udp"],
        "uot": value["uot"],
        "provider-name": value["provider-name"],
    }


def exercise(
    binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    tcp = start_server(EchoHandler)
    udp = UdpServer()
    mixed_port = reserve_port()
    controller_port = reserve_port()
    inline_authority_port = reserve_port()
    file_authority_port = reserve_port()
    inline_authority_home = scratch / "inline-authority"
    file_authority_home = scratch / "file-authority"
    inline_authority_home.mkdir()
    file_authority_home.mkdir()
    inline_process, inline_stdout, inline_stderr = start_authority(
        authority,
        inline_authority_home,
        inline_authority_port,
        CIPHER,
        INLINE_PASSWORD,
    )
    file_process, file_stdout, file_stderr = start_authority(
        authority,
        file_authority_home,
        file_authority_port,
        CIPHER,
        FILE_PASSWORD,
    )
    inline_stopped = False
    provider_file = scratch / ".config" / "mihomo" / "file-provider.yaml"
    provider_file.parent.mkdir(parents=True)
    provider_file.write_text(
        f"""proxies:
  - name: file-ss-member
    type: ss
    server: 127.0.0.1
    port: {file_authority_port}
    cipher: {CIPHER}
    password: {FILE_PASSWORD}
    udp: true
"""
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxy-providers:
  inline-ss:
    type: inline
    payload:
      - name: inline-ss-member
        type: ss
        server: 127.0.0.1
        port: {inline_authority_port}
        cipher: {CIPHER}
        password: {INLINE_PASSWORD}
        udp: true
  file-ss:
    type: file
    path: {provider_file}
proxy-groups:
  - name: ss-group
    type: select
    proxies: [REJECT]
    use: [inline-ss, file-ss]
    default-selected: REJECT
rules:
  - MATCH,ss-group
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        initial = group_summary(controller_port, "ss-group")

        inline_select = select(
            controller_port, "ss-group", "inline-ss-member"
        )
        inline_tcp = tcp_echo(
            mixed_port, tcp.port, b"phase6c-inline-provider-tcp"
        )
        inline_udp = wait_udp_echo(
            process, mixed_port, udp.port, b"phase6c-inline-provider-udp"
        )
        inline_group = group_summary(controller_port, "ss-group")
        stop(inline_process)
        inline_stdout.close()
        inline_stderr.close()
        inline_stopped = True

        file_select = select(controller_port, "ss-group", "file-ss-member")
        file_tcp = tcp_echo(mixed_port, tcp.port, b"phase6c-file-provider-tcp")
        file_udp = wait_udp_echo(
            process, mixed_port, udp.port, b"phase6c-file-provider-udp"
        )
        file_group = group_summary(controller_port, "ss-group")

        return {
            "initial-group": initial,
            "inline-provider": provider_summary(controller_port, "inline-ss"),
            "file-provider": provider_summary(controller_port, "file-ss"),
            "inline-member": adapter_summary(
                controller_port,
                "/providers/proxies/inline-ss/inline-ss-member",
            ),
            "file-member": adapter_summary(
                controller_port,
                "/providers/proxies/file-ss/file-ss-member",
            ),
            "inline-select": inline_select,
            "inline-tcp": inline_tcp,
            "inline-udp": inline_udp,
            "inline-group": inline_group,
            "file-select": file_select,
            "file-tcp": file_tcp,
            "file-udp": file_udp,
            "file-group": file_group,
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        if not inline_stopped:
            stop(inline_process)
            inline_stdout.close()
            inline_stderr.close()
        stop(file_process)
        stdout.close()
        stderr.close()
        file_stdout.close()
        file_stderr.close()
        udp.close()
        tcp.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-provider-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE6CSSPROVIDER_CARGO_TARGET",
            "phase6c-shadowsocks-provider",
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
    print("Phase 6C-D Shadowsocks provider/group differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

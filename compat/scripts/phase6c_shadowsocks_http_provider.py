#!/usr/bin/env python3
"""Go/Rust differential for Phase 6C-E Shadowsocks HTTP providers."""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
import time
from typing import Any

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    cargo_target_path,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_http_provider import ProviderServer
from phase5d_proxies import request, start_health_server
from phase5d_streams import wait_controller
from phase6a_simple_adapters import UdpServer, wait_udp_echo
from phase6c_shadowsocks import start_authority
from phase6c_shadowsocks_provider import tcp_echo


FAILURE_ARTIFACT = (
    ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-http-provider-diff.json"
)
CIPHER = "aes-128-gcm"
FIRST_PASSWORD = "phase6c-http-provider-first"
SECOND_PASSWORD = "phase6c-http-provider-second"
MEMBER = "remote-ss"
PROVIDER = "remote-ss-provider"
GROUP = "remote-ss-group"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSSHTTPPROVIDER_CARGO_TARGET",
        "phase6c-shadowsocks-http-provider",
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def provider_payload(port: int, password: str) -> bytes:
    return f"""proxies:
  - name: {MEMBER}
    type: ss
    server: 127.0.0.1
    port: {port}
    cipher: {CIPHER}
    password: {password}
    udp: true
""".encode()


def member_summary(controller_port: int) -> dict[str, Any]:
    status, body = request(
        controller_port,
        "GET",
        f"/providers/proxies/{PROVIDER}/{MEMBER}",
    )
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


def provider_names(controller_port: int) -> list[str]:
    status, body = request(controller_port, "GET", f"/providers/proxies/{PROVIDER}")
    if status != 200:
        raise AssertionError((status, body))
    return [proxy["name"] for proxy in json.loads(body)["proxies"]]


def wait_names(process: Any, controller_port: int, expected: list[str]) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during SS provider load: {process.returncode}")
        try:
            if provider_names(controller_port) == expected:
                return
        except (OSError, AssertionError):
            pass
        time.sleep(0.02)
    raise TimeoutError(f"Shadowsocks HTTP-provider members did not become {expected}")


def select_member(controller_port: int) -> tuple[int, bool]:
    status, body = request(
        controller_port,
        "PUT",
        f"/proxies/{GROUP}",
        {"name": MEMBER},
    )
    return status, body == b""


def health_summary(controller_port: int, health_url: str) -> dict[str, Any]:
    status, body = request(controller_port, "GET", f"/providers/proxies/{PROVIDER}")
    if status != 200:
        raise AssertionError((status, body))
    member = json.loads(body)["proxies"][0]
    url_health = member["extra"].get(health_url)
    return {
        "alive": member["alive"],
        "history": bool(member["history"]),
        "url-alive": url_health["alive"] if url_health else None,
        "url-history": bool(url_health and url_health["history"]),
    }


def wait_healthy(process: Any, controller_port: int, health_url: str) -> dict[str, Any]:
    deadline = time.monotonic() + (2 * IO_DEADLINE)
    current: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during SS healthcheck: {process.returncode}")
        try:
            current = health_summary(controller_port, health_url)
            if all(current.values()):
                return current
        except (OSError, KeyError, IndexError):
            pass
        time.sleep(0.02)
    raise TimeoutError(f"Shadowsocks provider did not become healthy: {current}")


def write_config(
    path: pathlib.Path,
    mixed_port: int,
    controller_port: int,
    provider_port: int,
    cache: pathlib.Path,
    health_url: str,
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxy-providers:
  {PROVIDER}:
    type: http
    url: http://127.0.0.1:{provider_port}/provider.yaml?phase=6c-e
    path: {cache}
    interval: 600
    health-check:
      enable: true
      url: {health_url}
      expected-status: '204'
      interval: 600
      timeout: 1000
      lazy: true
proxy-groups:
  - name: {GROUP}
    type: select
    proxies: [REJECT]
    use: [{PROVIDER}]
rules:
  - DST-PORT,{provider_port},DIRECT
  - MATCH,{GROUP}
"""
    )


def exercise(
    binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    first_port, second_port = reserve_port(), reserve_port()
    first_home, second_home = scratch / "first-authority", scratch / "second-authority"
    first_home.mkdir()
    second_home.mkdir()
    first_process, first_stdout, first_stderr = start_authority(
        authority, first_home, first_port, CIPHER, FIRST_PASSWORD
    )
    second_process, second_stdout, second_stderr = start_authority(
        authority, second_home, second_port, CIPHER, SECOND_PASSWORD
    )
    first_stopped = False
    tcp = start_server(EchoHandler)
    udp = UdpServer()
    health = start_health_server()
    health_url = f"http://127.0.0.1:{health.server_port}/generate_204"
    first_payload = provider_payload(first_port, FIRST_PASSWORD)
    second_payload = provider_payload(second_port, SECOND_PASSWORD)
    provider = ProviderServer(first_payload)
    mixed_port, controller_port = reserve_port(), reserve_port()
    cache = scratch / ".config" / "mihomo" / "providers" / "remote-ss.yaml"
    config = scratch / "config.yaml"
    write_config(
        config,
        mixed_port,
        controller_port,
        provider.port,
        cache,
        health_url,
    )

    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_names(process, controller_port, [MEMBER])
        initial_select = select_member(controller_port)
        initial_tcp = tcp_echo(mixed_port, tcp.port, b"phase6c-http-provider-first-tcp")
        initial_udp = wait_udp_echo(
            process, mixed_port, udp.port, b"phase6c-http-provider-first-udp"
        )
        initial_member = member_summary(controller_port)
        initial_cache = cache.read_bytes() == first_payload

        provider.respond(second_payload)
        refreshed = request(controller_port, "PUT", f"/providers/proxies/{PROVIDER}")
        wait_names(process, controller_port, [MEMBER])
        refreshed_cache = cache.read_bytes() == second_payload
        stop(first_process)
        first_stdout.close()
        first_stderr.close()
        first_stopped = True
        refreshed_select = select_member(controller_port)
        refreshed_tcp = tcp_echo(
            mixed_port, tcp.port, b"phase6c-http-provider-second-tcp"
        )
        refreshed_udp = wait_udp_echo(
            process, mixed_port, udp.port, b"phase6c-http-provider-second-udp"
        )

        stop(process)
        stdout.close()
        stderr.close()
        requests_before_restart = len(provider.observations)
        provider.respond(b"remote unavailable", 500)
        process, stdout, stderr = launch(binary, config, scratch)
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_names(process, controller_port, [MEMBER])
        restart_select = select_member(controller_port)
        restart_tcp = tcp_echo(mixed_port, tcp.port, b"phase6c-http-provider-cache-tcp")
        restart_udp = wait_udp_echo(
            process, mixed_port, udp.port, b"phase6c-http-provider-cache-udp"
        )
        manual_health = request(
            controller_port,
            "GET",
            f"/providers/proxies/{PROVIDER}/healthcheck",
        )
        healthy = wait_healthy(process, controller_port, health_url)
        return {
            "initial-request": len(provider.observations) >= 1,
            "initial-select": initial_select,
            "initial-member": initial_member,
            "initial-cache": initial_cache,
            "initial-tcp": initial_tcp,
            "initial-udp": initial_udp,
            "refresh": (refreshed[0], refreshed[1] == b""),
            "refresh-cache": refreshed_cache,
            "refresh-select": refreshed_select,
            "refresh-tcp": refreshed_tcp,
            "refresh-udp": refreshed_udp,
            "restart-used-fresh-cache": len(provider.observations)
            == requests_before_restart,
            "restart-members": provider_names(controller_port),
            "restart-select": restart_select,
            "restart-tcp": restart_tcp,
            "restart-udp": restart_udp,
            "manual-health": (manual_health[0], manual_health[1] == b""),
            "healthy": healthy,
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        if not first_stopped:
            stop(first_process)
            first_stdout.close()
            first_stderr.close()
        stop(second_process)
        second_stdout.close()
        second_stderr.close()
        provider.close()
        health.shutdown()
        health.server_close()
        udp.close()
        tcp.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-http-provider-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE6CSSHTTPPROVIDER_CARGO_TARGET",
            "phase6c-shadowsocks-http-provider",
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
    print("Phase 6C-E Shadowsocks HTTP-provider lifecycle differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

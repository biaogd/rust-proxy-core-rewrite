#!/usr/bin/env python3
"""Go/Rust differential for Phase 5F1 fixed-listener LAN policies."""

from __future__ import annotations

import http.client
import json
import pathlib
import platform
import socket
import tempfile
import time
from typing import Any

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    recv_until,
    reserve_port,
    socks_connect,
    start_server,
    wait_ready,
)
from phase3 import http_request, launch, status, stop
from phase5b1a import build_binaries, debug_files
from phase5b3a import relay_result
from phase5d_configs import json_request
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5f-lan-policy-diff.json"


def controller_snapshot(port: int) -> dict[str, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    connection.request(
        "GET", "/configs", headers={"Authorization": f"Bearer {SECRET}"}
    )
    response = connection.getresponse()
    try:
        if response.status != 200:
            raise AssertionError((response.status, response.read()))
        value = json.loads(response.read())
        return {
            key: value[key]
            for key in (
                "allow-lan",
                "bind-address",
                "skip-auth-prefixes",
                "lan-allowed-ips",
                "lan-disallowed-ips",
                "inbound-tfo",
                "inbound-mptcp",
                "keep-alive-idle",
                "keep-alive-interval",
                "disable-keep-alive",
                "interface-name",
                "routing-mark",
                "tcp-concurrent",
            )
        }
    finally:
        response.close()
        connection.close()


def http_route(port: int, destination_port: int) -> str:
    try:
        stream, response = http_request(port, destination_port, None)
        with stream:
            if " 200 " not in status(response):
                return status(response)
            return relay_result(stream, b"lan-http")
    except (OSError, EOFError, ConnectionResetError, BrokenPipeError):
        return "closed"


def http_route_at(host: str, port: int, destination_port: int) -> str:
    return http_route_to(host, port, "127.0.0.1", destination_port)


def http_route_to(
    host: str, port: int, destination_host: str, destination_port: int
) -> str:
    try:
        stream = socket.create_connection((host, port), timeout=IO_DEADLINE)
        stream.settimeout(IO_DEADLINE)
        with stream:
            stream.sendall(
                (
                    f"CONNECT {destination_host}:{destination_port} HTTP/1.1\r\n"
                    f"Host: {destination_host}:{destination_port}\r\n\r\n"
                ).encode()
            )
            response = recv_until(stream, b"\r\n\r\n")
            if " 200 " not in status(response):
                return status(response)
            return relay_result(stream, f"lan-{host}-{destination_host}".encode())
    except (OSError, EOFError, ConnectionResetError, BrokenPipeError):
        return "closed"


def wait_route_at(
    process: Any, host: str, port: int, destination_port: int, expected: str
) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited while waiting for {host}: {process.returncode}")
        if http_route_at(host, port, destination_port) == expected:
            return
        time.sleep(0.02)
    raise TimeoutError(f"listener {host}:{port} did not become {expected}")


def native_ipv4_candidates() -> list[str]:
    candidates: list[str] = []
    try:
        for family, _, _, _, address in socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_INET
        ):
            if family == socket.AF_INET and not address[0].startswith("127."):
                candidates.append(str(address[0]))
    except socket.gaierror:
        pass

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        address = str(probe.getsockname()[0])
        if not address.startswith("127."):
            candidates.append(address)
    finally:
        probe.close()
    return list(dict.fromkeys(candidates))


def socks_route(port: int, destination_port: int) -> str:
    try:
        stream = socks_connect(
            port, 1, socket.inet_aton("127.0.0.1"), destination_port
        )
        return relay_result(stream, b"lan-socks")
    except (OSError, EOFError, ConnectionResetError, BrokenPipeError):
        return "closed"


def exercise_skip_auth(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    http_port, socks_port, mixed_port = reserve_port(), reserve_port(), reserve_port()
    controller_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""port: {http_port}
socks-port: {socks_port}
mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
allow-lan: true
bind-address: 0.0.0.0
skip-auth-prefixes: [127.0.0.0/8]
lan-allowed-ips: [0.0.0.0/0]
lan-disallowed-ips: []
authentication: [alice:secret]
inbound-tfo: true
inbound-mptcp: false
keep-alive-idle: 17
keep-alive-interval: 9
disable-keep-alive: false
interface-name: ''
routing-mark: 0
tcp-concurrent: true
mode: rule
log-level: info
ipv6: true
rules: ['MATCH,DIRECT']
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        for port in (http_port, socks_port, mixed_port):
            wait_ready(process, port)
        wait_controller(process, controller_port)
        # Fixed listeners become connectable before the Go apply path has
        # necessarily published the process-global inbound prefix policy.  A
        # successful config snapshot is the observable apply barrier.
        snapshot = controller_snapshot(controller_port)
        return {
            "http": http_route(http_port, echo.port),
            "socks": socks_route(socks_port, echo.port),
            "mixed": http_route(mixed_port, echo.port),
            "tcp-concurrent-domain": http_route_to(
                "127.0.0.1", mixed_port, "localhost", echo.port
            ),
            "config": snapshot,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise_policy(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    extra: str,
) -> str:
    echo = start_server(EchoHandler)
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
allow-lan: true
bind-address: 0.0.0.0
{extra}
mode: rule
log-level: info
ipv6: false
rules: ['MATCH,DIRECT']
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        return http_route(mixed_port, echo.port)
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise_invalid_interface(
    binary: pathlib.Path, scratch: pathlib.Path
) -> str:
    echo = start_server(EchoHandler)
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
interface-name: phase5f-missing-interface
mode: rule
log-level: info
ipv6: false
rules: ['MATCH,DIRECT']
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        return http_route(mixed_port, echo.port)
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise_loopback_override(
    binary: pathlib.Path, scratch: pathlib.Path
) -> str:
    echo = start_server(EchoHandler)
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
allow-lan: false
bind-address: 192.0.2.1
mode: rule
log-level: info
ipv6: false
rules: ['MATCH,DIRECT']
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_route_at(process, "127.0.0.1", mixed_port, echo.port, "direct")
        return "direct"
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise_wildcard_dual_stack(
    binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, str]:
    echo = start_server(EchoHandler)
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
ipv6: true
rules: ['MATCH,DIRECT']
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_route_at(process, "127.0.0.1", mixed_port, echo.port, "direct")
        wait_route_at(process, "::1", mixed_port, echo.port, "direct")
        lan_candidates = native_ipv4_candidates()
        if not lan_candidates:
            raise RuntimeError("no native non-loopback IPv4 address is available")
        for lan in lan_candidates:
            if http_route_at(lan, mixed_port, echo.port) == "direct":
                break
        else:
            raise RuntimeError(
                f"wildcard listener did not accept native addresses: {lan_candidates}"
            )
        return {"ipv4": "direct", "ipv6": "direct", "native-lan": "direct"}
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise_patch_rebind(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
allow-lan: true
bind-address: 127.0.0.1
authentication: [alice:secret]
mode: rule
log-level: info
ipv6: false
rules: ['MATCH,DIRECT']
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        before = http_route_at("127.0.0.1", mixed_port, echo.port)
        patch_status, patch_body = json_request(
            controller_port,
            "PATCH",
            "/configs",
            {
                "bind-address": "[::1]",
                "skip-auth-prefixes": ["::1/128"],
                "lan-allowed-ips": ["::1/128"],
                "lan-disallowed-ips": [],
            },
        )
        wait_route_at(process, "::1", mixed_port, echo.port, "direct")
        old = http_route_at("127.0.0.1", mixed_port, echo.port)
        invalid_status, _ = json_request(
            controller_port,
            "PATCH",
            "/configs",
            {"lan-allowed-ips": ["not-a-prefix"]},
        )
        return {
            "before": before,
            "patch": {"status": patch_status, "empty-body": patch_body == b""},
            "new": http_route_at("::1", mixed_port, echo.port),
            "old": old,
            "invalid-prefix-status": invalid_status,
            "config": controller_snapshot(controller_port),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    cases = {}
    for name in (
        "skip-auth",
        "allowed",
        "disallowed",
        "invalid-interface",
        "loopback-override",
        "wildcard-dual-stack",
        "patch-rebind",
    ):
        case = scratch / name
        case.mkdir()
        cases[name] = case
    return {
        "skip-auth": exercise_skip_auth(binary, cases["skip-auth"]),
        "allowed-filter": exercise_policy(
            binary, cases["allowed"], "lan-allowed-ips: [192.0.2.0/24]"
        ),
        "disallowed-filter": exercise_policy(
            binary,
            cases["disallowed"],
            "lan-allowed-ips: [0.0.0.0/0]\nlan-disallowed-ips: [127.0.0.0/8]",
        ),
        "invalid-interface": exercise_invalid_interface(
            binary, cases["invalid-interface"]
        ),
        "allow-lan-false-ignores-bind": exercise_loopback_override(
            binary, cases["loopback-override"]
        ),
        "wildcard-dual-stack": exercise_wildcard_dual_stack(
            binary, cases["wildcard-dual-stack"]
        ),
        "patch-rebind": exercise_patch_rebind(binary, cases["patch-rebind"]),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5f-lan-policy-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE5FLANPOLICY_CARGO_TARGET", "phase5f-lan-policy"
        )
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
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
    print("Phase 5F1 LAN policy differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for Phase 6E-A VLESS native TCP."""

from __future__ import annotations

import json
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import uuid
from typing import Any

from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller
from phase6d_vmess_aead import connect_socks5_ip


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-tcp-diff.json"
STANDARD_UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
MAPPED_UUID_TEXT = "123456"
MAPPED_UUID = "f8598425-92f2-5508-a071-4fc67f9040ac"
LARGE_PAYLOAD = bytes(range(256)) * 512


def recv_or_eof(stream: socket.socket, length: int) -> bytes | None:
    try:
        return recv_exact(stream, length)
    except EOFError:
        return None


class VlessAuthorityHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        stream: socket.socket = self.request
        version = recv_or_eof(stream, 1)
        if version is None:
            return
        user = recv_or_eof(stream, 16)
        addon_size = recv_or_eof(stream, 1)
        if user is None or addon_size is None:
            return
        addons = recv_or_eof(stream, addon_size[0])
        command = recv_or_eof(stream, 1)
        port_bytes = recv_or_eof(stream, 2)
        address_type = recv_or_eof(stream, 1)
        if addons is None or command is None or port_bytes is None or address_type is None:
            return
        if address_type == b"\x01":
            packed = recv_or_eof(stream, 4)
            host = socket.inet_ntop(socket.AF_INET, packed) if packed is not None else ""
        elif address_type == b"\x03":
            packed = recv_or_eof(stream, 16)
            host = socket.inet_ntop(socket.AF_INET6, packed) if packed is not None else ""
        elif address_type == b"\x02":
            length = recv_or_eof(stream, 1)
            raw_host = recv_or_eof(stream, length[0]) if length is not None else None
            host = raw_host.decode(errors="replace") if raw_host is not None else ""
        else:
            return
        port = int.from_bytes(port_bytes, "big")
        user_text = str(uuid.UUID(bytes=user))
        authority: VlessAuthority = self.server.authority
        authority.observe(
            f"CONNECT {host}:{port} UUID {user_text} ADDON {addon_size[0]} COMMAND {command[0]}"
        )
        if version != b"\0" or command != b"\x01" or addons:
            return
        if host == "bad-version.phase6e":
            stream.sendall(b"\x01\0")
            return
        response_addon = b"abc" if host == "addon.phase6e" else b""
        stream.sendall(b"\0" + bytes([len(response_addon)]) + response_addon)
        while True:
            payload = stream.recv(64 * 1024)
            if not payload:
                return
            stream.sendall(payload)


class VlessAuthority:
    def __init__(self) -> None:
        self.server = socketserver.ThreadingTCPServer(
            ("127.0.0.1", 0), VlessAuthorityHandler
        )
        self.server.daemon_threads = True
        self.server.allow_reuse_address = True
        self.server.authority = self
        self.port = int(self.server.server_address[1])
        self.observations: set[str] = set()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def observe(self, value: str) -> None:
        with self.lock:
            self.observations.add(value)

    def wait_observations(self, expected: set[str]) -> list[str]:
        deadline = time.monotonic() + IO_DEADLINE
        while time.monotonic() < deadline:
            with self.lock:
                observed = self.observations.copy()
            if expected <= observed:
                return sorted(expected)
            time.sleep(0.02)
        raise TimeoutError(f"missing VLESS authority observations: {sorted(expected - observed)}")

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def vless_record(
    name: str,
    authority_port: int,
    user: str = STANDARD_UUID,
    encryption: str = "none",
    network: str = "tcp",
    extra: str = "",
) -> str:
    return f"""  - name: {name}
    type: vless
    server: 127.0.0.1
    port: {authority_port}
    uuid: '{user}'
    encryption: {encryption}
    network: {network}
{extra}"""


def exchange(
    mixed_port: int,
    host: str,
    port: int,
    payload: bytes,
    *,
    half_close: bool = False,
) -> bool:
    try:
        stream = connect_socks5_ip(mixed_port, host, port)
    except ValueError:
        stream = connect_domain(mixed_port, host, port)
    with stream:
        stream.settimeout(IO_DEADLINE)
        stream.sendall(payload)
        if half_close:
            stream.shutdown(socket.SHUT_WR)
        return recv_exact(stream, len(payload)) == payload


def rejected_exchange(mixed_port: int, host: str, port: int) -> bool:
    try:
        with connect_domain(mixed_port, host, port) as stream:
            stream.settimeout(2)
            stream.sendall(b"invalid-response")
            return stream.recv(1) == b""
    except (AssertionError, BrokenPipeError, ConnectionResetError, EOFError, OSError):
        return True


def config_validation(binary: pathlib.Path, scratch: pathlib.Path, body: str) -> bool:
    config = scratch / f"validate-{len(list(scratch.glob('validate-*')))}.yaml"
    config.write_text(
        f"""mixed-port: 0
mode: rule
log-level: info
ipv6: false
{body}rules:
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
        "uot": value["uot"],
        "xudp": value["xudp"],
    }


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority = VlessAuthority()
    authority.start()
    mixed_port, controller_port = reserve_port(), reserve_port()
    provider = scratch / ".config" / "mihomo" / "provider.yaml"
    provider.parent.mkdir(parents=True)
    provider.write_text(
        "proxies:\n" + vless_record("provider-vless", authority.port, MAPPED_UUID_TEXT)
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: true
proxies:
{vless_record('inline-vless', authority.port)}proxy-providers:
  local-vless:
    type: file
    path: {provider}
proxy-groups:
  - name: vless-select
    type: select
    proxies: [inline-vless]
    use: [local-vless]
    default-selected: inline-vless
rules:
  - MATCH,vless-select
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    refused_process = None
    refused_stdout = None
    refused_stderr = None
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        domain_small = exchange(mixed_port, "phase6e.example", 443, b"vless-native-tcp")
        ipv4_large = exchange(mixed_port, "192.0.2.8", 8443, LARGE_PAYLOAD)
        ipv6 = exchange(mixed_port, "2001:db8::8", 9443, b"vless-ipv6")
        response_addon = exchange(mixed_port, "addon.phase6e", 10443, b"response-addon")
        half_close = exchange(
            mixed_port,
            "half-close.phase6e",
            11443,
            b"vless-half-close",
            half_close=True,
        )
        bad_response = rejected_exchange(mixed_port, "bad-version.phase6e", 12443)
        survived_bad_response = process.poll() is None

        selected = request(
            controller_port,
            "PUT",
            "/proxies/vless-select",
            {"name": "provider-vless"},
        )
        if selected[0] != 204:
            raise AssertionError(selected)
        mapped_uuid_route = exchange(
            mixed_port, "mapped-uuid.phase6e", 13443, b"mapped-uuid"
        )

        refused_port = reserve_port()
        unavailable_authority_port = reserve_port()
        refused_scratch = scratch / "refused"
        refused_scratch.mkdir()
        refused_config = refused_scratch / "config.yaml"
        refused_config.write_text(
            f"""mixed-port: {refused_port}
mode: rule
log-level: info
ipv6: false
proxies:
{vless_record('refused-vless', unavailable_authority_port)}rules:
  - MATCH,refused-vless
"""
        )
        refused_process, refused_stdout, refused_stderr = launch(
            binary, refused_config, refused_scratch
        )
        wait_ready(refused_process, refused_port)
        connection_refused = rejected_exchange(
            refused_port, "refused.phase6e", 14443
        )
        survived_connection_refused = refused_process.poll() is None

        expected = {
            f"CONNECT phase6e.example:443 UUID {STANDARD_UUID} ADDON 0 COMMAND 1",
            f"CONNECT 192.0.2.8:8443 UUID {STANDARD_UUID} ADDON 0 COMMAND 1",
            f"CONNECT 2001:db8::8:9443 UUID {STANDARD_UUID} ADDON 0 COMMAND 1",
            f"CONNECT addon.phase6e:10443 UUID {STANDARD_UUID} ADDON 0 COMMAND 1",
            f"CONNECT half-close.phase6e:11443 UUID {STANDARD_UUID} ADDON 0 COMMAND 1",
            f"CONNECT bad-version.phase6e:12443 UUID {STANDARD_UUID} ADDON 0 COMMAND 1",
            f"CONNECT mapped-uuid.phase6e:13443 UUID {MAPPED_UUID} ADDON 0 COMMAND 1",
        }
        invalid_encryption = config_validation(
            binary,
            scratch,
            "proxies:\n"
            + vless_record(
                "invalid-vless",
                authority.port,
                encryption="unsupported",
            ),
        )
        mapped_uuid_accepted = config_validation(
            binary,
            scratch,
            "proxies:\n"
            + vless_record("mapped-vless", authority.port, MAPPED_UUID_TEXT),
        )
        return {
            "domain-small": domain_small,
            "ipv4-large": ipv4_large,
            "ipv6": ipv6,
            "response-addon": response_addon,
            "half-close": half_close,
            "bad-response-rejected": bad_response,
            "survived-bad-response": survived_bad_response,
            "provider-select": (selected[0], selected[1] == b""),
            "mapped-uuid-route": mapped_uuid_route,
            "controller-inline": proxy_snapshot(controller_port, "inline-vless"),
            "controller-provider": proxy_snapshot(
                controller_port, "provider-vless", "local-vless"
            ),
            "connection-refused": connection_refused,
            "survived-connection-refused": survived_connection_refused,
            "authority": authority.wait_observations(expected),
            "invalid-encryption-accepted": invalid_encryption,
            "mapped-uuid-accepted": mapped_uuid_accepted,
            "process-alive": process.poll() is None,
        }
    finally:
        if refused_process is not None:
            stop(refused_process)
        stop(process)
        stdout.close()
        stderr.close()
        if refused_stdout is not None:
            refused_stdout.close()
        if refused_stderr is not None:
            refused_stderr.close()
        authority.close()


def assert_rust_only_rejections(
    rust_binary: pathlib.Path, scratch: pathlib.Path, authority_port: int
) -> None:
    for extra, network, label in [
        ("", "unsupported-transport", "unknown transport"),
        (
            "    ws-opts:\n      max-early-data: 2048\n",
            "ws",
            "WebSocket early data",
        ),
        (
            "    xhttp-opts:\n      download-settings: {}\n",
            "xhttp",
            "xHTTP download settings",
        ),
    ]:
        accepted = config_validation(
            rust_binary,
            scratch,
            "proxies:\n"
            + vless_record(
                "outside-scope", authority_port, network=network, extra=extra
            ),
        )
        if accepted:
            raise AssertionError(f"Rust accepted out-of-scope VLESS feature: {label}")


def contract_errors(name: str, observations: dict[str, Any]) -> list[str]:
    errors = []
    required_true = [
        "domain-small",
        "ipv4-large",
        "ipv6",
        "response-addon",
        "half-close",
        "bad-response-rejected",
        "survived-bad-response",
        "mapped-uuid-route",
        "connection-refused",
        "survived-connection-refused",
        "mapped-uuid-accepted",
        "process-alive",
    ]
    for field in required_true:
        if observations[field] is not True:
            errors.append(f"{name}: {field} was not true")
    if observations["invalid-encryption-accepted"] is not False:
        errors.append(f"{name}: invalid encryption was accepted")
    expected_snapshot = {
        "type": "Vless",
        "udp": False,
        "uot": True,
        "xudp": True,
    }
    for field in ["controller-inline", "controller-provider"]:
        snapshot = observations[field]
        for key, expected in expected_snapshot.items():
            if snapshot[key] != expected:
                errors.append(f"{name}: {field}.{key} was {snapshot[key]!r}")
    if observations["provider-select"] != (204, True):
        errors.append(f"{name}: provider selection failed")
    return errors


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6e-vless-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6EVLESS_CARGO_TARGET", "phase6e-vless")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
            rejection_scratch = root / "rust-rejections"
            rejection_scratch.mkdir()
            assert_rust_only_rejections(
                binaries["rust"], rejection_scratch, reserve_port()
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
    errors = [
        error
        for name, result in observations.items()
        for error in contract_errors(name, result)
    ]
    if observations["go"] != observations["rust"] or errors:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {"contract-errors": errors, "observations": observations},
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6E-A VLESS native-TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

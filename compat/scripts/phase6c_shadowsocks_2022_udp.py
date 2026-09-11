#!/usr/bin/env python3
"""Go/Rust differential for SS2022 native UDP outbound.

Covers the three standard 2022 methods plus AES single-hop EIH. ChaCha8 UDP
stays rejected at config. Ciphertext is random and is not byte-compared.
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
from typing import Any

from phase1 import IO_DEADLINE, ROOT, cargo_target_path, reserve_port, wait_ready
from phase3 import UdpEchoHandler, launch, socks_udp_packet, stop
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks import SECRET, start_authority
from phase6c_shadowsocks_2022 import KEY_128, KEY_256
from phase6c_shadowsocks_udp import (
    domain_packet,
    exchange,
    proxy_snapshot,
    wait_exchange,
)


def proxy_config(cipher: str, password: str, extra: str = "") -> str:
    return f"""mixed-port: 17890
mode: rule
log-level: info
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: {cipher}
    password: {password}
{extra}rules:
  - MATCH,local-ss
"""


FAILURE_ARTIFACT = (
    ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-2022-udp-diff.json"
)
CIPHERS = (
    ("2022-blake3-aes-128-gcm", KEY_128),
    ("2022-blake3-aes-256-gcm", KEY_256),
    ("2022-blake3-chacha20-poly1305", KEY_256),
)
USER_KEY_128 = "EBESExQVFhcYGRobHB0eHw=="
USER_KEY_256 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
EIH_CASES = (
    ("2022-blake3-aes-128-gcm", KEY_128, USER_KEY_128),
    ("2022-blake3-aes-256-gcm", KEY_256, USER_KEY_256),
)
SHARED_CONFIG_LABELS = (
    "udp-aes128",
    "udp-aes256",
    "udp-chacha20",
    "udp-aes128-eih",
    "tcp-chacha8",
)
REWRITE_REJECT_LABELS = (
    "reject-chacha8-udp",
    "reject-2022-uot",
)


def authority_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSS2022UDP_CARGO_TARGET", "phase6c-shadowsocks-2022-udp"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def native_client_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE6CSS2022UDP_CARGO_TARGET", "phase6c-shadowsocks-2022-udp"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-udp-client{suffix}"


def validate_config(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    cases = (
        ("udp-aes128", "2022-blake3-aes-128-gcm", KEY_128, "    udp: true\n", True),
        ("udp-aes256", "2022-blake3-aes-256-gcm", KEY_256, "    udp: true\n", True),
        (
            "udp-chacha20",
            "2022-blake3-chacha20-poly1305",
            KEY_256,
            "    udp: true\n",
            True,
        ),
        (
            "udp-aes128-eih",
            "2022-blake3-aes-128-gcm",
            f"{KEY_128}:{USER_KEY_128}",
            "    udp: true\n",
            True,
        ),
        (
            "reject-chacha8-udp",
            "2022-blake3-chacha8-poly1305",
            KEY_256,
            "    udp: true\n",
            False,
        ),
        (
            "reject-2022-uot",
            "2022-blake3-aes-128-gcm",
            KEY_128,
            "    udp: true\n    udp-over-tcp: true\n",
            False,
        ),
        ("tcp-chacha8", "2022-blake3-chacha8-poly1305", KEY_256, "", True),
    )
    observations = {}
    for label, cipher, password, extra, expected in cases:
        config = scratch / f"{label}.yaml"
        config.write_text(proxy_config(cipher, password, extra))
        result = subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        observations[label] = result.returncode == 0
        observations[f"{label}-expected"] = expected
        observations[f"{label}-match"] = (result.returncode == 0) == expected
    return observations


def ipv6_packet(destination_port: int, payload: bytes) -> bytes:
    return (
        b"\x00\x00\x00\x04"
        + socket.inet_pton(socket.AF_INET6, "::1")
        + destination_port.to_bytes(2, "big")
        + payload
    )


class ThreadingUdpServerV6(socketserver.ThreadingUDPServer):
    address_family = socket.AF_INET6
    daemon_threads = True


def try_ipv6_echo() -> tuple[socketserver.BaseServer, int] | None:
    try:
        echo = ThreadingUdpServerV6(("::1", 0), UdpEchoHandler)
    except OSError:
        return None
    thread = threading.Thread(target=echo.serve_forever, daemon=True)
    thread.start()
    return echo, int(echo.server_address[1])


def exercise_listener(
    process: Any,
    proxy_port: int,
    echo_port: int,
    second_echo_port: int,
    label: str,
) -> dict[str, bool]:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(IO_DEADLINE)
    first = f"ss2022-udp-{label}-ipv4-first".encode()
    domain_payload = f"ss2022-udp-{label}-domain".encode()
    reused = bytes(range(256)) * 8
    second_dest = f"ss2022-udp-{label}-second".encode()
    large = b"L" * 1400
    try:
        wait_exchange(
            process, client, proxy_port, socks_udp_packet(echo_port, first), first
        )
        observations = {
            "ipv4": True,
            "domain": exchange(
                client,
                proxy_port,
                domain_packet("localhost", echo_port, domain_payload),
                domain_payload,
            ),
            "same-client-session-reuse": exchange(
                client, proxy_port, socks_udp_packet(echo_port, reused), reused
            ),
            "multi-dest": exchange(
                client,
                proxy_port,
                socks_udp_packet(second_echo_port, second_dest),
                second_dest,
            ),
            "large": exchange(
                client, proxy_port, socks_udp_packet(echo_port, large), large
            ),
        }
        burst = True
        for index in range(16):
            payload = f"ss2022-udp-{label}-burst-{index}".encode()
            if not exchange(
                client, proxy_port, socks_udp_packet(echo_port, payload), payload
            ):
                burst = False
                break
        observations["burst"] = burst
        return observations
    finally:
        client.close()


def exercise_wrong_key(
    process: Any, proxy_port: int, echo_port: int
) -> bool:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(0.4)
    try:
        client.sendto(socks_udp_packet(echo_port, b"wrong-key"), ("127.0.0.1", proxy_port))
        try:
            client.recvfrom(65_535)
        except TimeoutError:
            return True
        return False
    except OSError:
        return True
    finally:
        client.close()


def exercise_native_client(
    client: pathlib.Path,
    authority_port: int,
    echo_port: int,
    cipher: str,
    password: str,
) -> bool:
    payload = "ss2022-native-udp"
    result = subprocess.run(
        [
            str(client),
            f"127.0.0.1:{authority_port}",
            password,
            cipher,
            "127.0.0.1",
            str(echo_port),
            payload,
        ],
        check=False,
        capture_output=True,
        timeout=IO_DEADLINE,
    )
    return result.returncode == 0


def exercise_cipher(
    binary: pathlib.Path,
    authority: pathlib.Path,
    native_client: pathlib.Path,
    scratch: pathlib.Path,
    cipher: str,
    password: str,
    *,
    authority_password: str | None = None,
    authority_user_key: str | None = None,
) -> dict[str, Any]:
    echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
    echo_thread.start()
    echo_port = int(echo.server_address[1])
    second = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    second_thread = threading.Thread(target=second.serve_forever, daemon=True)
    second_thread.start()
    second_port = int(second.server_address[1])
    mixed_port = reserve_port()
    socks_port = reserve_port()
    controller_port = reserve_port()
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority,
        scratch,
        authority_port,
        cipher,
        authority_password or password,
        authority_user_key,
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
socks-port: {socks_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: true
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {cipher}
    password: {password}
    udp: true
rules:
  - MATCH,local-ss
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    ipv6_server = try_ipv6_echo()
    try:
        wait_ready(process, mixed_port)
        wait_ready(process, socks_port)
        mixed = exercise_listener(process, mixed_port, echo_port, second_port, "mixed")
        socks5 = exercise_listener(process, socks_port, echo_port, second_port, "socks5")
        ipv6 = False
        if ipv6_server is not None:
            v6_echo, v6_port = ipv6_server
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.bind(("127.0.0.1", 0))
            client.settimeout(IO_DEADLINE)
            payload = b"ss2022-udp-ipv6"
            try:
                client.sendto(ipv6_packet(v6_port, payload), ("127.0.0.1", mixed_port))
                response, _ = client.recvfrom(65_535)
                ipv6 = (
                    response[:4] == b"\x00\x00\x00\x04"
                    and response[22:] == payload
                )
            except (TimeoutError, OSError, AssertionError):
                ipv6 = False
            finally:
                client.close()
                v6_echo.shutdown()
                v6_echo.server_close()
        concurrent = True
        clients = []
        try:
            for index in range(3):
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client.bind(("127.0.0.1", 0))
                client.settimeout(IO_DEADLINE)
                payload = f"ss2022-udp-concurrent-{index}".encode()
                if not exchange(
                    client, mixed_port, socks_udp_packet(echo_port, payload), payload
                ):
                    concurrent = False
                    break
                clients.append(client)
        finally:
            for client in clients:
                client.close()
        native = exercise_native_client(
            native_client, authority_port, echo_port, cipher, password
        )
        stop(authority_process)
        restart_scratch = scratch / "restarted"
        restart_scratch.mkdir()
        authority_process, authority_stdout, authority_stderr = start_authority(
            authority,
            restart_scratch,
            authority_port,
            cipher,
            authority_password or password,
            authority_user_key,
        )
        restart_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        restart_client.bind(("127.0.0.1", 0))
        restarted = False
        try:
            restarted = wait_exchange(
                process,
                restart_client,
                mixed_port,
                socks_udp_packet(echo_port, b"ss2022-udp-restart"),
                b"ss2022-udp-restart",
            )
        except (TimeoutError, RuntimeError, OSError):
            restarted = False
        finally:
            restart_client.close()
        observations: dict[str, Any] = {
            "mixed": mixed,
            "socks5": socks5,
            "ipv6": ipv6,
            "concurrent-clients": concurrent,
            "native-association": native,
            "server-restart": restarted,
            "controller": proxy_snapshot(controller_port),
            "process-alive": process.poll() is None,
        }
        return observations
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        echo.shutdown()
        echo.server_close()
        echo_thread.join(timeout=IO_DEADLINE)
        second.shutdown()
        second.server_close()
        second_thread.join(timeout=IO_DEADLINE)


def exercise_wrong_key_cipher(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
) -> bool:
    echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
    echo_thread.start()
    echo_port = int(echo.server_address[1])
    mixed_port = reserve_port()
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority, scratch, authority_port, "2022-blake3-aes-128-gcm", KEY_128
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: 2022-blake3-aes-128-gcm
    password: {USER_KEY_128}
    udp: true
rules:
  - MATCH,local-ss
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        return exercise_wrong_key(process, mixed_port, echo_port)
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        echo.shutdown()
        echo.server_close()
        echo_thread.join(timeout=IO_DEADLINE)


def exercise(
    binary: pathlib.Path,
    authority: pathlib.Path,
    native_client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    validation = scratch / "validation"
    validation.mkdir()
    observations: dict[str, Any] = {
        "key-validation": validate_config(binary, validation)
    }
    for cipher, password in CIPHERS:
        cipher_scratch = scratch / cipher
        cipher_scratch.mkdir()
        observations[cipher] = exercise_cipher(
            binary, authority, native_client, cipher_scratch, cipher, password
        )
    for cipher, server_key, user_key in EIH_CASES:
        label = f"{cipher}-eih"
        cipher_scratch = scratch / label
        cipher_scratch.mkdir()
        observations[label] = exercise_cipher(
            binary,
            authority,
            native_client,
            cipher_scratch,
            cipher,
            f"{server_key}:{user_key}",
            authority_password=server_key,
            authority_user_key=user_key,
        )
    wrong = scratch / "wrong-key"
    wrong.mkdir()
    observations["wrong-key-timeout"] = exercise_wrong_key_cipher(
        binary, authority, wrong
    )
    return observations


def parity_observations(obs: dict[str, Any]) -> dict[str, Any]:
    validation = obs["key-validation"]
    view = dict(obs)
    view["key-validation"] = {
        label: validation[label] for label in SHARED_CONFIG_LABELS
    }
    return view


def rewrite_rejects_unsupported_udp(obs: dict[str, Any]) -> bool:
    validation = obs["key-validation"]
    return all(not validation[label] for label in REWRITE_REJECT_LABELS)


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-2022-udp-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE6CSS2022UDP_CARGO_TARGET", "phase6c-shadowsocks-2022-udp"
        )
        authority = authority_binary()
        native_client = native_client_binary()
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(
                    binary, authority, native_client, scratch
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
    if parity_observations(go) != parity_observations(rust) or not rewrite_rejects_unsupported_udp(
        rust
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6C-O Shadowsocks 2022 UDP outbound differential passed")
    print(
        "Pinned Go still accepts ChaCha8 UDP and 2022 UoT at -t "
        f"(chacha8-udp={go['key-validation']['reject-chacha8-udp']}, "
        f"2022-uot={go['key-validation']['reject-2022-uot']}); "
        "the rewrite rejects both by design."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

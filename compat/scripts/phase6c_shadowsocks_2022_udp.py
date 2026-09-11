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
LISTENER_REQUIRED = (
    "ipv4",
    "domain",
    "same-client-session-reuse",
    "multi-dest",
    "large",
    "burst",
)
CIPHER_REQUIRED = (
    "concurrent-clients",
    "native-association",
    "server-restart",
    "old-session-replay-ignored",
    "process-alive",
)
PARITY_OMIT_CIPHER_KEYS = ("old-session-replay-ignored",)


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


class UdpRelay:
    """Forwards Shadowsocks datagrams and can replay captured server replies."""

    def __init__(self, backend_port: int) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.settimeout(0.2)
        self.port = int(self._sock.getsockname()[1])
        self._backend = ("127.0.0.1", backend_port)
        self._product: tuple[str, int] | None = None
        self.replies: list[bytes] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def replay_oldest_reply(self) -> bool:
        with self._lock:
            if not self.replies or self._product is None:
                return False
            packet = self.replies[0]
            dest = self._product
        self._sock.sendto(packet, dest)
        return True

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=IO_DEADLINE)
        self._sock.close()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(65_535)
            except TimeoutError:
                continue
            except OSError:
                break
            if addr == self._backend:
                with self._lock:
                    self.replies.append(data)
                    product = self._product
                if product is not None:
                    try:
                        self._sock.sendto(data, product)
                    except OSError:
                        return
            else:
                with self._lock:
                    self._product = addr
                try:
                    self._sock.sendto(data, self._backend)
                except OSError:
                    return


def no_datagram(client: socket.socket, timeout: float = 0.4) -> bool:
    client.settimeout(timeout)
    try:
        client.recvfrom(65_535)
        return False
    except TimeoutError:
        return True
    except OSError:
        return True
    finally:
        client.settimeout(IO_DEADLINE)


def drain_datagrams(client: socket.socket) -> None:
    client.settimeout(0.05)
    try:
        while True:
            client.recvfrom(65_535)
    except (TimeoutError, OSError):
        pass
    finally:
        client.settimeout(IO_DEADLINE)


def exercise_listener(
    process: Any,
    proxy_port: int,
    echo_port: int,
    second_echo_port: int,
    label: str,
) -> tuple[dict[str, bool], socket.socket]:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(IO_DEADLINE)
    first = f"ss2022-udp-{label}-ipv4-first".encode()
    domain_payload = f"ss2022-udp-{label}-domain".encode()
    reused = bytes(range(256)) * 8
    second_dest = f"ss2022-udp-{label}-second".encode()
    large = b"L" * 1400
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
    return observations, client


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
    relay = UdpRelay(authority_port)
    mixed_client: socket.socket | None = None
    socks_client: socket.socket | None = None
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
    port: {relay.port}
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
        mixed, mixed_client = exercise_listener(
            process, mixed_port, echo_port, second_port, "mixed"
        )
        socks5, socks_client = exercise_listener(
            process, socks_port, echo_port, second_port, "socks5"
        )
        ipv6: bool | str = "skipped"
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
                ipv6_server = None
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
        authority_stdout.close()
        authority_stderr.close()
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
        restarted = False
        replay_ignored = False
        if mixed_client is None:
            raise RuntimeError("mixed UDP client was not established")
        try:
            restarted = wait_exchange(
                process,
                mixed_client,
                mixed_port,
                socks_udp_packet(echo_port, b"ss2022-udp-restart"),
                b"ss2022-udp-restart",
            )
            drain_datagrams(mixed_client)
            replay_ignored = relay.replay_oldest_reply() and no_datagram(mixed_client)
            replay_ignored = replay_ignored and exchange(
                mixed_client,
                mixed_port,
                socks_udp_packet(echo_port, b"ss2022-udp-after-replay"),
                b"ss2022-udp-after-replay",
            )
        except (TimeoutError, RuntimeError, OSError):
            restarted = False
            replay_ignored = False
        observations: dict[str, Any] = {
            "mixed": mixed,
            "socks5": socks5,
            "ipv6": ipv6,
            "concurrent-clients": concurrent,
            "native-association": native,
            "server-restart": restarted,
            "old-session-replay-ignored": replay_ignored,
            "controller": proxy_snapshot(controller_port),
            "process-alive": process.poll() is None,
        }
        return observations
    finally:
        if mixed_client is not None:
            mixed_client.close()
        if socks_client is not None:
            socks_client.close()
        if ipv6_server is not None:
            v6_echo, _ = ipv6_server
            v6_echo.shutdown()
            v6_echo.server_close()
        relay.close()
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


def cipher_labels() -> tuple[str, ...]:
    return tuple(cipher for cipher, _ in CIPHERS) + tuple(
        f"{cipher}-eih" for cipher, _, _ in EIH_CASES
    )


def parity_observations(obs: dict[str, Any]) -> dict[str, Any]:
    validation = obs["key-validation"]
    view = dict(obs)
    view["key-validation"] = {
        label: validation[label] for label in SHARED_CONFIG_LABELS
    }
    for label in cipher_labels():
        cipher_obs = dict(view[label])
        for key in PARITY_OMIT_CIPHER_KEYS:
            cipher_obs.pop(key, None)
        view[label] = cipher_obs
    return view


def cipher_required_failures(label: str, obs: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for side in ("mixed", "socks5"):
        for key in LISTENER_REQUIRED:
            if obs.get(side, {}).get(key) is not True:
                failures.append(f"{label}.{side}.{key}")
    if obs.get("ipv6") not in (True, "skipped"):
        failures.append(f"{label}.ipv6")
    for key in CIPHER_REQUIRED:
        if key in PARITY_OMIT_CIPHER_KEYS:
            continue
        if obs.get(key) is not True:
            failures.append(f"{label}.{key}")
    controller = obs.get("controller") or {}
    if controller.get("udp") is not True:
        failures.append(f"{label}.controller.udp")
    if controller.get("uot") is not False:
        failures.append(f"{label}.controller.uot")
    return failures


def required_failures(obs: dict[str, Any], *, rewrite: bool) -> list[str]:
    failures: list[str] = []
    validation = obs.get("key-validation") or {}
    for label in SHARED_CONFIG_LABELS:
        if validation.get(label) is not True:
            failures.append(f"key-validation.{label}")
    if rewrite:
        for label in REWRITE_REJECT_LABELS:
            if validation.get(label) is not False:
                failures.append(f"key-validation.{label}")
    if obs.get("wrong-key-timeout") is not True:
        failures.append("wrong-key-timeout")
    for label in cipher_labels():
        failures.extend(cipher_required_failures(label, obs.get(label) or {}))
        if rewrite and obs.get(label, {}).get("old-session-replay-ignored") is not True:
            failures.append(f"{label}.old-session-replay-ignored")
    return failures


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
    failures = required_failures(go, rewrite=False) + required_failures(
        rust, rewrite=True
    )
    if failures or parity_observations(go) != parity_observations(rust):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {
                    "failures": failures,
                    "observations": observations,
                },
                indent=2,
                sort_keys=True,
            )
        )
        print("Phase 6C-O required observations failed:", ", ".join(failures) or "parity")
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6C-O Shadowsocks 2022 UDP outbound differential passed")
    print(
        "Pinned Go still accepts ChaCha8 UDP and 2022 UoT at -t "
        f"(chacha8-udp={go['key-validation']['reject-chacha8-udp']}, "
        f"2022-uot={go['key-validation']['reject-2022-uot']}); "
        "the rewrite rejects both by design."
    )
    go_replay = [
        go[label]["old-session-replay-ignored"] for label in cipher_labels()
    ]
    if not all(go_replay):
        print(
            "Pinned Go did not ignore old-session ciphertext after restart; "
            "recorded without treating it as rewrite parity."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

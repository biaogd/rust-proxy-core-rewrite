#!/usr/bin/env python3
"""IN-B Go/Rust differential for Shadowsocks 2022 UDP inbound.

Exercises the three standard 2022 methods with UDP enabled on ss-config /
named listeners. ChaCha8 UDP stays rejected. Prefer the same Rust UDP client
against Go and Rust product inbounds (interop labeled where the client is not
the Go binary). Replay is proven on the product accept path via protocol unit
tests plus a live capture/replay probe against the Rust inbound.
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
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, cargo_target_path, wait_ready
from phase3 import UdpEchoHandler, launch, stop
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks_inbound import proxied_udp, reserve_tcp_udp_port
from phase6c_shadowsocks_2022 import KEY_128, KEY_256

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-inb-shadowsocks-2022-udp-diff.json"
USER_KEY_128 = "EBESExQVFhcYGRobHB0eHw=="
CIPHERS = (
    ("2022-blake3-aes-128-gcm", KEY_128),
    ("2022-blake3-aes-256-gcm", KEY_256),
    ("2022-blake3-chacha20-poly1305", KEY_256),
)
UDP_PAYLOAD = "inb-ss2022-udp"
UDP_REUSE = "inb-ss2022-udp-reuse-" + ("y" * 2048)


def udp_client_binary() -> pathlib.Path:
    target = cargo_target_path(
        "PHASE_INB_SS2022_UDP_CARGO_TARGET", "phase-inb-shadowsocks-2022-udp"
    )
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-udp-client{suffix}"


def inbound_yaml(ss_port: int, cipher: str, password: str, *, named: bool) -> str:
    if named:
        return f"""listeners:
  - name: ss-2022-udp
    type: shadowsocks
    listen: 127.0.0.1
    port: {ss_port}
    cipher: {cipher}
    password: "{password}"
    udp: true
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
    return f"""ss-config: ss://{cipher}:{password}@127.0.0.1:{ss_port}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""


def wait_route(
    process: subprocess.Popen[bytes],
    udp_client: pathlib.Path,
    ss_port: int,
    echo_port: int,
    cipher: str,
    password: str,
    payload: str = UDP_PAYLOAD,
) -> None:
    wait_ready(process, ss_port)
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during UDP readiness with {process.returncode}")
        try:
            if proxied_udp(
                udp_client,
                ss_port,
                echo_port,
                payload=payload,
                cipher=cipher,
                password=password,
            ):
                return
        except (AssertionError, OSError, subprocess.SubprocessError):
            pass
        time.sleep(0.02)
    raise TimeoutError("Shadowsocks 2022 UDP inbound route did not become ready")


def validate_config(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    cases = (
        ("accept-aes128-ss-config", "2022-blake3-aes-128-gcm", KEY_128, False, None, True),
        ("accept-aes256-named", "2022-blake3-aes-256-gcm", KEY_256, True, True, True),
        (
            "accept-chacha20-named",
            "2022-blake3-chacha20-poly1305",
            KEY_256,
            True,
            True,
            True,
        ),
    )
    observations: dict[str, bool] = {}
    for label, cipher, password, named, udp, expected in cases:
        ss_port = 19000 + abs(hash(label)) % 1000
        if named:
            udp_line = "" if udp is None else f"    udp: {'true' if udp else 'false'}\n"
            source = f"""listeners:
  - name: {label}
    type: shadowsocks
    listen: 127.0.0.1
    port: {ss_port}
    cipher: {cipher}
    password: "{password}"
{udp_line}mode: rule
rules:
  - MATCH,DIRECT
"""
        else:
            source = (
                f"ss-config: ss://{cipher}:{password}@127.0.0.1:{ss_port}\n"
                "mode: rule\n"
                "rules:\n"
                "  - MATCH,DIRECT\n"
            )
        config = scratch / f"{label}.yaml"
        config.write_text(source)
        result = subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=IO_DEADLINE,
        )
        observations[label] = (result.returncode == 0) == expected
    return observations


def validate_rust_only_config(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    cases = (
        (
            "reject-chacha8-named-udp",
            "2022-blake3-chacha8-poly1305",
            KEY_256,
            True,
            True,
            False,
        ),
        (
            "accept-chacha8-named-tcp",
            "2022-blake3-chacha8-poly1305",
            KEY_256,
            True,
            False,
            True,
        ),
        (
            "accept-aes128-eih-named",
            "2022-blake3-aes-128-gcm",
            f"{KEY_128}:{USER_KEY_128}",
            True,
            True,
            True,
        ),
    )
    observations: dict[str, bool] = {}
    for label, cipher, password, named, udp, expected in cases:
        ss_port = 19100 + abs(hash(label)) % 800
        udp_line = f"    udp: {'true' if udp else 'false'}\n"
        source = f"""listeners:
  - name: {label}
    type: shadowsocks
    listen: 127.0.0.1
    port: {ss_port}
    cipher: {cipher}
    password: "{password}"
{udp_line}mode: rule
rules:
  - MATCH,DIRECT
"""
        config = scratch / f"{label}.yaml"
        config.write_text(source)
        result = subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=IO_DEADLINE,
        )
        observations[label] = (result.returncode == 0) == expected
    return observations


class CountingUdpHandler(socketserver.BaseRequestHandler):
    counts: dict[bytes, int]

    def handle(self) -> None:
        data, sock = self.request
        CountingUdpHandler.counts[data] = CountingUdpHandler.counts.get(data, 0) + 1
        sock.sendto(data, self.client_address)


def exercise_cipher(
    binary: pathlib.Path,
    udp_client: pathlib.Path,
    scratch: pathlib.Path,
    cipher: str,
    password: str,
) -> dict[str, bool]:
    observations: dict[str, bool] = {}
    echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    thread = threading.Thread(target=echo.serve_forever, daemon=True)
    thread.start()
    echo_port = int(echo.server_address[1])
    ss_port = reserve_tcp_udp_port()
    config = scratch / f"{cipher}-named.yaml"
    config.write_text(inbound_yaml(ss_port, cipher, password, named=True))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_route(
            process,
            udp_client,
            ss_port,
            echo_port,
            cipher=cipher,
            password=password,
            payload=UDP_PAYLOAD,
        )
        observations["named-udp"] = proxied_udp(
            udp_client,
            ss_port,
            echo_port,
            payload=UDP_PAYLOAD,
            cipher=cipher,
            password=password,
        )
        observations["named-udp-reuse"] = proxied_udp(
            udp_client,
            ss_port,
            echo_port,
            payload=UDP_PAYLOAD,
            cipher=cipher,
            password=password,
            reuse_payload=UDP_REUSE,
        )
        observations["named-process-alive"] = process.poll() is None
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.shutdown()
        echo.server_close()
        thread.join(timeout=1)
    return observations


def exercise_wrong_key(
    binary: pathlib.Path,
    udp_client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    thread = threading.Thread(target=echo.serve_forever, daemon=True)
    thread.start()
    echo_port = int(echo.server_address[1])
    ss_port = reserve_tcp_udp_port()
    config = scratch / "wrong-key.yaml"
    config.write_text(
        inbound_yaml(ss_port, "2022-blake3-aes-128-gcm", KEY_128, named=True)
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, ss_port)
        wrong = proxied_udp(
            udp_client,
            ss_port,
            echo_port,
            payload="wrong-key-payload",
            cipher="2022-blake3-aes-128-gcm",
            password=KEY_256,
        )
        return {
            "wrong-key-no-echo": wrong is False,
            "wrong-key-process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.shutdown()
        echo.server_close()
        thread.join(timeout=1)


def exercise_rust_replay_probe(
    binary: pathlib.Path,
    udp_client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    """Capture one client datagram, replay it, and require a single echo hit."""
    CountingUdpHandler.counts = {}
    echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), CountingUdpHandler)
    thread = threading.Thread(target=echo.serve_forever, daemon=True)
    thread.start()
    echo_port = int(echo.server_address[1])
    ss_port = reserve_tcp_udp_port()
    config = scratch / "replay.yaml"
    config.write_text(
        inbound_yaml(ss_port, "2022-blake3-aes-128-gcm", KEY_128, named=True)
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, ss_port)
        # Drive one legitimate exchange through the product path first.
        ok = proxied_udp(
            udp_client,
            ss_port,
            echo_port,
            payload="inb-replay-seed",
            cipher="2022-blake3-aes-128-gcm",
            password=KEY_128,
        )
        seed_count = CountingUdpHandler.counts.get(b"inb-replay-seed", 0)

        relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay.bind(("127.0.0.1", 0))
        relay_port = int(relay.getsockname()[1])
        captured: list[bytes] = []
        stop_relay = threading.Event()
        peers: dict[str, tuple[str, int]] = {}

        def bidirectional() -> None:
            relay.settimeout(0.2)
            while not stop_relay.is_set():
                try:
                    data, addr = relay.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if addr == ("127.0.0.1", ss_port):
                    client_addr = peers.get("client")
                    if client_addr is not None:
                        relay.sendto(data, client_addr)
                else:
                    peers["client"] = addr
                    if len(captured) < 1:
                        captured.append(data)
                    relay.sendto(data, ("127.0.0.1", ss_port))

        worker = threading.Thread(target=bidirectional, daemon=True)
        worker.start()
        via_relay = proxied_udp(
            udp_client,
            relay_port,
            echo_port,
            payload="inb-replay-capture",
            cipher="2022-blake3-aes-128-gcm",
            password=KEY_128,
        )
        replayed = False
        if captured:
            before = CountingUdpHandler.counts.get(b"inb-replay-capture", 0)
            relay.sendto(captured[0], ("127.0.0.1", ss_port))
            time.sleep(0.3)
            after = CountingUdpHandler.counts.get(b"inb-replay-capture", 0)
            replayed = after == before
        stop_relay.set()
        worker.join(timeout=1)
        relay.close()
        after_ok = proxied_udp(
            udp_client,
            ss_port,
            echo_port,
            payload="inb-replay-after",
            cipher="2022-blake3-aes-128-gcm",
            password=KEY_128,
        )
        return {
            "replay-seed-ok": ok and seed_count == 1,
            "replay-capture-ok": via_relay and bool(captured),
            "replay-ignored": replayed,
            "replay-after-ok": after_ok,
            "replay-process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.shutdown()
        echo.server_close()
        thread.join(timeout=1)


def compare(go: dict[str, Any], rust: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for key in ("config", "wrong-key"):
        if go.get(key) != rust.get(key):
            failures.append(key)
    for cipher, _ in CIPHERS:
        if go.get(cipher) != rust.get(cipher):
            failures.append(cipher)
    for label, value in rust.get("rust-config", {}).items():
        if value is not True:
            failures.append(f"rust-config.{label}")
    rust_replay = rust.get("rust-replay", {})
    for label in (
        "replay-seed-ok",
        "replay-capture-ok",
        "replay-ignored",
        "replay-after-ok",
        "replay-process-alive",
    ):
        if rust_replay.get(label) is not True:
            failures.append(f"rust-replay.{label}")
    return failures


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-inb-ss2022-udp-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE_INB_SS2022_UDP_CARGO_TARGET", "phase-inb-shadowsocks-2022-udp"
        )
        udp_client = udp_client_binary()
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                entry: dict[str, Any] = {
                    "config": validate_config(binary, scratch),
                    "wrong-key": exercise_wrong_key(binary, udp_client, scratch),
                }
                for cipher, password in CIPHERS:
                    cipher_scratch = scratch / cipher.replace("/", "_")
                    cipher_scratch.mkdir()
                    entry[cipher] = exercise_cipher(
                        binary, udp_client, cipher_scratch, cipher, password
                    )
                observations[name] = entry
            rust_extra = root / "rust-extra"
            rust_extra.mkdir()
            observations["rust"]["rust-config"] = validate_rust_only_config(
                binaries["rust"], rust_extra
            )
            observations["rust"]["rust-replay"] = exercise_rust_replay_probe(
                binaries["rust"], udp_client, rust_extra
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
    failures = compare(observations["go"], observations["rust"])
    if failures:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {"failures": failures, "observations": observations},
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("IN-B Shadowsocks 2022 UDP inbound differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

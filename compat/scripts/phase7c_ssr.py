#!/usr/bin/env python3
"""Go/Rust differential for SSR-C: auth_sha1_v4 / auth_chain_* / random_head / stream ciphers / UDP.

Reuses the pinned shadowsocksrr server and fetch-time shims from phase7a.
UDP layering matches Go: SOCKS addr (no RSV/FRAG) → protocol → stream cipher
(obfs is TCP-only; UDP profiles use plain).
"""

from __future__ import annotations

import http.client
import json
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import (
    EchoHandler,
    HalfCloseHandler,
    IO_DEADLINE,
    ROOT,
    assert_go_oracle_baseline,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import (
    UdpEchoHandler,
    decode_socks_udp,
    launch,
    socks_udp_packet,
    stop,
    wait_udp_route,
)
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks_ciphers import LARGE_PAYLOAD, echo, half_close
from phase7a_ssr_tcp import (
    PASSWORD,
    SSR_SERVER_PIN,
    cancel_exchange,
    ensure_ssr_server,
    segmented_exchange,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase7c-ssr-diff.json"
SECRET = "phase7c-ssr-secret"

# (cipher, protocol, protocol_param, obfs, obfs_param, label)
TCP_PROFILES: list[tuple[str, str, str, str, str, str]] = [
    ("aes-128-cfb", "auth_sha1_v4", "", "plain", "", "auth_sha1_v4+plain"),
    ("aes-192-cfb", "auth_chain_a", "", "plain", "", "auth_chain_a+plain"),
    ("aes-256-cfb", "auth_chain_b", "", "plain", "", "auth_chain_b+plain"),
    ("aes-128-cfb", "origin", "", "random_head", "", "origin+random_head"),
    ("aes-128-ctr", "auth_sha1_v4", "", "random_head", "", "auth_sha1_v4+random_head"),
    ("rc4-md5", "origin", "", "plain", "", "origin+rc4-md5"),
    ("chacha20-ietf", "origin", "", "plain", "", "origin+chacha20-ietf"),
    ("none", "origin", "", "plain", "", "origin+none"),
    ("aes-128-cfb", "auth_chain_a", "", "http_simple", "", "auth_chain_a+http_simple"),
]

# UDP: obfs must be plain (TCP camouflage does not apply).
UDP_PROFILES: list[tuple[str, str, str, str]] = [
    ("aes-128-cfb", "origin", "", "origin+aes-128-cfb"),
    ("aes-128-cfb", "auth_aes128_md5", "", "auth_aes128_md5"),
    ("aes-128-cfb", "auth_sha1_v4", "", "auth_sha1_v4"),
    ("aes-128-cfb", "auth_chain_a", "", "auth_chain_a"),
    ("none", "origin", "", "origin+none"),
]


def write_tcp_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    ssr_port: int,
    cipher: str,
    protocol: str,
    protocol_param: str,
    obfs: str,
    obfs_param: str,
) -> None:
    lines = [
        f"mixed-port: {mixed_port}",
        "mode: rule",
        "log-level: info",
        "ipv6: false",
        "proxies:",
        "  - name: local-ssr",
        "    type: ssr",
        "    server: 127.0.0.1",
        f"    port: {ssr_port}",
        f"    password: {PASSWORD}",
        f"    cipher: {cipher}",
        f"    protocol: {protocol}",
        f"    obfs: {obfs}",
    ]
    if protocol_param:
        lines.append(f'    protocol-param: "{protocol_param}"')
    if obfs_param:
        lines.append(f"    obfs-param: {obfs_param}")
    lines.extend(
        [
            "proxy-groups:",
            "  - name: ssr-select",
            "    type: select",
            "    proxies: [local-ssr]",
            "    default-selected: local-ssr",
            "rules:",
            "  - MATCH,ssr-select",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_udp_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    socks_port: int,
    controller_port: int,
    ssr_port: int,
    cipher: str,
    protocol: str,
    protocol_param: str,
) -> None:
    lines = [
        f"mixed-port: {mixed_port}",
        f"socks-port: {socks_port}",
        f"external-controller: 127.0.0.1:{controller_port}",
        f"secret: {SECRET}",
        "mode: rule",
        "log-level: info",
        "ipv6: false",
        "proxies:",
        "  - name: local-ssr",
        "    type: ssr",
        "    server: 127.0.0.1",
        f"    port: {ssr_port}",
        f"    password: {PASSWORD}",
        f"    cipher: {cipher}",
        f"    protocol: {protocol}",
        "    obfs: plain",
        "    udp: true",
    ]
    if protocol_param:
        lines.append(f'    protocol-param: "{protocol_param}"')
    lines.extend(
        [
            "proxy-groups:",
            "  - name: ssr-select",
            "    type: select",
            "    proxies: [local-ssr]",
            "    default-selected: local-ssr",
            "rules:",
            "  - MATCH,ssr-select",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def exercise_tcp(
    binary: pathlib.Path,
    server_py: pathlib.Path,
    scratch: pathlib.Path,
    cipher: str,
    protocol: str,
    protocol_param: str,
    obfs: str,
    obfs_param: str,
    label: str,
) -> dict[str, Any]:
    echo_server = start_server(EchoHandler)
    half = start_server(HalfCloseHandler)
    mixed_port = reserve_port()
    ssr_port = reserve_port()
    authority, a_out, a_err = start_ssr_server_cipher(
        server_py,
        scratch,
        ssr_port,
        cipher=cipher,
        protocol=protocol,
        obfs=obfs,
        protocol_param=protocol_param,
        obfs_param=obfs_param,
    )
    config = scratch / "config.yaml"
    write_tcp_config(
        config,
        mixed_port=mixed_port,
        ssr_port=ssr_port,
        cipher=cipher,
        protocol=protocol,
        protocol_param=protocol_param,
        obfs=obfs,
        obfs_param=obfs_param,
    )
    process = stdout = stderr = None
    try:
        process, stdout, stderr = launch(binary, config, scratch)
        wait_ready(process, mixed_port)
        time.sleep(0.2)

        def safe_echo(payload: bytes) -> bool:
            try:
                return echo(mixed_port, "127.0.0.1", echo_server.port, payload)
            except (OSError, EOFError, TimeoutError):
                return False

        small = safe_echo(b"ssr-c-small")
        large = safe_echo(LARGE_PAYLOAD)
        try:
            segmented = segmented_exchange(
                mixed_port, "127.0.0.1", echo_server.port, LARGE_PAYLOAD
            )
        except (OSError, EOFError, TimeoutError):
            segmented = False
        try:
            half_ok = half_close(mixed_port, half.port)
        except (OSError, EOFError, TimeoutError):
            half_ok = False
        try:
            cancel_ok = cancel_exchange(mixed_port, "127.0.0.1", echo_server.port)
        except (OSError, EOFError, TimeoutError):
            cancel_ok = False
        return {
            "label": label,
            "cipher": cipher,
            "protocol": protocol,
            "obfs": obfs,
            "small": small,
            "large": large,
            "segmented": segmented,
            "half-close": half_ok,
            "cancel-isolated": cancel_ok,
            "process-alive": process.poll() is None,
            "ssr-server-pin": SSR_SERVER_PIN,
        }
    finally:
        if process is not None:
            stop(process)
        if stdout is not None:
            stdout.close()
        if stderr is not None:
            stderr.close()
        if authority.poll() is None:
            authority.kill()
            try:
                authority.wait(timeout=IO_DEADLINE)
            except subprocess.TimeoutExpired:
                pass
        a_out.close()
        a_err.close()
        echo_server.close()
        half.close()


def start_ssr_server_cipher(
    server_py: pathlib.Path,
    scratch: pathlib.Path,
    port: int,
    *,
    cipher: str,
    protocol: str,
    obfs: str,
    protocol_param: str,
    obfs_param: str,
) -> tuple[Any, Any, Any]:
    import os

    env = os.environ.copy()
    env["PYTHONPATH"] = str(server_py.parent.parent)
    stdout = (scratch / "ssr-server.stdout").open("wb")
    stderr = (scratch / "ssr-server.stderr").open("wb")
    cmd = [
        "python3",
        str(server_py),
        "-s",
        "127.0.0.1",
        "-p",
        str(port),
        "-k",
        PASSWORD,
        "-m",
        cipher,
        "-O",
        protocol,
        "-o",
        obfs,
        "--forbidden-ip",
        "",
        "-q",
    ]
    if protocol_param:
        cmd.extend(["-G", protocol_param])
    if obfs_param:
        cmd.extend(["-g", obfs_param])
    process = subprocess.Popen(
        cmd,
        cwd=str(server_py.parent),
        env=env,
        stdout=stdout,
        stderr=stderr,
    )
    deadline = time.time() + 8
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"SSR server exited early ({cipher}/{protocol}/{obfs}): "
                f"{(scratch / 'ssr-server.stderr').read_text()[:800]}"
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return process, stdout, stderr
        except OSError:
            time.sleep(0.1)
    process.kill()
    raise RuntimeError(f"SSR server failed to accept ({cipher}/{protocol}/{obfs})")


def proxy_snapshot(controller_port: int) -> dict[str, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", controller_port, timeout=5)
    connection.request(
        "GET",
        "/proxies/local-ssr",
        headers={"Authorization": f"Bearer {SECRET}"},
    )
    response = connection.getresponse()
    body = response.read()
    connection.close()
    if response.status != 200:
        raise AssertionError((response.status, body))
    payload = json.loads(body)
    return {
        "name": payload["name"],
        "type": payload["type"],
        "udp": payload["udp"],
    }


def reload_config(controller_port: int, config_path: pathlib.Path) -> bool:
    connection = http.client.HTTPConnection("127.0.0.1", controller_port, timeout=5)
    body = json.dumps({"path": str(config_path)}).encode()
    connection.request(
        "PUT",
        "/configs?force=true",
        body=body,
        headers={
            "Authorization": f"Bearer {SECRET}",
            "Content-Type": "application/json",
        },
    )
    response = connection.getresponse()
    _ = response.read()
    connection.close()
    return response.status in {200, 204}


def exercise_udp(
    binary: pathlib.Path,
    server_py: pathlib.Path,
    scratch: pathlib.Path,
    cipher: str,
    protocol: str,
    protocol_param: str,
    label: str,
) -> dict[str, Any]:
    echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
    echo_thread.start()
    echo_port = int(echo.server_address[1])
    mixed_port = reserve_port()
    socks_port = reserve_port()
    controller_port = reserve_port()
    ssr_port = reserve_port()
    authority, a_out, a_err = start_ssr_server_cipher(
        server_py,
        scratch,
        ssr_port,
        cipher=cipher,
        protocol=protocol,
        obfs="plain",
        protocol_param=protocol_param,
        obfs_param="",
    )
    config = scratch / "config.yaml"
    write_udp_config(
        config,
        mixed_port=mixed_port,
        socks_port=socks_port,
        controller_port=controller_port,
        ssr_port=ssr_port,
        cipher=cipher,
        protocol=protocol,
        protocol_param=protocol_param,
    )
    process = stdout = stderr = None
    try:
        process, stdout, stderr = launch(binary, config, scratch)
        wait_ready(process, mixed_port)
        wait_ready(process, socks_port)
        wait_udp_route(process, mixed_port, echo_port)
        first = f"ssr-c-udp-{label}".encode()
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(IO_DEADLINE)
        try:
            client.sendto(socks_udp_packet(echo_port, first), ("127.0.0.1", mixed_port))
            packet, _ = client.recvfrom(65_535)
            address, _, payload = decode_socks_udp(packet)
            ipv4_ok = address == "127.0.0.1" and payload == first
            reused = bytes(range(256)) * 8
            client.sendto(socks_udp_packet(echo_port, reused), ("127.0.0.1", mixed_port))
            packet, _ = client.recvfrom(65_535)
            _, _, payload = decode_socks_udp(packet)
            reuse_ok = payload == reused
        finally:
            client.close()
        snapshot = proxy_snapshot(controller_port)
        # Reload with an identical path (lifecycle smoke); UDP must still work.
        reload_ok = reload_config(controller_port, config)
        wait_udp_route(process, mixed_port, echo_port)
        after = f"ssr-c-udp-reload-{label}".encode()
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(IO_DEADLINE)
        try:
            client.sendto(socks_udp_packet(echo_port, after), ("127.0.0.1", mixed_port))
            packet, _ = client.recvfrom(65_535)
            _, _, payload = decode_socks_udp(packet)
            after_reload = payload == after
        finally:
            client.close()
        return {
            "label": label,
            "cipher": cipher,
            "protocol": protocol,
            "ipv4": ipv4_ok,
            "session-reuse": reuse_ok,
            "controller": snapshot,
            "reload": reload_ok,
            "after-reload": after_reload,
            "process-alive": process.poll() is None,
            "ssr-server-pin": SSR_SERVER_PIN,
        }
    finally:
        if process is not None:
            stop(process)
        if stdout is not None:
            stdout.close()
        if stderr is not None:
            stderr.close()
        if authority.poll() is None:
            authority.kill()
            try:
                authority.wait(timeout=IO_DEADLINE)
            except subprocess.TimeoutExpired:
                pass
        a_out.close()
        a_err.close()
        echo.shutdown()
        echo.server_close()


def shared_tcp(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        key: profile[key]
        for key in (
            "label",
            "cipher",
            "protocol",
            "obfs",
            "small",
            "large",
            "segmented",
            "cancel-isolated",
            "process-alive",
            "ssr-server-pin",
        )
    }


def shared_udp(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        key: profile[key]
        for key in (
            "label",
            "cipher",
            "protocol",
            "ipv4",
            "session-reuse",
            "controller",
            "reload",
            "after-reload",
            "process-alive",
            "ssr-server-pin",
        )
    }


def main() -> int:
    assert_go_oracle_baseline()
    observations: dict[str, Any] = {}
    server_py = ensure_ssr_server()
    with tempfile.TemporaryDirectory(prefix="phase7c-ssr-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE7C_SSR_CARGO_TARGET", "phase7c-ssr")
        try:
            for engine in ("rust", "go"):
                tcp: dict[str, Any] = {}
                for cipher, protocol, protocol_param, obfs, obfs_param, label in TCP_PROFILES:
                    scratch = root / engine / "tcp" / label.replace("+", "_")
                    scratch.mkdir(parents=True)
                    tcp[label] = exercise_tcp(
                        binaries[engine],
                        server_py,
                        scratch,
                        cipher,
                        protocol,
                        protocol_param,
                        obfs,
                        obfs_param,
                        label,
                    )
                udp: dict[str, Any] = {}
                for cipher, protocol, protocol_param, label in UDP_PROFILES:
                    scratch = root / engine / "udp" / label.replace("+", "_")
                    scratch.mkdir(parents=True)
                    udp[label] = exercise_udp(
                        binaries[engine],
                        server_py,
                        scratch,
                        cipher,
                        protocol,
                        protocol_param,
                        label,
                    )
                observations[engine] = {"tcp": tcp, "udp": udp}

            reject = root / "reject"
            reject.mkdir()
            bad = reject / "bad.yaml"
            bad.write_text(
                """mixed-port: 0
mode: rule
proxies:
  - name: bad
    type: ssr
    server: 127.0.0.1
    port: 1
    password: x
    cipher: aes-128-gcm
    protocol: origin
    obfs: plain
""",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [str(binaries["rust"]), "-d", str(reject), "-f", str(bad)],
                capture_output=True,
                timeout=20,
                check=False,
            )
            observations["rust-rejects-aead"] = proc.returncode != 0
            bad.write_text(
                """mixed-port: 0
mode: rule
proxies:
  - name: bad
    type: ssr
    server: 127.0.0.1
    port: 1
    password: x
    cipher: chacha20
    protocol: origin
    obfs: plain
""",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [str(binaries["rust"]), "-d", str(reject), "-f", str(bad)],
                capture_output=True,
                timeout=20,
                check=False,
            )
            observations["rust-rejects-legacy-chacha20"] = proc.returncode != 0
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

    go_tcp = {
        label: shared_tcp(profile)
        for label, profile in observations.get("go", {}).get("tcp", {}).items()
    }
    rust_tcp = {
        label: shared_tcp(profile)
        for label, profile in observations.get("rust", {}).get("tcp", {}).items()
    }
    go_udp = {
        label: shared_udp(profile)
        for label, profile in observations.get("go", {}).get("udp", {}).items()
    }
    rust_udp = {
        label: shared_udp(profile)
        for label, profile in observations.get("rust", {}).get("udp", {}).items()
    }

    rust_half_ok = all(
        profile.get("half-close")
        for profile in observations.get("rust", {}).get("tcp", {}).values()
    )

    if (
        go_tcp != rust_tcp
        or go_udp != rust_udp
        or not rust_half_ok
        or not observations.get("rust-rejects-aead")
        or not observations.get("rust-rejects-legacy-chacha20")
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1

    for engine in ("go", "rust"):
        for label, profile in observations[engine]["tcp"].items():
            required = (
                "small",
                "large",
                "segmented",
                "cancel-isolated",
                "process-alive",
            )
            if engine == "rust":
                required = (*required, "half-close")
            if not all(profile.get(key) for key in required):
                FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
                FAILURE_ARTIFACT.write_text(
                    json.dumps(observations, indent=2, sort_keys=True)
                )
                return 1
        for label, profile in observations[engine]["udp"].items():
            required = (
                "ipv4",
                "session-reuse",
                "reload",
                "after-reload",
                "process-alive",
            )
            if not all(profile.get(key) for key in required):
                FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
                FAILURE_ARTIFACT.write_text(
                    json.dumps(observations, indent=2, sort_keys=True)
                )
                return 1
            controller = profile.get("controller") or {}
            if controller.get("udp") is not True or controller.get("type") != "ShadowsocksR":
                FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
                FAILURE_ARTIFACT.write_text(
                    json.dumps(observations, indent=2, sort_keys=True)
                )
                return 1

    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("SSR-C ShadowsocksR TCP/UDP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

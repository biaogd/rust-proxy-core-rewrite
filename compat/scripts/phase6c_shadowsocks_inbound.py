#!/usr/bin/env python3
"""Go/Rust differential for Shadowsocks ss-config inbound TCP and UDP."""

from __future__ import annotations

import base64
import json
import os
import pathlib
import socketserver
import subprocess
import tempfile
import threading
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
from phase3 import UdpEchoHandler, launch, stop
from phase4 import dns_query
from phase5b1a import build_binaries, debug_files
from phase6b_socks5_udp import ControlServer, RelayServer
from phase6c_shadowsocks import PASSWORD as OUTBOUND_PASSWORD, start_authority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-inbound-diff.json"
PASSWORD = "phase6c-inbound-password"
CIPHER = "aes-128-gcm"
LEGACY_CIPHER = "aes-128-ctr"
TCP_PAYLOAD = "phase6c-ss-inbound-tcp"
LEGACY_TCP_PAYLOAD = "phase6c-ss-inbound-legacy-tcp"
UDP_PAYLOAD = "phase6c-ss-inbound-udp"
UDP_REUSE_PAYLOAD = "phase6c-ss-inbound-udp-reuse-" + ("x" * 4096)
PROXY_UDP_PAYLOAD = "phase6c-ss-inbound-proxy-udp"
PROXY_UDP_UOT_PAYLOAD = "phase6c-ss-inbound-proxy-udp-uot"
SOCKS5_UDP_PAYLOAD = "phase6c-ss-inbound-socks5-udp"
DNS_QUERY_ID = 0x6A10
KEY_2022 = "AAECAwQFBgcICQoLDA0ODw=="
CIPHER_2022 = "2022-blake3-aes-128-gcm"
TCP_2022_PAYLOAD = "phase6c-ss-inbound-2022-tcp"
OBFS_HOST = "phase6c-inbound.example"
OBFS_TLS_HOST = "phase6c-inbound-tls.example"
TCP_OBFS_PAYLOAD = "phase6c-ss-inbound-obfs-http"
TCP_OBFS_TLS_PAYLOAD = "phase6c-ss-inbound-obfs-tls"
STLS_HOST = "phase6c-shadow-tls.example"
STLS_PASSWORD = "phase6c-shadow-tls-plugin-password"
TCP_STLS_PAYLOAD = "phase6c-ss-inbound-shadow-tls"
KEY_2022_EIH_USER = "EBESExQVFhcYGRobHB0eHw=="
TCP_2022_EIH_PAYLOAD = "phase6c-ss-inbound-2022-eih"
TCP_UOT_V1_PAYLOAD = "phase6c-ss-inbound-uot-v1"
TCP_UOT_V2_PAYLOAD = "phase6c-ss-inbound-uot-v2"
TCP_UOT_SOCKS5_PAYLOAD = "phase6c-ss-inbound-uot-socks5"
TCP_UOT_PROXY_PAYLOAD = "phase6c-ss-inbound-uot-proxy"
TCP_UOT_PROXY_UOT_PAYLOAD = "phase6c-ss-inbound-uot-proxy-uot"


def client_binary() -> pathlib.Path:
    target = cargo_target_path("PHASE6CSSINBOUND_CARGO_TARGET", "phase6c-shadowsocks-inbound")
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-client{suffix}"


def udp_client_binary() -> pathlib.Path:
    target = cargo_target_path("PHASE6CSSINBOUND_CARGO_TARGET", "phase6c-shadowsocks-inbound")
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-udp-client{suffix}"


def uot_client_binary() -> pathlib.Path:
    target = cargo_target_path("PHASE6CSSINBOUND_CARGO_TARGET", "phase6c-shadowsocks-inbound")
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-uot-client{suffix}"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path("PHASE6CSSINBOUND_CARGO_TARGET", "phase6c-shadowsocks-inbound")
    suffix = ".exe" if os.name == "nt" else ""
    return target / "debug" / f"rewrite-shadowsocks-authority{suffix}"


def proxied_echo(
    client: pathlib.Path,
    ss_port: int,
    echo_port: int,
    cipher: str = CIPHER,
    password: str = PASSWORD,
    payload: str = TCP_PAYLOAD,
    obfs_mode: str | None = None,
    obfs_host: str | None = None,
    plugin_password: str | None = None,
    plugin_version: int | None = None,
) -> bool:
    command = [
        str(client),
        f"127.0.0.1:{ss_port}",
        password,
        cipher,
        "127.0.0.1",
        str(echo_port),
        payload,
    ]
    if obfs_mode is not None:
        command.append(obfs_mode)
        if obfs_host is not None:
            command.append(obfs_host)
        if plugin_password is not None:
            command.append(plugin_password)
        if plugin_version is not None:
            command.append(str(plugin_version))
    try:
        completed = subprocess.run(command, check=False, capture_output=True, timeout=IO_DEADLINE)
        return completed.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def wait_ss_route(
    process: subprocess.Popen[bytes],
    client: pathlib.Path,
    ss_port: int,
    echo_port: int,
    cipher: str = CIPHER,
    password: str = PASSWORD,
    payload: str = TCP_PAYLOAD,
    obfs_mode: str | None = None,
    obfs_host: str | None = None,
    plugin_password: str | None = None,
    plugin_version: int | None = None,
) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during readiness with {process.returncode}")
        try:
            if proxied_echo(
                client,
                ss_port,
                echo_port,
                cipher,
                password,
                payload,
                obfs_mode,
                obfs_host,
                plugin_password,
                plugin_version,
            ):
                return
        except (AssertionError, OSError, subprocess.SubprocessError):
            pass
        time.sleep(0.02)
    raise TimeoutError("Shadowsocks inbound route did not become ready")


def proxied_uot(
    client: pathlib.Path,
    ss_port: int,
    echo_port: int,
    payload: str,
    version: int,
    cipher: str = CIPHER,
    password: str = PASSWORD,
) -> bool:
    command = [
        str(client),
        f"127.0.0.1:{ss_port}",
        password,
        cipher,
        "127.0.0.1",
        str(echo_port),
        payload,
        str(version),
    ]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, timeout=IO_DEADLINE)
        return completed.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def wait_ss_uot_route(
    process: subprocess.Popen[bytes],
    client: pathlib.Path,
    ss_port: int,
    echo_port: int,
    payload: str,
    version: int,
    cipher: str = CIPHER,
    password: str = PASSWORD,
) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during UoT readiness with {process.returncode}")
        try:
            if proxied_uot(
                client,
                ss_port,
                echo_port,
                payload,
                version,
                cipher,
                password,
            ):
                return
        except (AssertionError, OSError, subprocess.SubprocessError):
            pass
        time.sleep(0.02)
    raise TimeoutError("Shadowsocks inbound UoT route did not become ready")


def proxied_udp(
    client: pathlib.Path,
    ss_port: int,
    echo_port: int,
    payload: str = UDP_PAYLOAD,
    cipher: str = CIPHER,
    password: str = PASSWORD,
    reuse_payload: str | None = None,
    verify_dns: bool = False,
) -> bool:
    command = [
        str(client),
        f"127.0.0.1:{ss_port}",
        password,
        cipher,
        "127.0.0.1",
        str(echo_port),
        payload,
    ]
    if verify_dns:
        command.append("verify-dns")
    elif reuse_payload is not None:
        command.append(reuse_payload)
    try:
        completed = subprocess.run(command, check=False, capture_output=True, timeout=IO_DEADLINE)
        return completed.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def wait_ss_udp_route(
    process: subprocess.Popen[bytes],
    client: pathlib.Path,
    ss_port: int,
    echo_port: int,
    payload: str = UDP_PAYLOAD,
    cipher: str = CIPHER,
) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during UDP readiness with {process.returncode}")
        try:
            if proxied_udp(client, ss_port, echo_port, payload, cipher):
                return
        except (AssertionError, OSError, subprocess.SubprocessError):
            pass
        time.sleep(0.02)
    raise TimeoutError("Shadowsocks inbound UDP route did not become ready")


def exercise(
    binary: pathlib.Path,
    client: pathlib.Path,
    udp_client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    echo = start_server(EchoHandler)
    udp_echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    udp_thread = threading.Thread(target=udp_echo.serve_forever, daemon=True)
    udp_thread.start()
    udp_port = int(udp_echo.server_address[1])
    ss_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""ss-config: ss://{CIPHER}:{PASSWORD}@127.0.0.1:{ss_port}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ss_route(process, client, ss_port, echo.port)
        wait_ss_udp_route(process, udp_client, ss_port, udp_port)
        return {
            "domain-aead-tcp": proxied_echo(client, ss_port, echo.port),
            "domain-aead-udp": proxied_udp(udp_client, ss_port, udp_port),
            "same-client-udp-session-reuse": proxied_udp(
                udp_client,
                ss_port,
                udp_port,
                reuse_payload=UDP_REUSE_PAYLOAD,
            ),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()
        udp_echo.shutdown()
        udp_echo.server_close()
        udp_thread.join(timeout=1)


def exercise_legacy_tcp(
    binary: pathlib.Path,
    client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    echo = start_server(EchoHandler)
    ss_port = reserve_port()
    config = scratch / "legacy-config.yaml"
    config.write_text(
        f"""ss-config: ss://{LEGACY_CIPHER}:{PASSWORD}@127.0.0.1:{ss_port}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ss_route(
            process,
            client,
            ss_port,
            echo.port,
            cipher=LEGACY_CIPHER,
            password=PASSWORD,
            payload=LEGACY_TCP_PAYLOAD,
        )
        return {
            "legacy-tcp": proxied_echo(
                client,
                ss_port,
                echo.port,
                cipher=LEGACY_CIPHER,
                password=PASSWORD,
                payload=LEGACY_TCP_PAYLOAD,
            ),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise_2022_tcp(
    binary: pathlib.Path,
    client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    echo = start_server(EchoHandler)
    ss_port = reserve_port()
    config = scratch / "2022-config.yaml"
    config.write_text(
        f"""ss-config: ss://{CIPHER_2022}:{KEY_2022}@127.0.0.1:{ss_port}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ss_route(
            process,
            client,
            ss_port,
            echo.port,
            cipher=CIPHER_2022,
            password=KEY_2022,
            payload=TCP_2022_PAYLOAD,
        )
        return {
            "2022-tcp": proxied_echo(
                client,
                ss_port,
                echo.port,
                cipher=CIPHER_2022,
                password=KEY_2022,
                payload=TCP_2022_PAYLOAD,
            ),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise_dns_udp(
    binary: pathlib.Path,
    udp_client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    dns_port = reserve_port()
    ss_port = reserve_port()
    query = dns_query("ss-inbound.phase6c.test", DNS_QUERY_ID)
    encoded_query = "b64:" + base64.b64encode(query).decode("ascii")
    config = scratch / "dns-udp-config.yaml"
    config.write_text(
        f"""ss-config: ss://{CIPHER}:{PASSWORD}@127.0.0.1:{ss_port}
mode: rule
log-level: info
ipv6: false
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  nameserver: [rcode://success]
proxies:
  - name: dns-local
    type: dns
rules:
  - DST-PORT,53,dns-local
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, dns_port)
        deadline = time.monotonic() + IO_DEADLINE
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"proxy exited during DNS UDP readiness with {process.returncode}")
            if proxied_udp(
                udp_client,
                ss_port,
                53,
                payload=encoded_query,
                verify_dns=True,
            ):
                return {"dns-udp": True}
            time.sleep(0.02)
        raise TimeoutError("Shadowsocks inbound DNS UDP route did not become ready")
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def exercise_socks5_udp(
    binary: pathlib.Path,
    udp_client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    relay = RelayServer()
    control = ControlServer(relay)
    ss_port = reserve_port()
    destination_port = 32_010
    config = scratch / "socks5-udp-config.yaml"
    config.write_text(
        f"""ss-config: ss://{CIPHER}:{PASSWORD}@127.0.0.1:{ss_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: relay-socks5
    type: socks5
    server: 127.0.0.1
    port: {control.port}
    username: udp-user
    password: udp-pass
    udp: true
rules:
  - MATCH,relay-socks5
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    time.sleep(0.5)
    try:
        deadline = time.monotonic() + IO_DEADLINE
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"proxy exited during SOCKS5 UDP readiness with {process.returncode}"
                )
            if proxied_udp(
                udp_client,
                ss_port,
                destination_port,
                payload=SOCKS5_UDP_PAYLOAD,
            ):
                return {"socks5-udp": True}
            time.sleep(0.02)
        raise TimeoutError("Shadowsocks inbound SOCKS5 UDP route did not become ready")
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        relay.close()
        control.close()


def exercise_obfs_http_listener(
    binary: pathlib.Path,
    client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    echo = start_server(EchoHandler)
    ss_port = reserve_port()
    config = scratch / "obfs-listener-config.yaml"
    config.write_text(
        f"""mode: rule
log-level: info
ipv6: false
listeners:
  - name: ss-obfs-inbound
    type: shadowsocks
    listen: 127.0.0.1
    port: {ss_port}
    cipher: {CIPHER}
    password: {PASSWORD}
    udp: false
    simple-obfs:
      enable: true
      mode: http
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ss_route(
            process,
            client,
            ss_port,
            echo.port,
            payload=TCP_OBFS_PAYLOAD,
            obfs_mode="http",
            obfs_host=OBFS_HOST,
        )
        return {
            "named-obfs-http-tcp": proxied_echo(
                client,
                ss_port,
                echo.port,
                payload=TCP_OBFS_PAYLOAD,
                obfs_mode="http",
                obfs_host=OBFS_HOST,
            ),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise_obfs_tls_listener(
    binary: pathlib.Path,
    client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    echo = start_server(EchoHandler)
    ss_port = reserve_port()
    config = scratch / "obfs-tls-listener-config.yaml"
    config.write_text(
        f"""mode: rule
log-level: info
ipv6: false
listeners:
  - name: ss-obfs-tls-inbound
    type: shadowsocks
    listen: 127.0.0.1
    port: {ss_port}
    cipher: {CIPHER}
    password: {PASSWORD}
    udp: false
    simple-obfs:
      enable: true
      mode: tls
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ss_route(
            process,
            client,
            ss_port,
            echo.port,
            payload=TCP_OBFS_TLS_PAYLOAD,
            obfs_mode="tls",
            obfs_host=OBFS_TLS_HOST,
        )
        return {
            "named-obfs-tls-tcp": proxied_echo(
                client,
                ss_port,
                echo.port,
                payload=TCP_OBFS_TLS_PAYLOAD,
                obfs_mode="tls",
                obfs_host=OBFS_TLS_HOST,
            ),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise_uot_listener(
    binary: pathlib.Path,
    uot_client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    udp_echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    udp_thread = threading.Thread(target=udp_echo.serve_forever, daemon=True)
    udp_thread.start()
    udp_port = int(udp_echo.server_address[1])
    ss_port = reserve_port()
    config = scratch / "uot-listener-config.yaml"
    config.write_text(
        f"""ss-config: ss://{CIPHER}:{PASSWORD}@127.0.0.1:{ss_port}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ss_uot_route(
            process,
            uot_client,
            ss_port,
            udp_port,
            payload=TCP_UOT_V1_PAYLOAD,
            version=1,
        )
        wait_ss_uot_route(
            process,
            uot_client,
            ss_port,
            udp_port,
            payload=TCP_UOT_V2_PAYLOAD,
            version=2,
        )
        return {
            "inbound-uot-v1": proxied_uot(
                uot_client,
                ss_port,
                udp_port,
                payload=TCP_UOT_V1_PAYLOAD,
                version=1,
            ),
            "inbound-uot-v2": proxied_uot(
                uot_client,
                ss_port,
                udp_port,
                payload=TCP_UOT_V2_PAYLOAD,
                version=2,
            ),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        udp_echo.shutdown()
        udp_echo.server_close()
        udp_thread.join(timeout=1)


def exercise_uot_socks5(
    binary: pathlib.Path,
    uot_client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    relay = RelayServer()
    control = ControlServer(relay)
    ss_port = reserve_port()
    destination_port = 32_011
    config = scratch / "uot-socks5-config.yaml"
    config.write_text(
        f"""ss-config: ss://{CIPHER}:{PASSWORD}@127.0.0.1:{ss_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: relay-socks5
    type: socks5
    server: 127.0.0.1
    port: {control.port}
    username: udp-user
    password: udp-pass
    udp: true
rules:
  - MATCH,relay-socks5
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ss_uot_route(
            process,
            uot_client,
            ss_port,
            destination_port,
            payload=TCP_UOT_SOCKS5_PAYLOAD,
            version=1,
        )
        return {
            "inbound-uot-socks5": proxied_uot(
                uot_client,
                ss_port,
                destination_port,
                payload=TCP_UOT_SOCKS5_PAYLOAD,
                version=1,
            ),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        relay.close()
        control.close()


def exercise_uot_proxied(
    binary: pathlib.Path,
    uot_client: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    udp_echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    udp_thread = threading.Thread(target=udp_echo.serve_forever, daemon=True)
    udp_thread.start()
    udp_port = int(udp_echo.server_address[1])
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority, scratch, authority_port, cipher=CIPHER, password=OUTBOUND_PASSWORD
    )
    time.sleep(0.2)
    ss_port = reserve_port()
    config = scratch / "uot-proxy-config.yaml"
    config.write_text(
        f"""ss-config: ss://{CIPHER}:{PASSWORD}@127.0.0.1:{ss_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: relay-ss
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {CIPHER}
    password: {OUTBOUND_PASSWORD}
    udp: true
rules:
  - MATCH,relay-ss
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ss_uot_route(
            process,
            uot_client,
            ss_port,
            udp_port,
            payload=TCP_UOT_PROXY_PAYLOAD,
            version=1,
        )
        return {
            "inbound-uot-proxy": proxied_uot(
                uot_client,
                ss_port,
                udp_port,
                payload=TCP_UOT_PROXY_PAYLOAD,
                version=1,
            ),
        }
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        udp_echo.shutdown()
        udp_echo.server_close()
        udp_thread.join(timeout=1)


def exercise_uot_proxied_uot(
    binary: pathlib.Path,
    uot_client: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    udp_echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    udp_thread = threading.Thread(target=udp_echo.serve_forever, daemon=True)
    udp_thread.start()
    udp_port = int(udp_echo.server_address[1])
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority, scratch, authority_port, cipher=CIPHER, password=OUTBOUND_PASSWORD
    )
    time.sleep(0.2)
    ss_port = reserve_port()
    config = scratch / "uot-proxy-uot-config.yaml"
    config.write_text(
        f"""ss-config: ss://{CIPHER}:{PASSWORD}@127.0.0.1:{ss_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: relay-ss-uot
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {CIPHER}
    password: {OUTBOUND_PASSWORD}
    udp: true
    udp-over-tcp: true
    udp-over-tcp-version: 1
rules:
  - MATCH,relay-ss-uot
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ss_uot_route(
            process,
            uot_client,
            ss_port,
            udp_port,
            payload=TCP_UOT_PROXY_UOT_PAYLOAD,
            version=1,
        )
        return {
            "inbound-uot-proxy-uot": proxied_uot(
                uot_client,
                ss_port,
                udp_port,
                payload=TCP_UOT_PROXY_UOT_PAYLOAD,
                version=1,
            ),
        }
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        udp_echo.shutdown()
        udp_echo.server_close()
        udp_thread.join(timeout=1)


def start_camouflage_tls(scratch: pathlib.Path) -> tuple[Any, int]:
    certificate = scratch / "camouflage.pem"
    private_key = scratch / "camouflage.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            f"/CN={STLS_HOST}",
            "-days",
            "1",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
        ],
        cwd=scratch,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=IO_DEADLINE,
    )
    port = reserve_port()
    process = subprocess.Popen(
        [
            "openssl",
            "s_server",
            "-accept",
            str(port),
            "-cert",
            str(certificate),
            "-key",
            str(private_key),
            "-www",
            "-tls1_2",
            "-quiet",
        ],
        cwd=scratch,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.2)
    return process, port


def exercise_shadow_tls_listener(
    binary: pathlib.Path,
    client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    echo = start_server(EchoHandler)
    camouflage, camouflage_port = start_camouflage_tls(scratch)
    ss_port = reserve_port()
    config = scratch / "shadow-tls-listener-config.yaml"
    config.write_text(
        f"""mode: rule
log-level: info
ipv6: false
listeners:
  - name: ss-shadow-tls-inbound
    type: shadowsocks
    listen: 127.0.0.1
    port: {ss_port}
    cipher: {CIPHER}
    password: {PASSWORD}
    udp: false
    shadow-tls:
      enable: true
      version: 3
      users:
        - name: phase6c-user
          password: {STLS_PASSWORD}
      handshake:
        dest: 127.0.0.1:{camouflage_port}
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ss_route(
            process,
            client,
            ss_port,
            echo.port,
            payload=TCP_STLS_PAYLOAD,
            obfs_mode="shadow-tls",
            obfs_host=STLS_HOST,
            plugin_password=STLS_PASSWORD,
            plugin_version=3,
        )
        return {
            "named-shadow-tls-tcp": proxied_echo(
                client,
                ss_port,
                echo.port,
                payload=TCP_STLS_PAYLOAD,
                obfs_mode="shadow-tls",
                obfs_host=STLS_HOST,
                plugin_password=STLS_PASSWORD,
                plugin_version=3,
            ),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()
        camouflage.terminate()
        camouflage.wait(timeout=1)


def exercise_2022_eih_tcp(
    binary: pathlib.Path,
    client: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    """Rust SS2022 EIH inbound smoke (Go Clash cannot listen with server:user PSK)."""
    echo = start_server(EchoHandler)
    ss_port = reserve_port()
    password = f"{KEY_2022}:{KEY_2022_EIH_USER}"
    scratch.mkdir(parents=True, exist_ok=True)
    config = scratch / "2022-eih-config.yaml"
    config.write_text(
        f"""mode: rule
log-level: info
ipv6: false
listeners:
  - name: ss-2022-eih
    type: shadowsocks
    listen: 127.0.0.1
    port: {ss_port}
    cipher: {CIPHER_2022}
    password: "{password}"
    udp: false
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ss_route(
            process,
            client,
            ss_port,
            echo.port,
            cipher=CIPHER_2022,
            password=password,
            payload=TCP_2022_EIH_PAYLOAD,
        )
        return {
            "named-2022-eih-tcp": proxied_echo(
                client,
                ss_port,
                echo.port,
                cipher=CIPHER_2022,
                password=password,
                payload=TCP_2022_EIH_PAYLOAD,
            ),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise_config_validation(
    binary: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    cases = {
        "valid-2022-inbound": (
            f"ss-config: ss://{CIPHER_2022}:{KEY_2022}@127.0.0.1:18395\n"
            "mode: rule\nrules: [MATCH,DIRECT]\n",
            True,
        ),
        "invalid-2022-inbound-key": (
            f"ss-config: ss://{CIPHER_2022}:not-base64@127.0.0.1:18396\n"
            "mode: rule\nrules: [MATCH,DIRECT]\n",
            False,
        ),
    }
    observations = {}
    for label, (source, should_pass) in cases.items():
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
        observations[label] = (result.returncode == 0) == should_pass
    return observations


def exercise_proxied_udp(
    binary: pathlib.Path,
    udp_client: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    udp_echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    udp_thread = threading.Thread(target=udp_echo.serve_forever, daemon=True)
    udp_thread.start()
    udp_port = int(udp_echo.server_address[1])
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority, scratch, authority_port, cipher=CIPHER, password=OUTBOUND_PASSWORD
    )
    time.sleep(0.2)
    ss_port = reserve_port()
    config = scratch / "proxy-udp-config.yaml"
    config.write_text(
        f"""ss-config: ss://{CIPHER}:{PASSWORD}@127.0.0.1:{ss_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: relay-ss
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {CIPHER}
    password: {OUTBOUND_PASSWORD}
    udp: true
rules:
  - MATCH,relay-ss
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    time.sleep(0.2)
    try:
        wait_ss_udp_route(
            process,
            udp_client,
            ss_port,
            udp_port,
            payload=PROXY_UDP_PAYLOAD,
        )
        return {
            "proxy-udp": proxied_udp(
                udp_client,
                ss_port,
                udp_port,
                payload=PROXY_UDP_PAYLOAD,
            ),
        }
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        udp_echo.shutdown()
        udp_echo.server_close()
        udp_thread.join(timeout=1)


def exercise_proxied_udp_uot(
    binary: pathlib.Path,
    udp_client: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, bool]:
    udp_echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    udp_thread = threading.Thread(target=udp_echo.serve_forever, daemon=True)
    udp_thread.start()
    udp_port = int(udp_echo.server_address[1])
    authority_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority, scratch, authority_port, cipher=CIPHER, password=OUTBOUND_PASSWORD
    )
    time.sleep(0.2)
    ss_port = reserve_port()
    config = scratch / "proxy-udp-uot-config.yaml"
    config.write_text(
        f"""ss-config: ss://{CIPHER}:{PASSWORD}@127.0.0.1:{ss_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: relay-ss-uot
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {CIPHER}
    password: {OUTBOUND_PASSWORD}
    udp: true
    udp-over-tcp: true
    udp-over-tcp-version: 1
rules:
  - MATCH,relay-ss-uot
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    time.sleep(0.2)
    try:
        wait_ss_udp_route(
            process,
            udp_client,
            ss_port,
            udp_port,
            payload=PROXY_UDP_UOT_PAYLOAD,
        )
        return {
            "proxy-udp-uot": proxied_udp(
                udp_client,
                ss_port,
                udp_port,
                payload=PROXY_UDP_UOT_PAYLOAD,
            ),
        }
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        udp_echo.shutdown()
        udp_echo.server_close()
        udp_thread.join(timeout=1)


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-inbound-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6CSSINBOUND_CARGO_TARGET", "phase6c-shadowsocks-inbound")
        client = client_binary()
        udp_client = udp_client_binary()
        uot_client = uot_client_binary()
        authority = authority_binary()
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = {
                    **exercise(binary, client, udp_client, scratch),
                    **exercise_legacy_tcp(binary, client, scratch),
                    **exercise_2022_tcp(binary, client, scratch),
                    **exercise_dns_udp(binary, udp_client, scratch),
                    **exercise_socks5_udp(binary, udp_client, scratch),
                    **exercise_obfs_http_listener(binary, client, scratch),
                    **exercise_obfs_tls_listener(binary, client, scratch),
                    **exercise_shadow_tls_listener(binary, client, scratch),
                    **exercise_uot_listener(binary, uot_client, scratch),
                    **exercise_uot_socks5(binary, uot_client, scratch),
                    **exercise_uot_proxied(binary, uot_client, authority, scratch),
                    **exercise_uot_proxied_uot(binary, uot_client, authority, scratch),
                    **exercise_proxied_udp(binary, udp_client, authority, scratch),
                    **exercise_proxied_udp_uot(binary, udp_client, authority, scratch),
                    **exercise_config_validation(binary, scratch),
                }
            # Go Clash cannot listen with `server:user` 2022 PSK (decode psk fails).
            # Exercise Rust EIH inbound separately so Go/Rust observations stay aligned.
            rust_eih_scratch = root / "rust-eih"
            rust_eih_scratch.mkdir()
            rust_eih = exercise_2022_eih_tcp(
                binaries["rust"],
                client,
                rust_eih_scratch,
            )
            if not rust_eih.get("named-2022-eih-tcp"):
                raise RuntimeError(f"Rust SS2022 EIH inbound failed: {rust_eih}")
            observations["rust-eih"] = rust_eih
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
    print("Phase 6C-N Shadowsocks ss-config inbound TCP/UDP differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

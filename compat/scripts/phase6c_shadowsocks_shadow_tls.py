#!/usr/bin/env python3
"""Go/Rust differential for Shadowsocks shadow-tls plugin TCP."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import tempfile
import textwrap
import time
from typing import Any

from phase1 import (
    EchoHandler,
    HalfCloseHandler,
    IO_DEADLINE,
    ROOT,
    cargo_target_path,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks_ciphers import LARGE_PAYLOAD, echo, half_close, wait_route


FAILURE_ARTIFACT = (
    ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-shadow-tls-diff.json"
)
TARGET_ENV = "PHASE6CSSSHADOWTLS_CARGO_TARGET"
TARGET_NAME = "phase6c-shadowsocks-shadow-tls"
HOST = "phase6c-shadow-tls.example"
PLUGIN_PASSWORD = "phase6c-shadow-tls-plugin-password"
CIPHER = "2022-blake3-aes-256-gcm"
KEY_256 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
VERSION = 3


def target_dir() -> pathlib.Path:
    return cargo_target_path(TARGET_ENV, TARGET_NAME)


def authority_binary() -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    return target_dir() / f"shadowtls-shadowsocks-authority{suffix}"


def build_authority() -> pathlib.Path:
    output = authority_binary()
    subprocess.run(
        [
            "go",
            "build",
            "-o",
            str(output),
            "./compat/helpers/shadowtls_shadowsocks_authority",
        ],
        cwd=ROOT,
        check=True,
        timeout=120,
    )
    return output


def config_text(plugin_options: str, client_fingerprint: str | None = None) -> str:
    fingerprint_line = (
        f"    client-fingerprint: {client_fingerprint}\n" if client_fingerprint else ""
    )
    return f"""mixed-port: 17890
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: {CIPHER}
    password: {KEY_256}
{fingerprint_line}    plugin: shadow-tls
    plugin-opts:
{plugin_options}
rules:
  - MATCH,local-ss
"""


def validate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    cases = (
        (
            "valid-v3",
            f"      host: {HOST}\n      password: {PLUGIN_PASSWORD}\n      version: 3\n      skip-cert-verify: true\n",
            None,
        ),
        (
            "valid-default-version",
            f"      host: {HOST}\n      password: {PLUGIN_PASSWORD}\n      skip-cert-verify: true\n",
            None,
        ),
        (
            "invalid-version",
            f"      host: {HOST}\n      password: {PLUGIN_PASSWORD}\n      version: 4\n",
            None,
        ),
        (
            "invalid-unknown-option",
            f"      host: {HOST}\n      password: {PLUGIN_PASSWORD}\n      version: 3\n      mode: tls\n",
            None,
        ),
        ("missing-plugin-opts", "", None),
        (
            "valid-v3-chrome-fingerprint",
            f"      host: {HOST}\n      password: {PLUGIN_PASSWORD}\n      version: 3\n      skip-cert-verify: true\n",
            "chrome",
        ),
    )
    observations = {}
    for label, plugin_options, client_fingerprint in cases:
        config = scratch / f"{label}.yaml"
        if plugin_options:
            config.write_text(config_text(plugin_options, client_fingerprint))
        else:
            config.write_text(
                f"""mixed-port: 17890
mode: rule
log-level: info
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: {CIPHER}
    password: {KEY_256}
    plugin: shadow-tls
rules:
  - MATCH,local-ss
"""
            )
        result = subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        observations[label] = result.returncode == 0
    return observations


def start_shadowtls_authority(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    port: int,
    version: int = VERSION,
    strict: str | None = None,
    client_ca: pathlib.Path | None = None,
) -> tuple[Any, Any, Any]:
    stdout = (scratch / "authority-stdout.log").open("wb")
    stderr = (scratch / "authority-stderr.log").open("wb")
    command = [
        str(binary),
        f"127.0.0.1:{port}",
        KEY_256,
        CIPHER,
        PLUGIN_PASSWORD,
        str(version),
    ]
    if strict is not None:
        command.append(strict)
    if client_ca is not None:
        command.append(str(client_ca))
    process = subprocess.Popen(
        command,
        cwd=scratch,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"shadow-tls authority exited with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return process, stdout, stderr
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("shadow-tls authority did not become ready")


def exercise_wire(
    binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path
) -> dict[str, bool]:
    return {
        **exercise_wire_variant(binary, authority, scratch, VERSION, None, "wire"),
        **exercise_wire_variant(
            binary, authority, scratch, VERSION, "0", "wire-tls12-camouflage"
        ),
        **exercise_wire_variant(binary, authority, scratch, 2, None, "wire-v2"),
        **exercise_wire_variant(binary, authority, scratch, 1, None, "wire-v1"),
        **exercise_wire_variant(
            binary,
            authority,
            scratch,
            2,
            None,
            "wire-v2-chrome-wsalpn",
            client_fingerprint="chrome",
            extra_plugin_opts="      alpn:\n        - http/1.1\n",
        ),
        **exercise_wire_variant(
            binary,
            authority,
            scratch,
            VERSION,
            None,
            "wire-v3-chrome",
            client_fingerprint="chrome",
        ),
    }


def generate_client_identity(scratch: pathlib.Path) -> tuple[str, str, pathlib.Path]:
    root_certificate = scratch / "client-root.pem"
    root_key = scratch / "client-root-key.pem"
    certificate = scratch / "client.pem"
    private_key = scratch / "client-key.pem"
    request = scratch / "client.csr"
    extensions = scratch / "client.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=clientAuth\n"
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=phase6c-shadowtls-client-root",
            "-days",
            "2",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(root_key),
            "-out",
            str(root_certificate),
        ],
        cwd=scratch,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=IO_DEADLINE,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=phase6c-shadowtls-client",
            "-keyout",
            str(private_key),
            "-out",
            str(request),
        ],
        cwd=scratch,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=IO_DEADLINE,
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(request),
            "-CA",
            str(root_certificate),
            "-CAkey",
            str(root_key),
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            str(extensions),
            "-out",
            str(certificate),
        ],
        cwd=scratch,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=IO_DEADLINE,
    )
    return certificate.read_text().strip(), private_key.read_text().strip(), root_certificate


def exercise_mtls(
    binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path
) -> dict[str, bool]:
    tcp_echo = start_server(EchoHandler)
    mixed_port = reserve_port()
    authority_port = reserve_port()
    variant_scratch = scratch / "wire-mtls"
    variant_scratch.mkdir(parents=True, exist_ok=True)
    certificate_pem, private_key_pem, client_ca = generate_client_identity(variant_scratch)
    authority_process, authority_stdout, authority_stderr = start_shadowtls_authority(
        authority, variant_scratch, authority_port, VERSION, None, client_ca
    )
    cert_yaml = textwrap.indent(certificate_pem, "          ")
    key_yaml = textwrap.indent(private_key_pem, "          ")
    config = variant_scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {CIPHER}
    password: {KEY_256}
    client-fingerprint: chrome
    plugin: shadow-tls
    plugin-opts:
      host: {HOST}
      password: {PLUGIN_PASSWORD}
      version: {VERSION}
      skip-cert-verify: true
      certificate: |-
{cert_yaml}
      private-key: |-
{key_yaml}
rules:
  - MATCH,local-ss
"""
    )
    process, stdout, stderr = launch(binary, config, variant_scratch)
    try:
        wait_ready(process, mixed_port)
        wait_route(process, mixed_port, tcp_echo.port)
        return {
            "wire-mtls:tcp-ipv4": echo(mixed_port, "127.0.0.1", tcp_echo.port, b"mtls"),
            "wire-mtls:process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        tcp_echo.close()


def exercise_wire_variant(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    version: int,
    strict: str | None,
    label: str,
    client_fingerprint: str | None = None,
    extra_plugin_opts: str = "",
) -> dict[str, bool]:
    tcp_echo = start_server(EchoHandler)
    half_close_server = start_server(HalfCloseHandler)
    mixed_port = reserve_port()
    authority_port = reserve_port()
    variant_scratch = scratch / label
    variant_scratch.mkdir(parents=True, exist_ok=True)
    authority_process, authority_stdout, authority_stderr = start_shadowtls_authority(
        authority, variant_scratch, authority_port, version, strict
    )
    config = variant_scratch / "config.yaml"
    fingerprint_line = (
        f"    client-fingerprint: {client_fingerprint}\n" if client_fingerprint else ""
    )
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {CIPHER}
    password: {KEY_256}
{fingerprint_line}    plugin: shadow-tls
    plugin-opts:
      host: {HOST}
      password: {PLUGIN_PASSWORD}
      version: {version}
      skip-cert-verify: true
{extra_plugin_opts}rules:
  - MATCH,local-ss
"""
    )
    process, stdout, stderr = launch(binary, config, variant_scratch)
    prefix = f"{label}:"
    try:
        wait_ready(process, mixed_port)
        wait_route(process, mixed_port, tcp_echo.port)
        try:
            half_close_result = half_close(mixed_port, half_close_server.port)
        except (EOFError, OSError):
            half_close_result = False
        return {
            f"{prefix}tcp-domain": echo(mixed_port, "localhost", tcp_echo.port, b"domain"),
            f"{prefix}tcp-ipv4-large": echo(
                mixed_port, "127.0.0.1", tcp_echo.port, LARGE_PAYLOAD
            ),
            f"{prefix}tcp-half-close": half_close_result,
            f"{prefix}process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        tcp_echo.close()
        half_close_server.close()


def exercise_hostile(
    binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path
) -> dict[str, bool]:
    """Wrong plugin password must fail the wire path for both runtimes."""
    tcp_echo = start_server(EchoHandler)
    mixed_port = reserve_port()
    authority_port = reserve_port()
    hostile = scratch / "hostile-wrong-password"
    hostile.mkdir(parents=True, exist_ok=True)
    authority_process, authority_stdout, authority_stderr = start_shadowtls_authority(
        authority, hostile, authority_port, VERSION, None
    )
    config = hostile / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {CIPHER}
    password: {KEY_256}
    plugin: shadow-tls
    plugin-opts:
      host: {HOST}
      password: wrong-plugin-password
      version: {VERSION}
      skip-cert-verify: true
rules:
  - MATCH,local-ss
"""
    )
    process, stdout, stderr = launch(binary, config, hostile)
    try:
        wait_ready(process, mixed_port)
        try:
            ok = echo(mixed_port, "127.0.0.1", tcp_echo.port, b"hostile")
        except (EOFError, OSError, TimeoutError):
            ok = False
        # Expect failure: wrong password must not successfully echo.
        return {
            "hostile:wrong-password-rejected": not ok,
            "hostile:process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        tcp_echo.close()


def exercise(
    binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    validation = scratch / "validation"
    validation.mkdir()
    wire = scratch / "wire"
    wire.mkdir()
    hostile = scratch / "hostile"
    hostile.mkdir()
    return {
        "config": validate(binary, validation),
        "wire": exercise_wire(binary, authority, wire),
        "hostile": exercise_hostile(binary, authority, hostile),
        "mtls": exercise_mtls(binary, authority, scratch / "mtls"),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-shadow-tls-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE6CSSSHADOWTLS_CARGO_TARGET",
            "phase6c-shadowsocks-shadow-tls",
        )
        authority = build_authority()
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
    print("Phase 6C-M6 Shadowsocks shadow-tls differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

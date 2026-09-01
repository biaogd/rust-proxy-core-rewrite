#!/usr/bin/env python3
"""Go/Rust differential for Phase 6D-A VMess AEAD over native TCP."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6d-vmess-tcp-diff.json"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
WRONG_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def build_authority(output: pathlib.Path) -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    binary = output / f"vmess-authority{suffix}"
    subprocess.run(
        [
            "go",
            "build",
            "-trimpath",
            "-o",
            str(binary),
            "./compat/helpers/vmess_authority",
        ],
        cwd=ROOT,
        check=True,
    )
    return binary


def start_authority(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    port: int,
    alter_id: int = 0,
    packet_mode: str = "reject",
    log_name: str = "authority",
    transport: str = "tcp",
    certificate: pathlib.Path | None = None,
    private_key: pathlib.Path | None = None,
    expected_ws_host: str = "",
    expected_ws_path: str = "",
    early_data_header: str = "",
    early_data_path_prefix: str = "",
    pre_response_bytes: int = 0,
    expected_http_method: str = "",
    expected_http_host: str = "",
    expected_http_path: str = "",
    expected_http_header: str = "",
) -> tuple[subprocess.Popen[bytes], Any, Any, pathlib.Path]:
    stdout_path = scratch / f"{log_name}-stdout.log"
    stdout = stdout_path.open("wb")
    stderr = (scratch / f"{log_name}-stderr.log").open("wb")
    command = [
        str(binary),
        "-listen",
        f"127.0.0.1:{port}",
        "-uuid",
        UUID,
        "-alter-id",
        str(alter_id),
        "-packet-mode",
        packet_mode,
        "-transport",
        transport,
        "-expected-ws-host",
        expected_ws_host,
        "-expected-ws-path",
        expected_ws_path,
        "-early-data-header",
        early_data_header,
        "-early-data-path-prefix",
        early_data_path_prefix,
        "-pre-response-bytes",
        str(pre_response_bytes),
        "-expected-http-method",
        expected_http_method,
        "-expected-http-host",
        expected_http_host,
        "-expected-http-path",
        expected_http_path,
        "-expected-http-header",
        expected_http_header,
    ]
    if certificate is not None and private_key is not None:
        command.extend(("-tls-cert", str(certificate), "-tls-key", str(private_key)))
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
            raise RuntimeError(f"VMess authority exited with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return process, stdout, stderr, stdout_path
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("VMess authority did not become ready")


def vmess_record(
    name: str,
    authority_port: int,
    uuid: str = UUID,
    extra: str = "",
    cipher: str = "auto",
    global_padding: bool = False,
    authenticated_length: bool = False,
    alter_id: int = 0,
) -> str:
    framing = ""
    if global_padding:
        framing += "    global-padding: true\n"
    if authenticated_length:
        framing += "    authenticated-length: true\n"
    return f"""  - name: {name}
    type: vmess
    server: 127.0.0.1
    port: {authority_port}
    uuid: {uuid}
    alterId: {alter_id}
    cipher: {cipher}
    network: tcp
{framing}{extra}"""


def exchange(
    mixed_port: int,
    host: str,
    port: int,
    payload: bytes,
    *,
    half_close: bool = False,
) -> bool:
    with connect_domain(mixed_port, host, port) as stream:
        stream.settimeout(IO_DEADLINE)
        stream.sendall(payload)
        if half_close:
            stream.shutdown(socket.SHUT_WR)
        return recv_exact(stream, len(payload)) == payload


def rejected_exchange(mixed_port: int, host: str, port: int) -> bool:
    try:
        with connect_domain(mixed_port, host, port) as stream:
            stream.settimeout(2)
            stream.sendall(b"wrong-uuid")
            return stream.recv(1) == b""
    except (AssertionError, BrokenPipeError, ConnectionResetError, EOFError, OSError):
        return True


def wait_vmess_route(process: subprocess.Popen[bytes], mixed_port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during VMess readiness with {process.returncode}")
        try:
            if exchange(mixed_port, "ready.phase6d", 443, b"ready"):
                return
        except (AssertionError, EOFError, OSError):
            pass
        time.sleep(0.02)
    raise TimeoutError("VMess route did not become ready")


def wait_authority_destinations(
    process: subprocess.Popen[bytes], stdout_path: pathlib.Path, expected: set[str]
) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    observed: set[str] = set()
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"VMess authority exited with {process.returncode}")
        observed = {
            line.removeprefix("CONNECT ").strip()
            for line in stdout_path.read_text(errors="replace").splitlines()
            if line.startswith("CONNECT ")
        }
        if expected <= observed:
            return sorted(expected)
        time.sleep(0.02)
    raise TimeoutError(
        f"VMess authority did not observe destinations: {sorted(expected - observed)}"
    )


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
    payload = json.loads(body)
    return {
        "name": payload["name"],
        "type": payload["type"],
        "udp": payload["udp"],
        "uot": payload["uot"],
        "xudp": payload["xudp"],
    }


def config_validation(binary: pathlib.Path, scratch: pathlib.Path, body: str) -> bool:
    config = scratch / f"validate-{len(list(scratch.glob('validate-*')))}.yaml"
    config.write_text(
        f"""mixed-port: 0
mode: rule
log-level: info
ipv6: false
{body}
rules:
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


def exercise(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    mixed_port, controller_port, authority_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    authority, authority_stdout, authority_stderr, authority_stdout_path = (
        start_authority(authority_binary, scratch, authority_port)
    )
    provider = scratch / ".config" / "mihomo" / "provider.yaml"
    provider.parent.mkdir(parents=True)
    provider.write_text(
        "proxies:\n" + vmess_record("provider-vmess", authority_port)
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
proxies:
{vmess_record("inline-vmess", authority_port)}
proxy-providers:
  local-vmess:
    type: file
    path: {provider}
proxy-groups:
  - name: vmess-select
    type: select
    proxies: [inline-vmess]
    use: [local-vmess]
    default-selected: inline-vmess
rules:
  - MATCH,vmess-select
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    wrong_process = None
    wrong_stdout = None
    wrong_stderr = None
    refused_process = None
    refused_stdout = None
    refused_stderr = None
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_vmess_route(process, mixed_port)
        domain_small = exchange(
            mixed_port, "phase6d.example", 443, b"vmess-native-tcp"
        )
        ipv4_large = exchange(
            mixed_port,
            "192.0.2.7",
            8443,
            bytes(range(256)) * 512,
        )
        half_close = exchange(
            mixed_port,
            "half-close.phase6d",
            9443,
            b"vmess-half-close",
            half_close=True,
        )
        selected = request(
            controller_port,
            "PUT",
            "/proxies/vmess-select",
            {"name": "provider-vmess"},
        )
        if selected[0] != 204:
            raise AssertionError(selected)
        provider_route = exchange(
            mixed_port, "provider.phase6d", 10443, b"provider-vmess"
        )

        wrong_port = reserve_port()
        wrong_scratch = scratch / "wrong"
        wrong_scratch.mkdir()
        wrong_config = wrong_scratch / "config.yaml"
        wrong_config.write_text(
            f"""mixed-port: {wrong_port}
mode: rule
log-level: info
ipv6: false
proxies:
{vmess_record("wrong-vmess", authority_port, WRONG_UUID)}
rules:
  - MATCH,wrong-vmess
"""
        )
        wrong_process, wrong_stdout, wrong_stderr = launch(
            binary, wrong_config, wrong_scratch
        )
        wait_ready(wrong_process, wrong_port)
        wrong_uuid_rejected = rejected_exchange(wrong_port, "wrong.phase6d", 443)
        survived_wrong_uuid = wrong_process.poll() is None

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
{vmess_record("refused-vmess", unavailable_authority_port)}
rules:
  - MATCH,refused-vmess
"""
        )
        refused_process, refused_stdout, refused_stderr = launch(
            binary, refused_config, refused_scratch
        )
        wait_ready(refused_process, refused_port)
        connection_refused = rejected_exchange(
            refused_port, "refused.phase6d", 443
        )
        survived_connection_refused = refused_process.poll() is None

        authority_destinations = wait_authority_destinations(
            authority,
            authority_stdout_path,
            {
                "phase6d.example:443",
                "192.0.2.7:8443",
                "half-close.phase6d:9443",
                "provider.phase6d:10443",
            },
        )

        invalid_cipher = config_validation(
            binary,
            scratch,
            "proxies:\n"
            + vmess_record(
                "invalid-vmess",
                authority_port,
                cipher="invalid",
            ),
        )
        missing_server = config_validation(
            binary,
            scratch,
            f"""proxies:
  - name: invalid-vmess
    type: vmess
    port: {authority_port}
    uuid: {UUID}
    alterId: 0
    cipher: auto
""",
        )
        return {
            "domain-small": domain_small,
            "ipv4-large": ipv4_large,
            "half-close": half_close,
            "provider-select": (selected[0], selected[1] == b""),
            "provider-route": provider_route,
            "controller-inline": proxy_snapshot(controller_port, "inline-vmess"),
            "controller-provider": proxy_snapshot(
                controller_port, "provider-vmess", "local-vmess"
            ),
            "wrong-uuid-rejected": wrong_uuid_rejected,
            "survived-wrong-uuid": survived_wrong_uuid,
            "connection-refused": connection_refused,
            "survived-connection-refused": survived_connection_refused,
            "authority-destinations": authority_destinations,
            "invalid-cipher-accepted": invalid_cipher,
            "missing-server-accepted": missing_server,
        }
    finally:
        if wrong_process is not None:
            stop(wrong_process)
        if refused_process is not None:
            stop(refused_process)
        stop(process)
        stop(authority)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        if wrong_stdout is not None:
            wrong_stdout.close()
        if wrong_stderr is not None:
            wrong_stderr.close()
        if refused_stdout is not None:
            refused_stdout.close()
        if refused_stderr is not None:
            refused_stderr.close()


def assert_rust_only_rejections(
    rust_binary: pathlib.Path, scratch: pathlib.Path, authority_port: int
) -> None:
    for extra in [
        "    alterId: -1\n",
        "    packet-encoding: unsupported\n",
    ]:
        accepted = config_validation(
            rust_binary,
            scratch,
            "proxies:\n"
            + vmess_record("outside-scope", authority_port, extra=extra),
        )
        if accepted:
            raise AssertionError(f"Rust accepted out-of-scope VMess field: {extra!r}")


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6d-vmess-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6DVMESS_CARGO_TARGET", "phase6d-vmess")
        authority = build_authority(root)
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, authority, scratch)
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
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(observations, indent=2, sort_keys=True)
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6D-A VMess AEAD native-TCP differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for Phase 6D-I VMess gRPC/Gun single streams."""

from __future__ import annotations

import json
import pathlib
import re
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase6d_vmess_tcp import build_authority, exchange, start_authority
from phase6d_vmess_websocket import LARGE_PAYLOAD, trusted_roots


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6d-vmess-grpc-diff.json"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
DEFAULT_USER_AGENT = "grpc-go/1.36.0"


def record(
    name: str,
    port: int,
    *,
    cipher: str,
    alter_id: int,
    tls: bool,
    options: str,
) -> str:
    tls_fields = ""
    if tls:
        tls_fields = "    tls: true\n    servername: dot.phase4.test\n"
    return f"""  - name: {name}
    type: vmess
    server: 127.0.0.1
    port: {port}
    uuid: {UUID}
    alterId: {alter_id}
    cipher: {cipher}
    network: grpc
{tls_fields}{options}"""


def wait_exchange(
    process: Any,
    mixed_port: int,
    host: str,
    port: int,
    payload: bytes,
) -> bool:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during VMess Gun readiness: {process.returncode}")
        try:
            if exchange(mixed_port, host, port, payload):
                return True
        except (AssertionError, EOFError, OSError):
            pass
        time.sleep(0.02)
    raise TimeoutError("VMess Gun route did not become ready")


def wait_observations(
    authorities: list[tuple[Any, pathlib.Path]], expected: set[str]
) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed: set[str] = set()
        for process, output in authorities:
            if process.poll() is not None:
                raise RuntimeError("VMess Gun authority exited")
            observed.update(
                line.strip()
                for line in output.read_text(errors="replace").splitlines()
                if line.startswith(("TLS ", "ALPN ", "GRPC ", "CONNECT "))
            )
        if expected <= observed:
            return sorted(
                re.sub(r"^(GRPC POST 127\.0\.0\.1:)\d+ ", r"\1<port> ", line)
                for line in observed
            )
        time.sleep(0.02)
    raise TimeoutError(f"missing VMess Gun observations: {sorted(expected - observed)}")


def exercise(
    binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    ports = [reserve_port() for _ in range(4)]
    specs = [
        ("default", False, 0, f"127.0.0.1:{ports[0]}", "/GunService/Tun", DEFAULT_USER_AGENT),
        ("named", False, 0, f"127.0.0.1:{ports[1]}", "/example/Tun", "phase6d-i/1.0"),
        ("tls-path", True, 1, "dot.phase4.test", "/custom/path", "phase6d-i-tls/1.0"),
        ("tls-named", True, 0, "dot.phase4.test", "/secure/Tun", DEFAULT_USER_AGENT),
    ]
    authorities: list[tuple[Any, pathlib.Path]] = []
    handles = []
    for port, spec in zip(ports, specs, strict=True):
        name, tls, alter_id, host, path, user_agent = spec
        process, stdout, stderr, output = start_authority(
            authority_binary,
            scratch,
            port,
            alter_id=alter_id,
            log_name=f"authority-{name}",
            transport="grpc",
            certificate=pathlib.Path(SERVER_CERTIFICATE) if tls else None,
            private_key=pathlib.Path(SERVER_KEY) if tls else None,
            expected_http_host=host,
            expected_http_path=path,
            expected_grpc_user_agent=user_agent,
        )
        authorities.append((process, output))
        handles.append((process, stdout, stderr))

    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        trusted_roots()
        + f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
{record("vmess-grpc-default", ports[0], cipher="auto", alter_id=0, tls=False, options="")}{record("vmess-grpc-named", ports[1], cipher="none", alter_id=0, tls=False, options="    grpc-opts:\n      grpc-service-name: example\n      grpc-user-agent: phase6d-i/1.0\n")}{record("vmess-grpc-tls-path", ports[2], cipher="aes-128-cfb", alter_id=1, tls=True, options="    grpc-opts:\n      grpc-service-name: /custom/path\n      grpc-user-agent: phase6d-i-tls/1.0\n      ping-interval: 0\n      max-connections: 0\n      min-streams: 0\n      max-streams: 0\n")}{record("vmess-grpc-tls-named", ports[3], cipher="chacha20-poly1305", alter_id=0, tls=True, options="    grpc-opts:\n      grpc-service-name: secure\n")}rules:
  - DST-PORT,28001,vmess-grpc-default
  - DST-PORT,28002,vmess-grpc-named
  - DST-PORT,28003,vmess-grpc-tls-path
  - DST-PORT,28004,vmess-grpc-tls-named
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        matrix = {
            "default": wait_exchange(
                process, mixed_port, "grpc-default.phase6d", 28001, b"grpc-default"
            ),
            "named-large": wait_exchange(
                process, mixed_port, "grpc-named.phase6d", 28002, LARGE_PAYLOAD
            ),
            "tls-custom-path": wait_exchange(
                process, mixed_port, "grpc-path.phase6d", 28003, b"grpc-tls-path"
            ),
            "tls-named-large": wait_exchange(
                process, mixed_port, "grpc-secure.phase6d", 28004, LARGE_PAYLOAD
            ),
        }
        expected = {
            f"GRPC POST 127.0.0.1:{ports[0]} /GunService/Tun application/grpc {DEFAULT_USER_AGENT}",
            f"GRPC POST 127.0.0.1:{ports[1]} /example/Tun application/grpc phase6d-i/1.0",
            "TLS dot.phase4.test",
            "ALPN h2",
            "GRPC POST dot.phase4.test /custom/path application/grpc phase6d-i-tls/1.0",
            f"GRPC POST dot.phase4.test /secure/Tun application/grpc {DEFAULT_USER_AGENT}",
            "CONNECT grpc-default.phase6d:28001",
            "CONNECT grpc-named.phase6d:28002",
            "CONNECT grpc-path.phase6d:28003",
            "CONNECT grpc-secure.phase6d:28004",
        }
        return {
            "matrix": matrix,
            "process-alive": process.poll() is None,
            "authority": wait_observations(authorities, expected),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        for authority, authority_stdout, authority_stderr in handles:
            stop(authority)
            authority_stdout.close()
            authority_stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6d-vmess-grpc-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6DIVMESS_CARGO_TARGET", "phase6d-i-vmess")
        authority = build_authority(root)
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
    print("Phase 6D-I VMess gRPC/Gun differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

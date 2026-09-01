#!/usr/bin/env python3
"""Go/Rust differential for Phase 6D-H VMess HTTP/1 and HTTP/2 transports."""

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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6d-vmess-http-diff.json"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


def record(
    name: str,
    port: int,
    *,
    network: str,
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
    network: {network}
{tls_fields}{options}"""


def wait_exchange(
    process: Any,
    mixed_port: int,
    host: str,
    port: int,
    payload: bytes,
    *,
    half_close: bool = False,
) -> bool:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during VMess HTTP readiness: {process.returncode}")
        try:
            if exchange(mixed_port, host, port, payload, half_close=half_close):
                return True
        except (AssertionError, EOFError, OSError):
            pass
        time.sleep(0.02)
    raise TimeoutError("VMess HTTP transport route did not become ready")


def half_close_rejected(mixed_port: int, host: str, port: int) -> bool:
    try:
        return not exchange(mixed_port, host, port, b"half-close", half_close=True)
    except (AssertionError, BrokenPipeError, ConnectionResetError, EOFError, OSError):
        return True


def wait_observations(
    authorities: list[tuple[Any, pathlib.Path]], expected_prefixes: set[str]
) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed: set[str] = set()
        for process, output in authorities:
            if process.poll() is not None:
                raise RuntimeError("VMess HTTP authority exited")
            observed.update(
                line.strip()
                for line in output.read_text(errors="replace").splitlines()
                if line.startswith(("TLS ", "ALPN ", "HTTP ", "H2 ", "CONNECT "))
            )
        if all(any(line.startswith(prefix) for line in observed) for prefix in expected_prefixes):
            return sorted(re.sub(r" BODY \d+$", " BODY <padding>", line) for line in observed)
        time.sleep(0.02)
    missing = {
        prefix
        for prefix in expected_prefixes
        if not any(line.startswith(prefix) for line in observed)
    }
    raise TimeoutError(f"missing VMess HTTP observations: {sorted(missing)}")


def exercise(
    binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    ports = [reserve_port() for _ in range(6)]
    specs = [
        ("http", "http", False, 1, "POST", "front-http.phase6d.test", "/plain-http", "X-Phase=6d-h"),
        ("https", "http", True, 0, "GET", "front-https.phase6d.test", "/secure-http", "X-Phase=6d-h-tls"),
        ("h2c", "h2", False, 0, "PUT", "front-h2c.phase6d.test", "/plain-h2", ""),
        ("h2", "h2", True, 1, "PUT", "front-h2.phase6d.test", "/secure-h2", ""),
        ("http-default", "http", False, 0, "GET", "127.0.0.1", "/", ""),
        ("h2-default", "h2", False, 0, "PUT", "www.example.com", "/", ""),
    ]
    authorities: list[tuple[Any, pathlib.Path]] = []
    handles = []
    for port, spec in zip(ports, specs, strict=True):
        name, transport, tls, alter_id, method, host, path, header = spec
        process, stdout, stderr, output = start_authority(
            authority_binary,
            scratch,
            port,
            alter_id=alter_id,
            log_name=f"authority-{name}",
            transport=transport,
            certificate=pathlib.Path(SERVER_CERTIFICATE) if tls else None,
            private_key=pathlib.Path(SERVER_KEY) if tls else None,
            expected_http_method=method,
            expected_http_host=host,
            expected_http_path=path,
            expected_http_header=header,
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
{record("vmess-http", ports[0], network="http", cipher="aes-128-cfb", alter_id=1, tls=False, options="    http-opts:\n      method: POST\n      path: [/plain-http]\n      headers:\n        Host: [front-http.phase6d.test]\n        X-Phase: [6d-h]\n")}{record("vmess-https", ports[1], network="http", cipher="aes-128-gcm", alter_id=0, tls=True, options="    http-opts:\n      method: GET\n      path: [/secure-http]\n      headers:\n        Host: [front-https.phase6d.test]\n        X-Phase: [6d-h-tls]\n")}{record("vmess-h2c", ports[2], network="h2", cipher="none", alter_id=0, tls=False, options="    h2-opts:\n      host: [front-h2c.phase6d.test]\n      path: /plain-h2\n")}{record("vmess-h2", ports[3], network="h2", cipher="chacha20-poly1305", alter_id=1, tls=True, options="    h2-opts:\n      host: [front-h2.phase6d.test]\n      path: /secure-h2\n")}{record("vmess-http-default", ports[4], network="http", cipher="auto", alter_id=0, tls=False, options="")}{record("vmess-h2-default", ports[5], network="h2", cipher="auto", alter_id=0, tls=False, options="")}rules:
  - DST-PORT,27001,vmess-http
  - DST-PORT,27002,vmess-https
  - DST-PORT,27003,vmess-h2c
  - DST-PORT,27004,vmess-h2
  - DST-PORT,27005,vmess-http-default
  - DST-PORT,27006,vmess-h2-default
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        matrix = {
            "http": wait_exchange(process, mixed_port, "http.phase6d", 27001, b"http-ready"),
            "https-large": wait_exchange(process, mixed_port, "https.phase6d", 27002, LARGE_PAYLOAD),
            "h2c-large": wait_exchange(process, mixed_port, "h2c.phase6d", 27003, LARGE_PAYLOAD),
            "h2": wait_exchange(process, mixed_port, "h2.phase6d", 27004, b"h2-ready"),
            "h2-half-close-rejected": half_close_rejected(
                mixed_port, "h2-half.phase6d", 27004
            ),
            "http-default": wait_exchange(
                process, mixed_port, "http-default.phase6d", 27005, b"http-default"
            ),
            "h2-default": wait_exchange(
                process, mixed_port, "h2-default.phase6d", 27006, b"h2-default"
            ),
        }
        expected_prefixes = {
            "TLS dot.phase4.test",
            "ALPN h2",
            "HTTP POST front-http.phase6d.test /plain-http X-Phase=6d-h BODY ",
            "HTTP GET front-https.phase6d.test /secure-http X-Phase=6d-h-tls BODY ",
            "H2 PUT front-h2c.phase6d.test /plain-h2 identity",
            "H2 PUT front-h2.phase6d.test /secure-h2 identity",
            "HTTP GET 127.0.0.1 /  BODY ",
            "H2 PUT www.example.com / identity",
            "CONNECT http.phase6d:27001",
            "CONNECT https.phase6d:27002",
            "CONNECT h2c.phase6d:27003",
            "CONNECT h2.phase6d:27004",
            "CONNECT http-default.phase6d:27005",
            "CONNECT h2-default.phase6d:27006",
        }
        return {
            "matrix": matrix,
            "process-alive": process.poll() is None,
            "authority": wait_observations(authorities, expected_prefixes),
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
    with tempfile.TemporaryDirectory(prefix="phase6d-vmess-http-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6DHVMESS_CARGO_TARGET", "phase6d-h-vmess")
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
    print("Phase 6D-H VMess HTTP/1 and HTTP/2 differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

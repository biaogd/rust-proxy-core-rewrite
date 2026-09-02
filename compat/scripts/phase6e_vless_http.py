#!/usr/bin/env python3
"""Go/Rust differential for Phase 6E-D VLESS HTTP/1 and HTTP/2 transports."""

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
from phase6d_vmess_websocket import LARGE_PAYLOAD, trusted_roots
from phase6e_vless_tcp import exchange, vless_record
from phase6e_vless_websocket import build_authority, start_authority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-http-diff.json"


def record(
    name: str,
    port: int,
    *,
    network: str,
    tls: bool,
    options: str,
) -> str:
    tls_fields = ""
    if tls:
        tls_fields = "    tls: true\n    servername: dot.phase4.test\n"
    return vless_record(
        name,
        port,
        network=network,
        extra=f"{tls_fields}{options}",
    )


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
            raise RuntimeError(f"proxy exited during VLESS HTTP readiness: {process.returncode}")
        try:
            if exchange(mixed_port, host, port, payload, half_close=half_close):
                return True
        except (AssertionError, EOFError, OSError):
            pass
        time.sleep(0.02)
    raise TimeoutError("VLESS HTTP transport route did not become ready")


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
                raise RuntimeError("VLESS HTTP authority exited")
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
    raise TimeoutError(f"missing VLESS HTTP observations: {sorted(missing)}")


def exercise(
    binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    ports = [reserve_port() for _ in range(6)]
    specs = [
        ("http", "http", False, "POST", "front-http.phase6e.test", "/plain-http", "X-Phase=6e-d"),
        ("https", "http", True, "GET", "front-https.phase6e.test", "/secure-http", "X-Phase=6e-d-tls"),
        ("h2c", "h2", False, "PUT", "front-h2c.phase6e.test", "/plain-h2", ""),
        ("h2", "h2", True, "PUT", "front-h2.phase6e.test", "/secure-h2", ""),
        ("http-default", "http", False, "GET", "127.0.0.1", "/", ""),
        ("h2-default", "h2", False, "PUT", "www.example.com", "/", ""),
    ]
    authorities: list[tuple[Any, pathlib.Path]] = []
    handles = []
    for port, spec in zip(ports, specs, strict=True):
        name, transport, tls, method, host, path, header = spec
        process, stdout, stderr, output = start_authority(
            authority_binary,
            scratch,
            port,
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
{record("vless-http", ports[0], network="http", tls=False, options="    http-opts:\n      method: POST\n      path: [/plain-http]\n      headers:\n        Host: [front-http.phase6e.test]\n        X-Phase: [6e-d]\n")}{record("vless-https", ports[1], network="http", tls=True, options="    http-opts:\n      method: GET\n      path: [/secure-http]\n      headers:\n        Host: [front-https.phase6e.test]\n        X-Phase: [6e-d-tls]\n")}{record("vless-h2c", ports[2], network="h2", tls=False, options="    h2-opts:\n      host: [front-h2c.phase6e.test]\n      path: /plain-h2\n")}{record("vless-h2", ports[3], network="h2", tls=True, options="    h2-opts:\n      host: [front-h2.phase6e.test]\n      path: /secure-h2\n")}{record("vless-http-default", ports[4], network="http", tls=False, options="")}{record("vless-h2-default", ports[5], network="h2", tls=False, options="")}rules:
  - DST-PORT,27201,vless-http
  - DST-PORT,27202,vless-https
  - DST-PORT,27203,vless-h2c
  - DST-PORT,27204,vless-h2
  - DST-PORT,27205,vless-http-default
  - DST-PORT,27206,vless-h2-default
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        matrix = {
            "http": wait_exchange(process, mixed_port, "http.phase6e", 27201, b"http-ready"),
            "https-large": wait_exchange(process, mixed_port, "https.phase6e", 27202, LARGE_PAYLOAD),
            "h2c-large": wait_exchange(process, mixed_port, "h2c.phase6e", 27203, LARGE_PAYLOAD),
            "h2": wait_exchange(process, mixed_port, "h2.phase6e", 27204, b"h2-ready"),
            "h2-half-close-rejected": half_close_rejected(
                mixed_port, "h2-half.phase6e", 27204
            ),
            "http-default": wait_exchange(
                process, mixed_port, "http-default.phase6e", 27205, b"http-default"
            ),
            "h2-default": wait_exchange(
                process, mixed_port, "h2-default.phase6e", 27206, b"h2-default"
            ),
        }
        expected_prefixes = {
            "TLS dot.phase4.test",
            "ALPN h2",
            "HTTP POST front-http.phase6e.test /plain-http X-Phase=6e-d BODY ",
            "HTTP GET front-https.phase6e.test /secure-http X-Phase=6e-d-tls BODY ",
            "H2 PUT front-h2c.phase6e.test /plain-h2 identity",
            "H2 PUT front-h2.phase6e.test /secure-h2 identity",
            "HTTP GET 127.0.0.1 /  BODY ",
            "H2 PUT www.example.com / identity",
            f"CONNECT http.phase6e:27201",
            f"CONNECT https.phase6e:27202",
            f"CONNECT h2c.phase6e:27203",
            f"CONNECT h2.phase6e:27204",
            f"CONNECT http-default.phase6e:27205",
            f"CONNECT h2-default.phase6e:27206",
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
    with tempfile.TemporaryDirectory(prefix="phase6e-vless-http-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6EVLESSHTTP_CARGO_TARGET", "phase6e-d-vless")
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
    print("Phase 6E-D VLESS HTTP/1 and HTTP/2 differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

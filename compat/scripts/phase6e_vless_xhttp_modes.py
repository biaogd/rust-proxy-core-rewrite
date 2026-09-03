#!/usr/bin/env python3
"""Go/Rust differential for VLESS xHTTP auto, stream-up, and packet-up."""

from __future__ import annotations

import json
import pathlib
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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-xhttp-modes-diff.json"


def record(name: str, port: int, mode: str | None, *, post_bytes: int = 1_000_000) -> str:
    mode_line = f"      mode: {mode}\n" if mode is not None else ""
    return vless_record(
        name,
        port,
        network="xhttp",
        extra=(
            "    tls: true\n"
            "    servername: dot.phase4.test\n"
            "    xhttp-opts:\n"
            f"{mode_line}"
            f"      host: {name}.phase6e\n"
            f"      path: /{name}\n"
            "      x-padding-bytes: '32'\n"
            f"      sc-max-each-post-bytes: '{post_bytes}'\n"
            "      headers:\n"
            "        X-Phase: 6e-xhttp-modes\n"
        ),
    )


def wait_exchange(process: Any, mixed_port: int, host: str, port: int, payload: bytes) -> bool:
    deadline = time.monotonic() + max(IO_DEADLINE, 15.0)
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during xHTTP mode readiness: {process.returncode}")
        try:
            if exchange(mixed_port, host, port, payload):
                return True
        except (AssertionError, EOFError, OSError) as error:
            last_error = error
        time.sleep(0.02)
    raise TimeoutError(f"VLESS xHTTP mode route did not become ready: {last_error}")


def wait_observations(
    authorities: list[tuple[Any, pathlib.Path]], expected: set[str]
) -> list[str]:
    deadline = time.monotonic() + max(IO_DEADLINE, 10.0)
    while time.monotonic() < deadline:
        observed: set[str] = set()
        for process, output in authorities:
            if process.poll() is not None:
                raise RuntimeError("VLESS xHTTP mode authority exited")
            observed.update(output.read_text(errors="replace").splitlines())
        if expected <= observed:
            return sorted(expected)
        time.sleep(0.02)
    raise TimeoutError(f"missing VLESS xHTTP mode observations: {sorted(expected - observed)}")


def exercise(
    binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    specs = [
        ("xhttp-stream-up", "stream-up", 1_000_000),
        ("xhttp-packet-up", "packet-up", 512),
        ("xhttp-auto", None, 512),
    ]
    ports = {name: reserve_port() for name, _, _ in specs}
    authorities: list[tuple[Any, pathlib.Path]] = []
    handles = []
    for name, _, _ in specs:
        process, stdout, stderr, output = start_authority(
            authority_binary,
            scratch,
            ports[name],
            log_name=f"authority-{name}",
            transport="xhttp",
            certificate=pathlib.Path(SERVER_CERTIFICATE),
            private_key=pathlib.Path(SERVER_KEY),
            expected_http_host=f"{name}.phase6e",
            expected_http_path=f"/{name}/",
            expected_http_header="X-Phase=6e-xhttp-modes",
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
{''.join(record(name, ports[name], mode, post_bytes=post_bytes) for name, mode, post_bytes in specs)}rules:
  - DST-PORT,29301,xhttp-stream-up
  - DST-PORT,29302,xhttp-packet-up
  - DST-PORT,29303,xhttp-auto
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        matrix = {
            "stream-up-large": wait_exchange(
                process, mixed_port, "stream-up.phase6e", 29301, LARGE_PAYLOAD
            ),
            "packet-up-chunked": wait_exchange(
                process, mixed_port, "packet-up.phase6e", 29302, b"P" * 4096
            ),
            "auto-selects-packet-up": wait_exchange(
                process, mixed_port, "auto.phase6e", 29303, b"A" * 2048
            ),
        }
        expected = {
            "TLS dot.phase4.test",
            "ALPN h2",
            "XHTTP GET xhttp-stream-up.phase6e /xhttp-stream-up/<session>",
            "XHTTP STREAM-UP xhttp-stream-up.phase6e /xhttp-stream-up/<session>",
            "XHTTP GET xhttp-packet-up.phase6e /xhttp-packet-up/<session>",
            "XHTTP GET xhttp-auto.phase6e /xhttp-auto/<session>",
            "CONNECT stream-up.phase6e:29301",
            "CONNECT packet-up.phase6e:29302",
            "CONNECT auto.phase6e:29303",
        }
        return {
            "matrix": matrix,
            "authority": wait_observations(authorities, expected),
            "process-alive": process.poll() is None,
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
    with tempfile.TemporaryDirectory(prefix="phase6e-vless-xhttp-modes-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6EVLESSXHTTPMODES_CARGO_TARGET", "phase6e-xhttp-modes")
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
    print("Phase 6E VLESS xHTTP common-mode differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for the common VLESS xHTTP stream-one carrier."""

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


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-xhttp-diff.json"


def record(name: str, port: int, *, no_grpc_header: bool) -> str:
    no_grpc = "      no-grpc-header: true\n" if no_grpc_header else ""
    return vless_record(
        name,
        port,
        network="xhttp",
        extra=(
            "    tls: true\n"
            "    servername: dot.phase4.test\n"
            "    xhttp-opts:\n"
            "      mode: stream-one\n"
            f"      host: {name}.phase6e\n"
            f"      path: /{name}\n"
            "      x-padding-bytes: '64'\n"
            f"{no_grpc}"
            "      headers:\n"
            "        User-Agent: phase6e-xhttp/1.0\n"
            "        X-Phase: 6e-xhttp\n"
        ),
    )


def wait_exchange(process: Any, mixed_port: int, host: str, port: int, payload: bytes) -> bool:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during xHTTP readiness: {process.returncode}")
        try:
            if exchange(mixed_port, host, port, payload):
                return True
        except (AssertionError, EOFError, OSError):
            pass
        time.sleep(0.02)
    raise TimeoutError("VLESS xHTTP route did not become ready")


def wait_observations(authorities: list[tuple[Any, pathlib.Path]], expected: set[str]) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed: set[str] = set()
        for process, output in authorities:
            if process.poll() is not None:
                raise RuntimeError("VLESS xHTTP authority exited")
            observed.update(
                line.strip()
                for line in output.read_text(errors="replace").splitlines()
                if line.startswith(("TLS ", "ALPN ", "XHTTP ", "CONNECT "))
            )
        if expected <= observed:
            return sorted(expected)
        time.sleep(0.02)
    raise TimeoutError(f"missing VLESS xHTTP observations: {sorted(expected - observed)}")


def exercise(binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    specs = [("xhttp-grpc", False), ("xhttp-plain", True)]
    ports = {name: reserve_port() for name, _ in specs}
    authorities: list[tuple[Any, pathlib.Path]] = []
    handles = []
    for name, _ in specs:
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
            expected_http_header="X-Phase=6e-xhttp",
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
{record("xhttp-grpc", ports["xhttp-grpc"], no_grpc_header=False)}{record("xhttp-plain", ports["xhttp-plain"], no_grpc_header=True)}rules:
  - DST-PORT,28501,xhttp-grpc
  - DST-PORT,28502,xhttp-plain
  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        matrix = {
            "grpc-header": wait_exchange(
                process, mixed_port, "xhttp-small.phase6e", 28501, b"xhttp-stream-one"
            ),
            "no-grpc-header-large": wait_exchange(
                process, mixed_port, "xhttp-large.phase6e", 28502, LARGE_PAYLOAD
            ),
        }
        expected = {
            "TLS dot.phase4.test",
            "ALPN h2",
            "XHTTP POST xhttp-grpc.phase6e /xhttp-grpc/ application/grpc PADDING 64 X-Phase=6e-xhttp",
            "XHTTP POST xhttp-plain.phase6e /xhttp-plain/  PADDING 64 X-Phase=6e-xhttp",
            "CONNECT xhttp-small.phase6e:28501",
            "CONNECT xhttp-large.phase6e:28502",
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
    with tempfile.TemporaryDirectory(prefix="phase6e-vless-xhttp-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6EVLESSXHTTP_CARGO_TARGET", "phase6e-k-vless")
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
    print("Phase 6E-K VLESS xHTTP stream-one differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

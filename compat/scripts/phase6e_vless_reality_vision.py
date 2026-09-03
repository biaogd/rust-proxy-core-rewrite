#!/usr/bin/env python3
"""Go/Rust differential for VLESS REALITY combined with XTLS Vision."""

from __future__ import annotations

import json
import pathlib
import ssl
import subprocess
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, connect_domain, debug_files
from phase6e_vless_reality import (
    REALITY_PUBLIC_KEY,
    REALITY_SERVER_NAME,
    REALITY_SHORT_ID,
    build_authority,
)
from phase6e_vless_tcp import LARGE_PAYLOAD, STANDARD_UUID, exchange


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-reality-vision-diff.json"
INNER_TLS_PORT = 26033


def record(authority_port: int) -> str:
    return f"""  - name: vless-reality-vision
    type: vless
    server: 127.0.0.1
    port: {authority_port}
    uuid: {STANDARD_UUID}
    encryption: none
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    servername: {REALITY_SERVER_NAME}
    reality-opts:
      public-key: {REALITY_PUBLIC_KEY}
      short-id: {REALITY_SHORT_ID}
"""


def nested_tls_exchange(mixed_port: int, payload: bytes) -> bool:
    context = ssl.create_default_context(cafile=str(ROOT_CERTIFICATE))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    raw = connect_domain(mixed_port, "reality-vision-inner.phase6e", INNER_TLS_PORT)
    raw.settimeout(IO_DEADLINE)
    with context.wrap_socket(raw, server_hostname="dot.phase4.test") as stream:
        stream.sendall(payload)
        return stream.recv(len(payload)) == payload


def wait_observations(output: pathlib.Path, expected: set[str]) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed = {
            line.strip()
            for line in output.read_text(errors="replace").splitlines()
            if line.startswith(("CONNECT ", "INNER_TLS "))
        }
        if expected <= observed:
            return sorted(expected)
        time.sleep(0.02)
    raise TimeoutError(f"missing REALITY+Vision observations: {sorted(expected - observed)}")


def exercise(binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority_port = reserve_port()
    authority_stdout_path = scratch / "authority-stdout.log"
    authority_stdout = authority_stdout_path.open("wb")
    authority_stderr = (scratch / "authority-stderr.log").open("wb")
    authority = subprocess.Popen(
        [
            str(authority_binary),
            "-listen",
            f"127.0.0.1:{authority_port}",
            "-uuid",
            STANDARD_UUID,
            "-flow",
            "xtls-rprx-vision",
            "-inner-tls-cert",
            str(SERVER_CERTIFICATE),
            "-inner-tls-key",
            str(SERVER_KEY),
            "-inner-tls-port",
            str(INNER_TLS_PORT),
        ],
        stdout=authority_stdout,
        stderr=authority_stderr,
        start_new_session=True,
    )
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if authority.poll() is not None:
            raise RuntimeError("REALITY+Vision authority exited early")
        if "READY " in authority_stdout_path.read_text(errors="replace"):
            break
        time.sleep(0.02)
    else:
        raise TimeoutError("REALITY+Vision authority did not become ready")

    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
{record(authority_port)}rules:
  - MATCH,vless-reality-vision
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        matrix = {
            "small": exchange(mixed_port, "reality-vision.phase6e", 26031, b"reality-vision"),
            "large": exchange(mixed_port, "reality-vision-large.phase6e", 26032, LARGE_PAYLOAD),
            "half-close": exchange(
                mixed_port,
                "reality-vision-half.phase6e",
                26031,
                b"reality-vision-half",
                half_close=True,
            ),
            "nested-tls-direct": nested_tls_exchange(mixed_port, b"reality-vision-direct"),
        }
        expected = {
            "CONNECT reality-vision.phase6e:26031",
            "CONNECT reality-vision-large.phase6e:26032",
            "CONNECT reality-vision-half.phase6e:26031",
            f"CONNECT reality-vision-inner.phase6e:{INNER_TLS_PORT}",
            "INNER_TLS dot.phase4.test 1301",
        }
        return {
            "matrix": matrix,
            "authority": wait_observations(authority_stdout_path, expected),
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop(authority)
        authority_stdout.close()
        authority_stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6e-vless-reality-vision-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6EVLESSREALITYVISION_CARGO_TARGET", "phase6e-j-vless")
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
    print("Phase 6E-J VLESS REALITY+Vision differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

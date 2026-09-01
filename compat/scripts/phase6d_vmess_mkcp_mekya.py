#!/usr/bin/env python3
"""Go/Rust differential for Phase 6D-K/L VMess mKCP and Mekya TCP."""

from __future__ import annotations

import json
import pathlib
import socket
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase6d_vmess_tcp import UUID, build_authority, exchange, start_authority
from phase6d_vmess_websocket import LARGE_PAYLOAD, trusted_roots


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6d-vmess-mkcp-mekya-diff.json"


def reserve_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def record(name: str, port: int, network: str, options: str, *, tls: bool = False) -> str:
    tls_fields = ""
    if tls:
        tls_fields = "    tls: true\n    servername: dot.phase4.test\n"
    return f"""  - name: {name}
    type: vmess
    server: 127.0.0.1
    port: {port}
    uuid: {UUID}
    alterId: 0
    cipher: auto
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
    deadline = time.monotonic() + max(IO_DEADLINE, 15)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during VMess transport readiness: {process.returncode}")
        try:
            if exchange(mixed_port, host, port, payload, half_close=half_close):
                return True
        except (AssertionError, EOFError, OSError):
            pass
        time.sleep(0.05)
    raise TimeoutError(f"VMess transport route {host}:{port} did not become ready")


def observations(paths: list[pathlib.Path], expected: set[str]) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        seen = {
            line.strip()
            for path in paths
            for line in path.read_text(errors="replace").splitlines()
            if line.startswith("CONNECT ")
        }
        if expected <= seen:
            return sorted(expected)
        time.sleep(0.02)
    raise TimeoutError(f"missing authority observations: {sorted(expected - seen)}")


def exercise(binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    mkcp_specs = [
        ("default", "", ""),
        ("seed", "phase6d-k-seed", ""),
        ("srtp", "", "srtp"),
        ("utp", "phase6d-k-utp", "utp"),
        ("wechat", "", "wechat-video"),
        ("dtls", "phase6d-k-dtls", "dtls"),
        ("wireguard", "", "wireguard"),
    ]
    authority_handles = []
    authority_logs: list[pathlib.Path] = []
    records = []
    rules = []
    expected = set()
    route_port = 28600
    for index, (name, seed, header) in enumerate(mkcp_specs):
        port = reserve_udp_port()
        handle = start_authority(
            authority,
            scratch,
            port,
            log_name=f"authority-mkcp-{name}",
            transport="mkcp",
            mkcp_seed=seed,
            mkcp_header=header,
        )
        authority_handles.append(handle[:3])
        authority_logs.append(handle[3])
        options = "    mkcp-opts:\n      tti: 15\n"
        if seed:
            options += f"      seed: {seed}\n"
        if header:
            options += f"      header: {header}\n"
        records.append(record(f"vmess-mkcp-{name}", port, "mkcp", options))
        target_port = route_port + index
        rules.append(f"  - DST-PORT,{target_port},vmess-mkcp-{name}\n")
        expected.add(f"CONNECT mkcp-{name}.phase6d:{target_port}")

    for index, alpn in enumerate(("h2", "http/1.1")):
        name = "h2" if alpn == "h2" else "h1"
        port = reserve_port()
        handle = start_authority(
            authority,
            scratch,
            port,
            log_name=f"authority-mekya-{name}",
            transport="mekya",
            certificate=pathlib.Path(SERVER_CERTIFICATE),
            private_key=pathlib.Path(SERVER_KEY),
            mkcp_seed=f"phase6d-l-{name}",
            mkcp_header="srtp" if name == "h2" else "",
            mekya_alpn=alpn,
        )
        authority_handles.append(handle[:3])
        authority_logs.append(handle[3])
        options = f"""    mekya-opts:
      url: https://127.0.0.1:{port}/mekya
      h2-pool-size: 2
      max-write-delay: 20
      max-request-size: 96000
      polling-interval-initial: 20
      max-write-size: 1048576
      max-write-duration-ms: 5000
      max-simultaneous-write-connection: 16
      packet-writing-buffer: 1024
      kcp:
        tti: 15
        seed: phase6d-l-{name}
"""
        if name == "h2":
            options += "        header: srtp\n"
        records.append(record(f"vmess-mekya-{name}", port, "mekya", options, tls=True))
        target_port = 28700 + index
        rules.append(f"  - DST-PORT,{target_port},vmess-mekya-{name}\n")
        expected.add(f"CONNECT mekya-{name}.phase6d:{target_port}")

    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        trusted_roots()
        + f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
{''.join(records)}rules:
{''.join(rules)}  - MATCH,REJECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        matrix: dict[str, bool] = {}
        for index, (name, _, _) in enumerate(mkcp_specs):
            payload = LARGE_PAYLOAD if name in {"seed", "dtls"} else f"mkcp-{name}".encode()
            matrix[f"mkcp-{name}"] = wait_exchange(
                process,
                mixed_port,
                f"mkcp-{name}.phase6d",
                route_port + index,
                payload,
            )
        matrix["mekya-h2"] = wait_exchange(
            process, mixed_port, "mekya-h2.phase6d", 28700, LARGE_PAYLOAD
        )
        matrix["mekya-h1"] = wait_exchange(
            process,
            mixed_port,
            "mekya-h1.phase6d",
            28701,
            b"mekya-http1",
        )
        return {
            "matrix": matrix,
            "authority": observations(authority_logs, expected),
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        for authority_process, authority_stdout, authority_stderr in authority_handles:
            stop(authority_process)
            authority_stdout.close()
            authority_stderr.close()


def main() -> int:
    result: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6d-vmess-mkcp-mekya-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6DKL_CARGO_TARGET", "phase6d-kl-vmess")
        authority = build_authority(root)
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                result[name] = exercise(binary, authority, scratch)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "error": f"{type(error).__name__}: {error}",
                        "observations": result,
                        "debug": debug_files(root),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            raise
    if result["go"] != result["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(result, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6D-K/L VMess mKCP and Mekya differential passed")
    print(json.dumps(result["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

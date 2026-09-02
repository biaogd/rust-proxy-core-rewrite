#!/usr/bin/env python3
"""Go/Rust differential for Phase 6D-G VMess WebSocket variants."""

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
from phase6d_vmess_tcp import build_authority, exchange, start_authority
from phase6d_vmess_websocket import LARGE_PAYLOAD, record, trusted_roots


FAILURE_ARTIFACT = (
    ROOT / "compat" / "artifacts" / "phase6d-vmess-websocket-variants-diff.json"
)


def ws_fields(
    path: str,
    host: str,
    *,
    max_early_data: int | None = None,
    early_header: str | None = None,
    raw_upgrade: bool = False,
    fast_open: bool = False,
) -> str:
    fields = f"    ws-opts:\n      path: {path}\n      headers:\n        Host: {host}\n"
    if max_early_data is not None:
        fields += f"      max-early-data: {max_early_data}\n"
    if early_header is not None:
        fields += f"      early-data-header-name: {early_header}\n"
    if raw_upgrade:
        fields += "      v2ray-http-upgrade: true\n"
    if fast_open:
        fields += "      v2ray-http-upgrade-fast-open: true\n"
    return fields


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
            raise RuntimeError(f"proxy exited during VMess variant readiness: {process.returncode}")
        try:
            if exchange(mixed_port, host, port, payload, half_close=half_close):
                return True
        except (AssertionError, EOFError, OSError):
            pass
        time.sleep(0.02)
    raise TimeoutError("VMess WebSocket variant route did not become ready")


def wait_observations(
    authorities: list[tuple[Any, pathlib.Path]], expected: set[str]
) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed: set[str] = set()
        for process, output in authorities:
            if process.poll() is not None:
                raise RuntimeError("VMess variant authority exited")
            observed.update(
                line.strip()
                for line in output.read_text(errors="replace").splitlines()
                if line.startswith(("TLS ", "WS ", "UPGRADE ", "EARLY ", "FASTOPEN ", "CONNECT "))
            )
        if expected <= observed:
            return sorted(expected)
        time.sleep(0.02)
    raise TimeoutError(f"missing VMess variant observations: {sorted(expected - observed)}")


def exercise(
    binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    ports = [reserve_port() for _ in range(6)]
    specs = [
        ("ws-header", "ws", False, 0, "header.phase6d.test", "/header", "X-Vmess-Early", "", 0),
        ("ws-path", "ws", True, 0, "dot.phase4.test", "/append?token=1", "", "/append", 0),
        ("ws-query", "ws", False, 1, "query.phase6d.test", "/query?a=1&z=2", "Sec-WebSocket-Protocol", "", 0),
        ("raw-early", "upgrade", True, 1, "dot.phase4.test", "/raw-early", "X-Raw-Early", "", 0),
        ("raw-fast", "upgrade", False, 0, "fast.phase6d.test", "/raw-fast", "", "", 16),
        ("raw-query", "upgrade", False, 0, "raw-query.phase6d.test", "/raw-query?a=1&z=2", "Sec-WebSocket-Protocol", "", 0),
    ]
    authorities: list[tuple[Any, pathlib.Path]] = []
    handles = []
    for port, spec in zip(ports, specs, strict=True):
        name, transport, tls, alter_id, host, path, early_header, path_prefix, pre_bytes = spec
        process, stdout, stderr, output = start_authority(
            authority_binary,
            scratch,
            port,
            alter_id=alter_id,
            log_name=f"authority-{name}",
            transport=transport,
            certificate=pathlib.Path(SERVER_CERTIFICATE) if tls else None,
            private_key=pathlib.Path(SERVER_KEY) if tls else None,
            expected_ws_host=host,
            expected_ws_path=path,
            early_data_header=early_header,
            early_data_path_prefix=path_prefix,
            pre_response_bytes=pre_bytes,
        )
        authorities.append((process, output))
        handles.append((process, stdout, stderr))

    records = [
        record(
            "ws-header",
            ports[0],
            network="ws",
            ws_fields=ws_fields(
                "/header", "header.phase6d.test", max_early_data=32, early_header="X-Vmess-Early"
            ),
        ),
        record(
            "ws-path",
            ports[1],
            network="ws",
            cipher="chacha20-poly1305",
            tls_fields="    tls: true\n",
            ws_fields=ws_fields(
                "/append?token=1", "dot.phase4.test", max_early_data=32
            ),
        ),
        record(
            "ws-query",
            ports[2],
            network="ws",
            alter_id=1,
            cipher="none",
            ws_fields=ws_fields(
                "/query?z=2&ed=32&a=1",
                "query.phase6d.test",
                max_early_data=1,
                early_header="X-Ignored-By-Ed",
            ),
        ),
        record(
            "raw-early",
            ports[3],
            network="ws",
            alter_id=1,
            cipher="aes-128-cfb",
            tls_fields="    tls: true\n",
            ws_fields=ws_fields(
                "/raw-early",
                "dot.phase4.test",
                max_early_data=32,
                early_header="X-Raw-Early",
                raw_upgrade=True,
            ),
        ),
        record(
            "raw-fast",
            ports[4],
            network="ws",
            ws_fields=ws_fields(
                "/raw-fast",
                "fast.phase6d.test",
                raw_upgrade=True,
                fast_open=True,
            ),
        ),
        record(
            "raw-query",
            ports[5],
            network="ws",
            cipher="aes-128-gcm",
            ws_fields=ws_fields(
                "/raw-query?z=2&ed=32&a=1",
                "raw-query.phase6d.test",
                raw_upgrade=True,
            ),
        ),
    ]
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    rules = "".join(
        f"  - DST-PORT,{26101 + index},{spec[0]}\n" for index, spec in enumerate(specs)
    )
    config.write_text(
        trusted_roots()
        + f"mixed-port: {mixed_port}\nmode: rule\nlog-level: info\nipv6: false\nproxies:\n"
        + "".join(records)
        + "rules:\n"
        + rules
        + "  - MATCH,REJECT\n"
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        matrix = {
            "ws-header": wait_exchange(process, mixed_port, "header-target.phase6d", 26101, b"header"),
            "ws-path-large": wait_exchange(
                process, mixed_port, "path-target.phase6d", 26102, LARGE_PAYLOAD
            ),
            "ws-query-legacy": wait_exchange(
                process, mixed_port, "query-target.phase6d", 26103, b"query"
            ),
            "raw-early-large": wait_exchange(
                process, mixed_port, "raw-early-target.phase6d", 26104, LARGE_PAYLOAD
            ),
            "raw-fast": wait_exchange(
                process, mixed_port, "raw-fast-target.phase6d", 26105, b"fast-open"
            ),
            "raw-query-half-close": wait_exchange(
                process,
                mixed_port,
                "raw-query-target.phase6d",
                26106,
                b"raw-query-half-close",
                half_close=True,
            ),
        }
        expected = {
            "WS header.phase6d.test /header",
            "EARLY X-Vmess-Early 32",
            "TLS dot.phase4.test",
            "WS dot.phase4.test /append?token=1",
            "EARLY PATH 32",
            "WS query.phase6d.test /query?a=1&z=2",
            "EARLY Sec-WebSocket-Protocol 32",
            "UPGRADE dot.phase4.test /raw-early",
            "EARLY X-Raw-Early 32",
            "UPGRADE fast.phase6d.test /raw-fast",
            "FASTOPEN 16",
            "UPGRADE raw-query.phase6d.test /raw-query?a=1&z=2",
            "CONNECT header-target.phase6d:26101",
            "CONNECT path-target.phase6d:26102",
            "CONNECT query-target.phase6d:26103",
            "CONNECT raw-early-target.phase6d:26104",
            "CONNECT raw-fast-target.phase6d:26105",
            "CONNECT raw-query-target.phase6d:26106",
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
    with tempfile.TemporaryDirectory(prefix="phase6d-vmess-websocket-variants-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6DGVMESS_CARGO_TARGET", "phase6d-g-vmess")
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
    print("Phase 6D-G VMess WebSocket variant differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

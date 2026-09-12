#!/usr/bin/env python3
"""Go/Rust differential for 7E-D Snell v2 ConnectV2 reuse pooling."""

from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import tempfile
import time
from typing import Any

from hy2_support import build_binaries
from phase1 import IO_DEADLINE, ROOT, cargo_target_path, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import debug_files
from phase5d_streams import SECRET, wait_controller
from phase7e_snell_tcp import (
    PSK,
    PSK_V3,
    authority_binary,
    config_validation,
    exchange,
    listen_echo,
    proxy_snapshot,
    snell_record,
    start_authority,
    wait_exchange,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase7e-snell-reuse-diff.json"


def accepted_count(scratch: pathlib.Path) -> int:
    path = scratch / "authority-stderr.log"
    if not path.exists():
        return 0
    return path.read_text(errors="replace").count("ACCEPTED")


def exercise(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    echo, echo_thread, echo_port = listen_echo()
    _ = echo_thread

    mixed_port, controller_port, v2_port, v3_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    v2_scratch = scratch / "authority-v2"
    v3_scratch = scratch / "authority-v3"
    v2_process, v2_stdout, v2_stderr = start_authority(
        authority, v2_scratch, v2_port, PSK, 2
    )
    v3_process, v3_stdout, v3_stderr = start_authority(
        authority, v3_scratch, v3_port, PSK_V3, 3
    )

    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
hosts:
  echo.snell.test: 127.0.0.1
proxies:
{snell_record("snell-v2", v2_port, PSK, version=2)}
{snell_record("snell-v2-flag", v2_port, PSK, version=2, extra="    reuse: true\n")}
{snell_record("snell-v3-reuse", v3_port, PSK_V3, version=3, extra="    reuse: true\n")}
rules:
  - DST-PORT,{echo_port},snell-v2
  - MATCH,snell-v3-reuse
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        time.sleep(0.3)

        first = wait_exchange(process, mixed_port, "echo.snell.test", echo_port, b"reuse-1")
        time.sleep(0.4)
        v2_after_warmup = accepted_count(v2_scratch)
        second = exchange(mixed_port, "127.0.0.1", echo_port, b"reuse-2")
        time.sleep(0.4)
        third = exchange(mixed_port, "127.0.0.1", echo_port, b"reuse-3")
        time.sleep(0.4)
        fourth = exchange(mixed_port, "127.0.0.1", echo_port, b"reuse-4")
        time.sleep(0.2)
        v2_accepted = accepted_count(v2_scratch)
        v2_reuse_delta = v2_accepted - v2_after_warmup

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [
                pool.submit(exchange, mixed_port, "127.0.0.1", echo_port, f"c{i}".encode())
                for i in range(4)
            ]
            concurrent_ok = all(future.result(timeout=IO_DEADLINE) for future in futures)

        echo_v3, echo_v3_thread, echo_v3_port = listen_echo()
        _ = echo_v3_thread
        try:
            v3_first = wait_exchange(
                process, mixed_port, "127.0.0.1", echo_v3_port, b"v3-reuse-1"
            )
            v3_second = exchange(mixed_port, "127.0.0.1", echo_v3_port, b"v3-reuse-2")
            v3_third = exchange(mixed_port, "127.0.0.1", echo_v3_port, b"v3-reuse-3")
        finally:
            echo_v3.shutdown()
            echo_v3.server_close()
        v3_accepted = accepted_count(v3_scratch)

        snapshot = proxy_snapshot(controller_port, "snell-v2")
        flag_snapshot = proxy_snapshot(controller_port, "snell-v2-flag")
        return {
            "v2-first": first,
            "v2-second": second,
            "v2-third": third,
            "v2-fourth": fourth,
            "v2-accepted": v2_accepted,
            "v2-reuse-delta": v2_reuse_delta,
            "concurrent-ok": concurrent_ok,
            "v3-first": v3_first,
            "v3-second": v3_second,
            "v3-third": v3_third,
            "v3-accepted": v3_accepted,
            "snapshot": {
                "name": snapshot["name"],
                "type": snapshot["type"],
                "udp": snapshot["udp"],
            },
            "flag-snapshot": {
                "name": flag_snapshot["name"],
                "type": flag_snapshot["type"],
            },
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop(v2_process)
        stop(v3_process)
        v2_stdout.close()
        v2_stderr.close()
        v3_stdout.close()
        v3_stderr.close()
        echo.shutdown()
        echo.server_close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-7ed-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE7ESNELL_CARGO_TARGET", "phase-7ea")
        authority = authority_binary()
        if not authority.exists():
            target = cargo_target_path("PHASE7ESNELL_CARGO_TARGET", "phase-7ea")
            profile = os.environ.get("HY2_BUILD_PROFILE", "debug")
            raise RuntimeError(
                f"rewrite-snell-authority was not built: {target / profile}"
            )
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], authority, scratch)
            observations["rust-reuse-accepted"] = config_validation(
                binaries["rust"],
                root / "rust-validate-reuse",
                "proxies:\n"
                "  - name: ok\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK}\n"
                "    reuse: true\n",
            )
            observations["rust-v4-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-v4",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK}\n"
                "    version: 4\n"
                "    reuse: true\n",
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

    go = observations["go"]
    rust = observations["rust"]
    rust_only = ["rust-reuse-accepted", "rust-v4-rejected"]
    pooled = (
        rust.get("v2-reuse-delta") == 0
        and go.get("v2-reuse-delta") == 0
        and rust.get("v3-accepted") == 3
        and go.get("v3-accepted") == 3
    )
    if go != rust or not all(observations.get(key) for key in rust_only) or not pooled:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {
                    "go": go,
                    "rust": rust,
                    **{key: observations.get(key) for key in rust_only},
                    "pooled": pooled,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("7E-D Snell v2 reuse differential passed")
    print(json.dumps(rust, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

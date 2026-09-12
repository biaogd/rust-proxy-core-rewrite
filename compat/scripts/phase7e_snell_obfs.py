#!/usr/bin/env python3
"""Go/Rust differential for 7E-C Snell simple-obfs HTTP/TLS outbound."""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
import time
from typing import Any

from hy2_support import build_binaries
from phase1 import ROOT, cargo_target_path, reserve_port, wait_ready
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
from phase7e_snell_udp import LARGE_UDP, listen_udp_echo, udp_exchange_retry


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase7e-snell-obfs-diff.json"


def exercise(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    echo, echo_thread, echo_port = listen_echo()
    udp_echo, udp_thread, udp_port = listen_udp_echo()
    _ = echo_thread, udp_thread

    mixed_port, controller_port, http_port, tls_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    http_process, http_stdout, http_stderr = start_authority(
        authority, scratch / "authority-http", http_port, PSK, 1, obfs="http"
    )
    tls_process, tls_stdout, tls_stderr = start_authority(
        authority, scratch / "authority-tls", tls_port, PSK_V3, 3, obfs="tls"
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
{snell_record("snell-http", http_port, PSK, extra="    obfs-opts:\n      mode: http\n      host: bing.com\n")}
{snell_record("snell-tls", tls_port, PSK_V3, version=3, extra="    udp: true\n    obfs-opts:\n      mode: tls\n")}
rules:
  - DST-PORT,{echo_port},snell-http
  - MATCH,snell-tls
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        time.sleep(0.3)

        http_small = wait_exchange(
            process, mixed_port, "echo.snell.test", echo_port, b"obfs-http"
        )
        http_second = exchange(mixed_port, "127.0.0.1", echo_port, b"obfs-http-2")
        # TLS proxy is MATCH for ports other than echo_port. Use a second echo.
        echo_tls, echo_tls_thread, echo_tls_port = listen_echo()
        _ = echo_tls_thread
        try:
            tls_small = wait_exchange(
                process, mixed_port, "127.0.0.1", echo_tls_port, b"obfs-tls"
            )
            tls_udp = udp_exchange_retry(
                mixed_port, "127.0.0.1", udp_port, b"obfs-udp"
            )
            tls_udp_large = udp_exchange_retry(
                mixed_port, "127.0.0.1", udp_port, LARGE_UDP
            )
        finally:
            echo_tls.shutdown()
            echo_tls.server_close()

        http_snapshot = proxy_snapshot(controller_port, "snell-http")
        tls_snapshot = proxy_snapshot(controller_port, "snell-tls")
        return {
            "http-small": http_small,
            "http-second": http_second,
            "tls-small": tls_small,
            "tls-udp": tls_udp,
            "tls-udp-large": tls_udp_large,
            "http-snapshot": {
                "name": http_snapshot["name"],
                "type": http_snapshot["type"],
                "udp": http_snapshot["udp"],
            },
            "tls-snapshot": {
                "name": tls_snapshot["name"],
                "type": tls_snapshot["type"],
                "udp": tls_snapshot["udp"],
            },
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop(http_process)
        stop(tls_process)
        http_stdout.close()
        http_stderr.close()
        tls_stdout.close()
        tls_stderr.close()
        echo.shutdown()
        echo.server_close()
        udp_echo.shutdown()
        udp_echo.server_close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-7ec-") as temporary:
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
            observations["rust-obfs-http-accepted"] = config_validation(
                binaries["rust"],
                root / "rust-validate-http",
                "proxies:\n"
                "  - name: ok\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK}\n"
                "    obfs-opts:\n"
                "      mode: http\n"
                "      host: bing.com\n",
            )
            observations["rust-obfs-tls-accepted"] = config_validation(
                binaries["rust"],
                root / "rust-validate-tls",
                "proxies:\n"
                "  - name: ok\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK}\n"
                "    obfs-opts:\n"
                "      mode: tls\n",
            )
            observations["rust-shadowtls-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-shadowtls",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK}\n"
                "    obfs-opts:\n"
                "      mode: shadow-tls\n",
            )
            observations["rust-reuse-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-reuse",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: snell\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                f"    psk: {PSK}\n"
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
    rust_only = [
        "rust-obfs-http-accepted",
        "rust-obfs-tls-accepted",
        "rust-shadowtls-rejected",
        "rust-reuse-rejected",
    ]
    if (
        go != rust
        or not all(observations.get(key) for key in rust_only)
        or rust.get("http-snapshot", {}).get("udp") is not False
        or rust.get("tls-snapshot", {}).get("udp") is not True
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {
                    "go": go,
                    "rust": rust,
                    **{key: observations.get(key) for key in rust_only},
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("7E-C Snell simple-obfs differential passed")
    print(json.dumps(rust, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

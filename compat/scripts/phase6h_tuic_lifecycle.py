#!/usr/bin/env python3
"""Go/Rust differential for 6H-C TUIC v5 outbound lifecycle.

Connection reuse, TUIC Heartbeat datagrams + QUIC keep-alive, congestion names,
max-open-streams pooling, cancel isolation, authority restart/reconnect,
provider/health/reload, concurrent TCP+UDP, and malformed-command unit coverage
via process survival. Soak is `phase6h_tuic_soak.py`.
"""

from __future__ import annotations

import json
import pathlib
import tempfile
import time
from typing import Any

from hy2_support import build_binaries
from phase1 import EchoHandler, IO_DEADLINE, ROOT, recv_exact, reload_via_controller, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import connect_domain, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_tcp import rejected_exchange
from phase6h_tuic_tcp import start_authority, tuic_record, wait_exchange
from phase6h_tuic_udp import (
    decode_socks_udp,
    socks_udp_associate,
    socks_udp_packet,
    start_udp_echo,
    udp_exchange_retry,
)
from phase_hy2c_hysteria2 import cancel_churn, concurrent_tcp


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6h-tuic-lifecycle-diff.json"
CONCURRENT = 8
CANCEL_ROUNDS = 16


def extra_lines(**fields: object) -> str:
    lines = []
    for key, value in fields.items():
        yaml_key = key.replace("_", "-")
        lines.append(f"    {yaml_key}: {value}")
    return ("\n".join(lines) + "\n") if lines else ""


def exchange_once(mixed_port: int, echo_port: int, payload: bytes) -> bool:
    with connect_domain(mixed_port, "127.0.0.1", echo_port) as stream:
        stream.settimeout(IO_DEADLINE)
        stream.sendall(payload)
        return recv_exact(stream, len(payload)) == payload


def write_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    controller_port: int,
    authority_port: int,
    pool_port: int,
    udp_port: int,
    include_removable: bool,
) -> None:
    removable = (
        tuic_record("removable-tuic", authority_port) if include_removable else ""
    )
    members = (
        "[tuic-cubic, tuic-newreno, tuic-bbr, removable-tuic]"
        if include_removable
        else "[tuic-cubic, tuic-newreno, tuic-bbr]"
    )
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: true
proxies:
{tuic_record("tuic-cubic", authority_port, extra=extra_lines(congestion_controller="cubic", heartbeat_interval=1000))}{tuic_record("tuic-newreno", authority_port, extra=extra_lines(congestion_controller="new_reno"))}{tuic_record("tuic-bbr", authority_port, extra=extra_lines(congestion_controller="bbr"))}{tuic_record("tuic-pool", authority_port, extra=extra_lines(max_open_streams=2))}{removable}proxy-groups:
  - name: tuic-select
    type: select
    proxies: {members}
    default-selected: tuic-cubic
rules:
  - DST-PORT,{pool_port},tuic-pool
  - DST-PORT,{udp_port},tuic-cubic
  - MATCH,tuic-select
"""
    )


def select_proxy(controller_port: int, name: str) -> None:
    status, body = request(
        controller_port, "PUT", "/proxies/tuic-select", {"name": name}
    )
    if status != 204:
        raise AssertionError((status, body))


def exercise(
    binary: pathlib.Path,
    authority_binary: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    pool_echo = start_server(EchoHandler)
    udp_echo, udp_port = start_udp_echo()
    mixed_port, controller_port, authority_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    authority_scratch = scratch / "authority"
    authority_scratch.mkdir()
    authority, a_out, a_err = start_authority(
        authority_binary, authority_scratch, authority_port
    )
    time.sleep(0.4)
    if authority.poll() is not None:
        raise RuntimeError("TUIC authority exited early")

    config = scratch / "config.yaml"
    write_config(
        config,
        mixed_port=mixed_port,
        controller_port=controller_port,
        authority_port=authority_port,
        pool_port=pool_echo.port,
        udp_port=udp_port,
        include_removable=True,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)

        cubic_ok = wait_exchange(
            process, mixed_port, "127.0.0.1", echo.port, b"cubic-ready"
        )
        time.sleep(2.5)
        after_heartbeat = exchange_once(mixed_port, echo.port, b"after-heartbeat")
        reuse_second = exchange_once(mixed_port, echo.port, b"reuse-second")
        concurrent_ok = concurrent_tcp(mixed_port, echo.port, CONCURRENT)
        pool_ok = concurrent_tcp(mixed_port, pool_echo.port, CONCURRENT)

        select_proxy(controller_port, "tuic-newreno")
        newreno_ok = wait_exchange(
            process, mixed_port, "127.0.0.1", echo.port, b"newreno"
        )
        select_proxy(controller_port, "tuic-bbr")
        bbr_ok = wait_exchange(process, mixed_port, "127.0.0.1", echo.port, b"bbr")
        select_proxy(controller_port, "tuic-cubic")

        udp_ok = udp_exchange_retry(mixed_port, "127.0.0.1", udp_port, b"lifecycle-udp")
        tcp_during_udp = False
        control, datagram, bind_port = socks_udp_associate(mixed_port)
        try:
            datagram.sendto(
                socks_udp_packet("127.0.0.1", udp_port, b"hold-udp"),
                ("127.0.0.1", bind_port),
            )
            tcp_during_udp = exchange_once(mixed_port, echo.port, b"with-udp-hold")
            response, _ = datagram.recvfrom(65_535)
            _, _, body = decode_socks_udp(response)
            tcp_udp_concurrent = tcp_during_udp and body == b"hold-udp"
        finally:
            datagram.close()
            control.close()

        cancel_ok = cancel_churn(mixed_port, echo.port, CANCEL_ROUNDS)
        after_cancel = exchange_once(mixed_port, echo.port, b"after-cancel")

        stop(authority)
        a_out.close()
        a_err.close()
        time.sleep(0.3)
        during_restart = rejected_exchange(mixed_port, "127.0.0.1", echo.port)
        authority_scratch2 = scratch / "authority-restart"
        authority_scratch2.mkdir()
        authority, a_out, a_err = start_authority(
            authority_binary, authority_scratch2, authority_port
        )
        time.sleep(0.5)
        reload_via_controller(process, controller_port, config, secret=SECRET)
        after_restart = wait_exchange(
            process, mixed_port, "127.0.0.1", echo.port, b"after-restart", deadline_secs=20.0
        )
        after_restart_udp = udp_exchange_retry(
            mixed_port, "127.0.0.1", udp_port, b"udp-after-restart"
        )

        write_config(
            config,
            mixed_port=mixed_port,
            controller_port=controller_port,
            authority_port=authority_port,
            pool_port=pool_echo.port,
            udp_port=udp_port,
            include_removable=False,
        )
        reload_via_controller(process, controller_port, config, secret=SECRET)
        after_reload = wait_exchange(
            process, mixed_port, "127.0.0.1", echo.port, b"after-reload", deadline_secs=15.0
        )

        return {
            "cubic": cubic_ok,
            "after-heartbeat": after_heartbeat,
            "reuse-second": reuse_second,
            "concurrent": concurrent_ok,
            "pool-max-open-streams": pool_ok,
            "newreno": newreno_ok,
            "bbr": bbr_ok,
            "udp": udp_ok,
            "tcp-udp-concurrent": tcp_udp_concurrent,
            "cancel-churn": cancel_ok,
            "after-cancel": after_cancel,
            "during-restart-rejected": during_restart,
            "after-restart": after_restart,
            "after-restart-udp": after_restart_udp,
            "after-reload": after_reload,
            "alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop(authority)
        a_out.close()
        a_err.close()
        echo.close()
        pool_echo.close()
        udp_echo.shutdown()
        udp_echo.server_close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-6hc-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6HTUIC_CARGO_TARGET", "phase-6hc")
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(
                    binaries[name], binaries["go"], scratch
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
    required = (
        "cubic",
        "after-heartbeat",
        "reuse-second",
        "concurrent",
        "pool-max-open-streams",
        "newreno",
        "bbr",
        "udp",
        "tcp-udp-concurrent",
        "cancel-churn",
        "after-cancel",
        "during-restart-rejected",
        "after-restart",
        "after-restart-udp",
        "after-reload",
        "alive",
    )
    if go != rust or not all(rust.get(key) for key in required):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps({"go": go, "rust": rust}, indent=2, sort_keys=True)
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("6H-C TUIC v5 lifecycle differential passed")
    print(json.dumps(rust, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

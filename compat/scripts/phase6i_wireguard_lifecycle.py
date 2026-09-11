#!/usr/bin/env python3
"""Go/Rust differential for 6I-C WireGuard outbound lifecycle.

Keepalive idle, concurrent TCP+UDP, cancel isolation, authority restart
(reload required for Go session recovery), and YAML acceptance of
`persistent-keepalive` / `refresh-server-ip-interval`. Native Parity is not
claimed.
"""

from __future__ import annotations

import concurrent.futures
import json
import pathlib
import tempfile
import time
from typing import Any

from hy2_support import build_binaries
from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    recv_exact,
    reload_via_controller,
    reserve_port,
    wait_ready,
)
from phase3 import launch, stop
from phase5b1a import connect_domain, debug_files
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_tcp import rejected_exchange
from phase6h_tuic_udp import decode_socks_udp, socks_udp_associate, socks_udp_packet
from phase6i_wireguard_tcp import (
    authority_binary,
    config_validation,
    generate_keypair,
    listen_ipv4,
    reachable_ipv4,
    start_authority,
    wait_exchange,
    wg_record,
)
from phase6i_wireguard_udp import listen_udp_echo, udp_exchange_retry


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6i-wireguard-lifecycle-diff.json"
CONCURRENT = 4
CANCEL_ROUNDS = 8


def extra_lines(**fields: object) -> str:
    lines = ["    udp: true"]
    for key, value in fields.items():
        yaml_key = key.replace("_", "-")
        lines.append(f"    {yaml_key}: {value}")
    return "\n".join(lines) + "\n"


def exchange_once(mixed_port: int, host: str, echo_port: int, payload: bytes) -> bool:
    with connect_domain(mixed_port, host, echo_port) as stream:
        stream.settimeout(IO_DEADLINE)
        stream.sendall(payload)
        return recv_exact(stream, len(payload)) == payload


def cancel_churn(mixed_port: int, host: str, echo_port: int, rounds: int) -> bool:
    for index in range(rounds):
        try:
            stream = connect_domain(mixed_port, host, echo_port)
            stream.settimeout(IO_DEADLINE)
            try:
                if index % 2 == 0:
                    stream.close()
                    continue
                payload = f"keep-{index}".encode()
                stream.sendall(payload)
                if recv_exact(stream, len(payload)) != payload:
                    return False
            finally:
                try:
                    stream.close()
                except OSError:
                    pass
        except (OSError, TimeoutError, AssertionError, EOFError):
            return False
    return True


def concurrent_tcp(mixed_port: int, host: str, echo_port: int, count: int) -> bool:
    def one(index: int) -> bool:
        payload = (f"wg-c-{index}-".encode() * 32)[:512]
        try:
            with connect_domain(mixed_port, host, echo_port) as stream:
                stream.settimeout(IO_DEADLINE)
                stream.sendall(payload)
                return recv_exact(stream, len(payload)) == payload
        except (OSError, TimeoutError, AssertionError, EOFError):
            return False

    def burst() -> bool:
        if not one(-1):
            return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
            futures = [pool.submit(one, index) for index in range(count)]
            try:
                results = [future.result(timeout=max(IO_DEADLINE, 20.0)) for future in futures]
            except (OSError, TimeoutError, AssertionError, EOFError):
                return False
            return sum(1 for ok in results if ok) >= max(1, (count * 3) // 4)

    return burst() or burst()


def write_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    controller_port: int,
    authority_port: int,
    private_key: str,
    public_key: str,
    inner_host: str,
    udp_port: int,
) -> None:
    extra = extra_lines(persistent_keepalive=1, refresh_server_ip_interval=60)
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
hosts:
  echo.wg.test: {inner_host}
proxies:
{wg_record("inline-wg", authority_port, private_key, public_key, extra=extra)}
rules:
  - DST-PORT,{udp_port},inline-wg
  - MATCH,inline-wg
"""
    )


def exercise(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    client_private: str,
    client_public: str,
    server_private: str,
    server_public: str,
) -> dict[str, Any]:
    inner_host = reachable_ipv4()
    echo, echo_thread, echo_port = listen_ipv4(EchoHandler)
    udp_echo, udp_thread, udp_port = listen_udp_echo()
    _ = echo_thread, udp_thread

    mixed_port, controller_port, authority_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    authority_scratch = scratch / "authority"
    wg_process, authority_stdout, authority_stderr = start_authority(
        authority,
        authority_scratch,
        authority_port,
        server_private,
        client_public,
    )

    config = scratch / "config.yaml"
    write_config(
        config,
        mixed_port=mixed_port,
        controller_port=controller_port,
        authority_port=authority_port,
        private_key=client_private,
        public_key=server_public,
        inner_host=inner_host,
        udp_port=udp_port,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        time.sleep(0.3)

        ready = wait_exchange(
            process, mixed_port, inner_host, echo_port, b"wg-ready"
        )
        time.sleep(2.5)
        after_keepalive = exchange_once(
            mixed_port, inner_host, echo_port, b"after-keepalive"
        )
        reuse_second = exchange_once(mixed_port, inner_host, echo_port, b"reuse-second")
        concurrent_ok = concurrent_tcp(mixed_port, inner_host, echo_port, CONCURRENT)

        udp_ok = udp_exchange_retry(mixed_port, inner_host, udp_port, b"lifecycle-udp")
        tcp_udp_concurrent = False
        control, datagram, bind_port = socks_udp_associate(mixed_port)
        try:
            datagram.sendto(
                socks_udp_packet(inner_host, udp_port, b"hold-udp"),
                ("127.0.0.1", bind_port),
            )
            tcp_during_udp = exchange_once(
                mixed_port, inner_host, echo_port, b"with-udp-hold"
            )
            response, _ = datagram.recvfrom(65_535)
            _, _, body = decode_socks_udp(response)
            tcp_udp_concurrent = tcp_during_udp and body == b"hold-udp"
        finally:
            datagram.close()
            control.close()

        cancel_ok = cancel_churn(mixed_port, inner_host, echo_port, CANCEL_ROUNDS)
        after_cancel = exchange_once(mixed_port, inner_host, echo_port, b"after-cancel")

        stop(wg_process)
        authority_stdout.close()
        authority_stderr.close()
        time.sleep(0.3)
        during_restart = rejected_exchange(mixed_port, inner_host, echo_port)
        authority_scratch2 = scratch / "authority-restart"
        wg_process, authority_stdout, authority_stderr = start_authority(
            authority,
            authority_scratch2,
            authority_port,
            server_private,
            client_public,
        )
        time.sleep(0.5)
        reload_via_controller(process, controller_port, config, secret=SECRET)
        after_restart = wait_exchange(
            process,
            mixed_port,
            inner_host,
            echo_port,
            b"after-restart",
            deadline_secs=20.0,
        )
        after_restart_udp = udp_exchange_retry(
            mixed_port, inner_host, udp_port, b"udp-after-restart"
        )
        after_reload = wait_exchange(
            process, mixed_port, "echo.wg.test", echo_port, b"after-reload"
        )

        return {
            "ready": ready,
            "after-keepalive": after_keepalive,
            "reuse-second": reuse_second,
            "concurrent": concurrent_ok,
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
        stop(wg_process)
        authority_stdout.close()
        authority_stderr.close()
        echo.shutdown()
        echo.server_close()
        udp_echo.shutdown()
        udp_echo.server_close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-6ic-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6IWG_CARGO_TARGET", "phase-6ia")
        authority = authority_binary()
        if not authority.exists():
            raise RuntimeError(f"rewrite-wireguard-authority was not built: {authority}")
        key_scratch = root / "keys"
        key_scratch.mkdir()
        client_private, client_public = generate_keypair(binaries["rust"], key_scratch)
        server_private, server_public = generate_keypair(binaries["rust"], key_scratch)
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(
                    binaries[name],
                    authority,
                    scratch,
                    client_private,
                    client_public,
                    server_private,
                    server_public,
                )
            observations["rust-keepalive-accepted"] = config_validation(
                binaries["rust"],
                root / "rust-validate-keepalive",
                "proxies:\n"
                "  - name: keep\n"
                "    type: wireguard\n"
                "    server: 127.0.0.1\n"
                "    port: 51820\n"
                f"    private-key: {client_private}\n"
                f"    public-key: {server_public}\n"
                "    ip: 10.0.0.2\n"
                "    persistent-keepalive: 25\n",
            )
            observations["rust-refresh-accepted"] = config_validation(
                binaries["rust"],
                root / "rust-validate-refresh",
                "proxies:\n"
                "  - name: refresh\n"
                "    type: wireguard\n"
                "    server: 127.0.0.1\n"
                "    port: 51820\n"
                f"    private-key: {client_private}\n"
                f"    public-key: {server_public}\n"
                "    ip: 10.0.0.2\n"
                "    refresh-server-ip-interval: 60\n",
            )
            observations["rust-amnezia-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-amnezia",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: wireguard\n"
                "    server: 127.0.0.1\n"
                "    port: 51820\n"
                f"    private-key: {client_private}\n"
                f"    public-key: {server_public}\n"
                "    ip: 10.0.0.2\n"
                "    amnezia-wg-option:\n"
                "      jc: 4\n",
            )
            observations["rust-peers-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-peers",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: wireguard\n"
                "    server: 127.0.0.1\n"
                "    port: 51820\n"
                f"    private-key: {client_private}\n"
                f"    public-key: {server_public}\n"
                "    ip: 10.0.0.2\n"
                "    peers:\n"
                "      - server: 127.0.0.1\n"
                "        port: 51820\n"
                f"        public-key: {server_public}\n"
                "        allowed-ips: [0.0.0.0/0]\n",
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
        "ready",
        "after-keepalive",
        "reuse-second",
        "concurrent",
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
    if (
        go != rust
        or not all(rust.get(key) for key in required)
        or not observations.get("rust-keepalive-accepted", False)
        or not observations.get("rust-refresh-accepted", False)
        or not observations.get("rust-amnezia-rejected", False)
        or not observations.get("rust-peers-rejected", False)
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {
                    "go": go,
                    "rust": rust,
                    "rust-keepalive-accepted": observations.get("rust-keepalive-accepted"),
                    "rust-refresh-accepted": observations.get("rust-refresh-accepted"),
                    "rust-amnezia-rejected": observations.get("rust-amnezia-rejected"),
                    "rust-peers-rejected": observations.get("rust-peers-rejected"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("6I-C WireGuard lifecycle differential passed")
    print(json.dumps(rust, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

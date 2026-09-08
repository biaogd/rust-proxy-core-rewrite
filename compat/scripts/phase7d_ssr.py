#!/usr/bin/env python3
"""SSR-D production hardening: negatives, concurrency/stress, reload-under-load.

Go/Rust differential against the pinned shadowsocksrr server (phase7a shims).
Soak lives in phase7d_ssr_soak.py (short CI default; long opt-in via env).
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import (
    EchoHandler,
    IO_DEADLINE,
    ROOT,
    assert_go_oracle_baseline,
    recv_exact,
    reload_via_controller,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import (
    UdpEchoHandler,
    decode_socks_udp,
    launch,
    socks_udp_packet,
    stop,
    wait_udp_route,
)
from phase5b1a import build_binaries, connect_domain, debug_files
from phase6c_shadowsocks_ciphers import echo
from phase6e_vless_tcp import rejected_exchange
from phase7a_ssr_tcp import PASSWORD, SSR_SERVER_PIN, cancel_exchange, ensure_ssr_server
from phase7c_ssr import start_ssr_server_cipher


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase7d-ssr-diff.json"
SECRET = "phase7d-ssr-secret"
CIPHER = "aes-128-cfb"
PROTOCOL = "auth_aes128_md5"
OBFS = "plain"
CONCURRENT_TCP = 8
CANCEL_ROUNDS = 16
STRESS_PAYLOAD = (b"ssr-d-" * 64)[:512]


def process_rss_kib(pid: int) -> int | None:
    try:
        import psutil

        return psutil.Process(pid).memory_info().rss // 1024
    except Exception:
        if os.name == "posix":
            try:
                for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1])
            except (OSError, ValueError):
                return None
        return None


def process_fd_count(pid: int) -> int | None:
    try:
        import psutil

        process = psutil.Process(pid)
        return process.num_handles() if os.name == "nt" else process.num_fds()
    except Exception:
        if os.name == "posix":
            try:
                return len(os.listdir(f"/proc/{pid}/fd"))
            except OSError:
                return None
        return None


def soft_resource_ok(pid: int) -> dict[str, Any]:
    rss = process_rss_kib(pid)
    fds = process_fd_count(pid)
    # Soft ceiling only — absolute values differ by engine; both must be measurable
    # and under an absurdly high bound so a leak runaway fails loudly.
    return {
        "rss-sampled": rss is not None,
        "fd-sampled": fds is not None,
        "rss-bounded": rss is not None and rss < 2_000_000,
        "fd-bounded": fds is not None and fds < (512 if os.name == "nt" else 256),
    }


def write_stress_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    socks_port: int,
    controller_port: int,
    ssr_port: int,
    wrong_rule_port: int,
    wrong_password: str = "wrong-ssr-password",
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
socks-port: {socks_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: warning
ipv6: false
proxies:
  - name: local-ssr
    type: ssr
    server: 127.0.0.1
    port: {ssr_port}
    password: {PASSWORD}
    cipher: {CIPHER}
    protocol: {PROTOCOL}
    obfs: {OBFS}
    udp: true
  - name: ssr-wrong-password
    type: ssr
    server: 127.0.0.1
    port: {ssr_port}
    password: {wrong_password}
    cipher: {CIPHER}
    protocol: {PROTOCOL}
    obfs: {OBFS}
    udp: true
  - name: ssr-wrong-cipher
    type: ssr
    server: 127.0.0.1
    port: {ssr_port}
    password: {PASSWORD}
    cipher: aes-256-cfb
    protocol: {PROTOCOL}
    obfs: {OBFS}
proxy-groups:
  - name: ssr-select
    type: select
    proxies: [local-ssr]
    default-selected: local-ssr
rules:
  - DST-PORT,{wrong_rule_port},ssr-wrong-password
  - MATCH,ssr-select
""",
        encoding="utf-8",
    )


def concurrent_tcp(mixed_port: int, echo_port: int, count: int) -> bool:
    def one(index: int) -> bool:
        payload = STRESS_PAYLOAD + index.to_bytes(2, "big")
        try:
            with connect_domain(mixed_port, "127.0.0.1", echo_port) as stream:
                stream.settimeout(IO_DEADLINE)
                stream.sendall(payload)
                return recv_exact(stream, len(payload)) == payload
        except (OSError, TimeoutError, AssertionError, EOFError):
            return False

    def burst() -> bool:
        if not one(0xFFFF):
            return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
            futures = [pool.submit(one, index) for index in range(count)]
            try:
                results = [
                    future.result(timeout=max(IO_DEADLINE, 20.0)) for future in futures
                ]
            except (OSError, TimeoutError, AssertionError, EOFError):
                return False
            return sum(1 for ok in results if ok) >= max(1, (count * 3) // 4)

    return burst() or burst()


def cancel_churn(mixed_port: int, echo_port: int, rounds: int) -> bool:
    for index in range(rounds):
        try:
            stream = connect_domain(mixed_port, "127.0.0.1", echo_port)
            stream.settimeout(IO_DEADLINE)
            try:
                if index % 2 == 0:
                    stream.close()
                    continue
                marker = f"keep-{index}".encode()
                stream.sendall(marker)
                if recv_exact(stream, len(marker)) != marker:
                    return False
            finally:
                try:
                    stream.close()
                except OSError:
                    pass
        except (OSError, TimeoutError, AssertionError, EOFError):
            return False
    return True


def udp_once(mixed_port: int, echo_port: int, payload: bytes) -> bool:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(IO_DEADLINE)
    try:
        client.sendto(socks_udp_packet(echo_port, payload), ("127.0.0.1", mixed_port))
        packet, _ = client.recvfrom(65_535)
        address, _, got = decode_socks_udp(packet)
        return address == "127.0.0.1" and got == payload
    except (OSError, AssertionError, TimeoutError):
        return False
    finally:
        client.close()


def tcp_udp_concurrent(mixed_port: int, tcp_port: int, udp_port: int) -> bool:
    barrier = threading.Barrier(2)
    results = {"tcp": False, "udp": False}

    def tcp_worker() -> None:
        barrier.wait(timeout=IO_DEADLINE)
        results["tcp"] = echo(mixed_port, "127.0.0.1", tcp_port, b"ssr-d-tcp-hold")

    def udp_worker() -> None:
        barrier.wait(timeout=IO_DEADLINE)
        results["udp"] = udp_once(mixed_port, udp_port, b"ssr-d-udp-hold")

    threads = [
        threading.Thread(target=tcp_worker, daemon=True),
        threading.Thread(target=udp_worker, daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=max(IO_DEADLINE, 20.0))
    return results["tcp"] and results["udp"]


def reload_under_load(
    process: Any,
    mixed_port: int,
    controller_port: int,
    config: pathlib.Path,
    echo_port: int,
) -> bool:
    stop_flag = threading.Event()
    errors: list[str] = []

    def traffic() -> None:
        while not stop_flag.is_set():
            try:
                if not echo(mixed_port, "127.0.0.1", echo_port, b"reload-load"):
                    errors.append("echo-false")
            except (OSError, EOFError, TimeoutError, AssertionError) as error:
                errors.append(type(error).__name__)
            time.sleep(0.02)

    worker = threading.Thread(target=traffic, daemon=True)
    worker.start()
    time.sleep(0.15)
    try:
        reload_via_controller(process, controller_port, config, secret=SECRET)
    except (OSError, TimeoutError, RuntimeError, AssertionError) as error:
        stop_flag.set()
        worker.join(timeout=2)
        return False
    time.sleep(0.2)
    stop_flag.set()
    worker.join(timeout=2)
    # Some mid-reload resets are acceptable; require recovery afterward.
    try:
        recovered = echo(mixed_port, "127.0.0.1", echo_port, b"after-reload-load")
    except (OSError, EOFError, TimeoutError, AssertionError):
        recovered = False
    return recovered and process.poll() is None


def config_rejects(binary: pathlib.Path, scratch: pathlib.Path, body: str) -> bool:
    """Rust-only loud reject (parity with phase7a/7b/7c). Go SSR allowlists differ."""
    config = scratch / f"reject-{len(list(scratch.glob('reject-*')))}.yaml"
    config.write_text(
        f"""mixed-port: 0
mode: rule
proxies:
{body}
rules:
  - MATCH,DIRECT
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [str(binary), "-d", str(scratch), "-f", str(config)],
        cwd=scratch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )
    return result.returncode != 0


def live_mismatch(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    ssr_port: int,
    echo_port: int,
    cipher: str,
    protocol: str,
    obfs: str,
    label: str,
) -> tuple[bool, bool]:
    """One-shot mixed listener with intentional cipher/protocol/obfs mismatch."""
    mismatch_scratch = scratch / label
    mismatch_scratch.mkdir(exist_ok=True)
    mismatch_port = reserve_port()
    mismatch_config = mismatch_scratch / "config.yaml"
    mismatch_config.write_text(
        f"""mixed-port: {mismatch_port}
mode: rule
log-level: warning
ipv6: false
proxies:
  - name: ssr-mismatch
    type: ssr
    server: 127.0.0.1
    port: {ssr_port}
    password: {PASSWORD}
    cipher: {cipher}
    protocol: {protocol}
    obfs: {obfs}
rules:
  - MATCH,ssr-mismatch
""",
        encoding="utf-8",
    )
    mismatch_proc, m_out, m_err = launch(binary, mismatch_config, mismatch_scratch)
    try:
        wait_ready(mismatch_proc, mismatch_port)
        rejected = rejected_exchange(mismatch_port, "127.0.0.1", echo_port)
        alive = mismatch_proc.poll() is None
        return rejected, alive
    finally:
        stop(mismatch_proc)
        m_out.close()
        m_err.close()


def hang_ssr_listener() -> tuple[socket.socket, int, list[socket.socket]]:
    """Accept TCP, stay mute briefly, then close — no SSR bytes.

    A forever-hold peer would only surface the client's own socket timeout; we
    close without speaking so the product must fail the handshake with EOF/reset.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = int(listener.getsockname()[1])
    held: list[socket.socket] = []

    def mute_then_close(conn: socket.socket) -> None:
        held.append(conn)
        time.sleep(0.4)
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass

    def accept_loop() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=mute_then_close, args=(conn,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return listener, port, held


def product_closed_exchange(
    mixed_port: int, host: str, port: int, *, wait: float = 5.0
) -> tuple[bool, str]:
    """Return (ok, reason). Client socket wait-timeout is failure, not success."""
    try:
        with connect_domain(mixed_port, host, port) as stream:
            stream.settimeout(wait)
            try:
                stream.sendall(b"ssr-d-hang-probe")
            except (BrokenPipeError, ConnectionResetError):
                return True, "write-reset"
            try:
                data = stream.recv(1)
            except TimeoutError:
                return False, "client-wait-timeout"
            except (BrokenPipeError, ConnectionResetError, EOFError):
                return True, "recv-reset"
            if data == b"":
                return True, "product-eof"
            return False, f"unexpected-data:{data!r}"
    except TimeoutError:
        return False, "dial-or-wait-timeout"
    except (BrokenPipeError, ConnectionResetError, EOFError):
        return True, "connect-reset"
    except OSError as error:
        # TimeoutError is an OSError subclass — must not count as product close.
        if isinstance(error, TimeoutError):
            return False, "os-timeout"
        return True, f"os-error:{type(error).__name__}"


def handshake_timeout_bounded(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    hang_port: int,
    echo_port: int,
) -> bool:
    """Dial SSR against a mute peer; product must close (not client wait-timeout)."""
    hang_scratch = scratch / "hang-timeout"
    hang_scratch.mkdir(exist_ok=True)
    hang_mixed = reserve_port()
    hang_config = hang_scratch / "config.yaml"
    hang_config.write_text(
        f"""mixed-port: {hang_mixed}
mode: rule
log-level: warning
ipv6: false
proxies:
  - name: ssr-hang
    type: ssr
    server: 127.0.0.1
    port: {hang_port}
    password: {PASSWORD}
    cipher: {CIPHER}
    protocol: {PROTOCOL}
    obfs: {OBFS}
rules:
  - MATCH,ssr-hang
""",
        encoding="utf-8",
    )
    process, stdout, stderr = launch(binary, hang_config, hang_scratch)
    try:
        wait_ready(process, hang_mixed)
        fds_before = process_fd_count(process.pid)
        started = time.monotonic()
        closed, reason = product_closed_exchange(
            hang_mixed, "127.0.0.1", echo_port, wait=5.0
        )
        elapsed = time.monotonic() - started
        alive = process.poll() is None
        fds_after = process_fd_count(process.pid)
        # Product-driven close should finish well under the client wait; a pass
        # that only rides the 5s socket timeout is rejected via reason.
        fd_ok = (
            fds_before is None
            or fds_after is None
            or fds_after <= fds_before + (32 if os.name == "nt" else 16)
        )
        return (
            closed
            and reason != "client-wait-timeout"
            and elapsed < 4.5
            and alive
            and fd_ok
        )
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def truncate_mid_stream(mixed_port: int, echo_port: int) -> bool:
    """Write a partial payload then cancel; subsequent full exchange must work."""
    try:
        with connect_domain(mixed_port, "127.0.0.1", echo_port) as stream:
            stream.settimeout(0.4)
            stream.sendall(b"trunc-")
            stream.close()
    except (OSError, TimeoutError):
        pass
    try:
        return echo(mixed_port, "127.0.0.1", echo_port, b"after-truncate")
    except (OSError, EOFError, TimeoutError, AssertionError):
        return False


def exercise(
    binary: pathlib.Path,
    server_py: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    echo_server = start_server(EchoHandler)
    udp_echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEchoHandler)
    udp_echo.allow_reuse_address = True
    udp_thread = threading.Thread(target=udp_echo.serve_forever, daemon=True)
    udp_thread.start()
    udp_port = int(udp_echo.server_address[1])

    mixed_port = reserve_port()
    socks_port = reserve_port()
    controller_port = reserve_port()
    ssr_port = reserve_port()
    wrong_rule_port = reserve_port()

    authority, a_out, a_err = start_ssr_server_cipher(
        server_py,
        scratch,
        ssr_port,
        cipher=CIPHER,
        protocol=PROTOCOL,
        obfs=OBFS,
        protocol_param="",
        obfs_param="",
    )
    config = scratch / "config.yaml"
    write_stress_config(
        config,
        mixed_port=mixed_port,
        socks_port=socks_port,
        controller_port=controller_port,
        ssr_port=ssr_port,
        wrong_rule_port=wrong_rule_port,
    )
    process = stdout = stderr = None
    try:
        process, stdout, stderr = launch(binary, config, scratch)
        wait_ready(process, mixed_port)
        wait_ready(process, socks_port)
        time.sleep(0.15)
        wait_udp_route(process, mixed_port, udp_port)

        baseline = echo(mixed_port, "127.0.0.1", echo_server.port, b"ssr-d-baseline")
        concurrent = concurrent_tcp(mixed_port, echo_server.port, CONCURRENT_TCP)
        mixed = tcp_udp_concurrent(mixed_port, echo_server.port, udp_port)
        churn = cancel_churn(mixed_port, echo_server.port, CANCEL_ROUNDS)
        after_cancel = echo(mixed_port, "127.0.0.1", echo_server.port, b"after-cancel-churn")
        truncated = truncate_mid_stream(mixed_port, echo_server.port)
        cancel_isolated = cancel_exchange(mixed_port, "127.0.0.1", echo_server.port)

        wrong_password = rejected_exchange(mixed_port, "127.0.0.1", wrong_rule_port)
        survived_wrong = process.poll() is None
        after_auth_fail = echo(mixed_port, "127.0.0.1", echo_server.port, b"after-auth-fail")

        refused_target = reserve_port()
        target_refused = rejected_exchange(mixed_port, "127.0.0.1", refused_target)
        survived_refused = process.poll() is None
        after_refused = echo(mixed_port, "127.0.0.1", echo_server.port, b"after-refused")

        # Cipher / protocol / obfs mismatch live paths (loud fail, process survives).
        cipher_mismatch_rejected, mismatch_alive = live_mismatch(
            binary,
            scratch,
            ssr_port=ssr_port,
            echo_port=echo_server.port,
            cipher="aes-256-cfb",
            protocol=PROTOCOL,
            obfs=OBFS,
            label="cipher-mismatch",
        )
        protocol_mismatch_rejected, protocol_mismatch_alive = live_mismatch(
            binary,
            scratch,
            ssr_port=ssr_port,
            echo_port=echo_server.port,
            cipher=CIPHER,
            protocol="origin",
            obfs=OBFS,
            label="protocol-mismatch",
        )
        obfs_mismatch_rejected, obfs_mismatch_alive = live_mismatch(
            binary,
            scratch,
            ssr_port=ssr_port,
            echo_port=echo_server.port,
            cipher=CIPHER,
            protocol=PROTOCOL,
            obfs="http_simple",
            label="obfs-mismatch",
        )

        hang_listener, hang_port, hang_held = hang_ssr_listener()
        try:
            hang_timeout_ok = handshake_timeout_bounded(
                binary, scratch, hang_port, echo_server.port
            )
        finally:
            hang_listener.close()
            for conn in hang_held:
                try:
                    conn.close()
                except OSError:
                    pass

        # Rust-only config rejects (Go SSR allowlists differ; same as 7a/7b/7c).
        reject_scratch = scratch / "rejects"
        reject_scratch.mkdir(exist_ok=True)
        rust_rejects: dict[str, bool] = {}
        if scratch.name == "rust":
            rust_rejects = {
                "rust-rejects-aead": config_rejects(
                    binary,
                    reject_scratch,
                    """  - name: bad
    type: ssr
    server: 127.0.0.1
    port: 1
    password: x
    cipher: aes-128-gcm
    protocol: origin
    obfs: plain
""",
                ),
                "rust-rejects-unknown-protocol": config_rejects(
                    binary,
                    reject_scratch,
                    """  - name: bad
    type: ssr
    server: 127.0.0.1
    port: 1
    password: x
    cipher: aes-128-cfb
    protocol: auth_chain_c
    obfs: plain
""",
                ),
                "rust-rejects-legacy-chacha20": config_rejects(
                    binary,
                    reject_scratch,
                    """  - name: bad
    type: ssr
    server: 127.0.0.1
    port: 1
    password: x
    cipher: chacha20
    protocol: origin
    obfs: plain
""",
                ),
            }

        reload_ok = reload_under_load(
            process, mixed_port, controller_port, config, echo_server.port
        )
        after_reload_udp = udp_once(mixed_port, udp_port, b"ssr-d-udp-after-reload")
        resources = soft_resource_ok(process.pid)

        return {
            "baseline": baseline,
            "concurrent-tcp": concurrent,
            "tcp-udp-concurrent": mixed,
            "cancel-churn": churn,
            "after-cancel": after_cancel,
            "truncate-isolated": truncated,
            "cancel-isolated": cancel_isolated,
            "wrong-password-rejected": wrong_password,
            "survived-wrong-password": survived_wrong,
            "after-auth-fail": after_auth_fail,
            "target-refused": target_refused,
            "survived-target-refused": survived_refused,
            "after-refused": after_refused,
            "cipher-mismatch-rejected": cipher_mismatch_rejected,
            "survived-cipher-mismatch": mismatch_alive,
            "protocol-mismatch-rejected": protocol_mismatch_rejected,
            "survived-protocol-mismatch": protocol_mismatch_alive,
            "obfs-mismatch-rejected": obfs_mismatch_rejected,
            "survived-obfs-mismatch": obfs_mismatch_alive,
            "hang-handshake-timeout": hang_timeout_ok,
            "reload-under-load": reload_ok,
            "after-reload-udp": after_reload_udp,
            "process-alive": process.poll() is None,
            "ssr-server-pin": SSR_SERVER_PIN,
            **rust_rejects,
            **resources,
        }
    finally:
        if process is not None:
            stop(process)
        if stdout is not None:
            stdout.close()
        if stderr is not None:
            stderr.close()
        if authority.poll() is None:
            authority.kill()
            try:
                authority.wait(timeout=IO_DEADLINE)
            except subprocess.TimeoutExpired:
                pass
        a_out.close()
        a_err.close()
        echo_server.close()
        udp_echo.shutdown()
        udp_echo.server_close()


def portable_view(entry: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "baseline",
        "concurrent-tcp",
        "tcp-udp-concurrent",
        "cancel-churn",
        "after-cancel",
        "truncate-isolated",
        "cancel-isolated",
        "wrong-password-rejected",
        "survived-wrong-password",
        "after-auth-fail",
        "target-refused",
        "survived-target-refused",
        "after-refused",
        "cipher-mismatch-rejected",
        "survived-cipher-mismatch",
        "protocol-mismatch-rejected",
        "survived-protocol-mismatch",
        "obfs-mismatch-rejected",
        "survived-obfs-mismatch",
        "hang-handshake-timeout",
        "reload-under-load",
        "after-reload-udp",
        "process-alive",
        "ssr-server-pin",
        "rss-bounded",
        "fd-bounded",
    )
    return {key: entry.get(key) for key in keys}


def main() -> int:
    assert_go_oracle_baseline()
    observations: dict[str, Any] = {}
    server_py = ensure_ssr_server()
    with tempfile.TemporaryDirectory(prefix="phase7d-ssr-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE7D_SSR_CARGO_TARGET", "phase7d-ssr")
        try:
            for engine in ("rust", "go"):
                scratch = root / engine
                scratch.mkdir()
                observations[engine] = exercise(binaries[engine], server_py, scratch)
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

    go_view = portable_view(observations.get("go", {}))
    rust_view = portable_view(observations.get("rust", {}))
    required_true = (
        "baseline",
        "concurrent-tcp",
        "tcp-udp-concurrent",
        "cancel-churn",
        "after-cancel",
        "truncate-isolated",
        "cancel-isolated",
        "wrong-password-rejected",
        "survived-wrong-password",
        "after-auth-fail",
        "target-refused",
        "survived-target-refused",
        "after-refused",
        "cipher-mismatch-rejected",
        "survived-cipher-mismatch",
        "protocol-mismatch-rejected",
        "survived-protocol-mismatch",
        "obfs-mismatch-rejected",
        "survived-obfs-mismatch",
        "hang-handshake-timeout",
        "reload-under-load",
        "after-reload-udp",
        "process-alive",
        "rss-bounded",
        "fd-bounded",
    )
    rust_only = (
        "rust-rejects-aead",
        "rust-rejects-unknown-protocol",
        "rust-rejects-legacy-chacha20",
    )
    rust_ok = all(observations["rust"].get(key) for key in required_true + rust_only)
    go_ok = all(observations["go"].get(key) for key in required_true)
    if go_view != rust_view or not rust_ok or not go_ok:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("SSR-D ShadowsocksR stress/negative differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

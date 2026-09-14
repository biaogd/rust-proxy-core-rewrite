#!/usr/bin/env python3
"""Go/Rust differential for 6J-B SSH outbound lifecycle.

Transport TCP keepalive reuse, concurrent mux, cancel isolation, dest-refused
isolation, authority restart reconnect (no reload required), encrypted
private-key file + passphrase, applied `host-key-algorithms`, and a short soak.
UDP / dialer-proxy stay rejected. Native Parity is not claimed.
"""

from __future__ import annotations

import concurrent.futures
import json
import pathlib
import shutil
import subprocess
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
from phase6j_ssh_tcp import (
    PASSWORD,
    USERNAME,
    authority_binary,
    config_validation,
    exchange,
    ssh_record,
    start_authority,
    unused_port,
    wait_exchange,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6j-ssh-lifecycle-diff.json"
CONCURRENT = 4
CANCEL_ROUNDS = 8
SOAK_ROUNDS = 20
PASSPHRASE = "phrase"


def extra_lines(**fields: object) -> str:
    lines = []
    for key, value in fields.items():
        yaml_key = key.replace("_", "-")
        if isinstance(value, list):
            rendered = "[" + ", ".join(str(item) for item in value) + "]"
            lines.append(f"    {yaml_key}: {rendered}")
        else:
            lines.append(f"    {yaml_key}: {value}")
    return ("\n".join(lines) + "\n") if lines else ""


def generate_encrypted_key(path: pathlib.Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    pub = pathlib.Path(str(path) + ".pub")
    if pub.exists():
        pub.unlink()
    subprocess.run(
        [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-N",
            PASSPHRASE,
            "-f",
            str(path),
            "-C",
            "rewrite-6jb",
            "-q",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return pub.read_text(encoding="utf-8").strip()


def exchange_once(mixed_port: int, host: str, echo_port: int, payload: bytes) -> bool:
    return exchange(mixed_port, host, echo_port, payload)


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
        payload = (f"ssh-c-{index}-".encode() * 32)[:512]
        try:
            return exchange_once(mixed_port, host, echo_port, payload)
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


def short_soak(mixed_port: int, host: str, echo_port: int, rounds: int) -> bool:
    for index in range(rounds):
        try:
            if not exchange_once(mixed_port, host, echo_port, f"soak-{index}".encode()):
                return False
        except (OSError, TimeoutError, AssertionError, EOFError):
            return False
    return True


def write_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    controller_port: int,
    authority_port: int,
    keyfile_port: int,
    refused_port: int,
) -> None:
    extra = extra_lines(host_key_algorithms=["ssh-ed25519"])
    keyfile_extra = extra + (
        "    private-key: id_ed25519\n"
        f"    private-key-passphrase: {PASSPHRASE}\n"
    )
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
keep-alive-idle: 1
keep-alive-interval: 1
hosts:
  echo.ssh.test: 127.0.0.1
proxies:
{ssh_record("inline-ssh", authority_port, extra=extra)}
{ssh_record("ssh-keyfile", authority_port, extra=keyfile_extra, password=None)}
rules:
  - DST-PORT,{keyfile_port},ssh-keyfile
  - DST-PORT,{refused_port},inline-ssh
  - MATCH,inline-ssh
"""
    )


def exercise(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    private_key_path: pathlib.Path,
    authorized_key: str,
) -> dict[str, Any]:
    from phase6j_ssh_tcp import listen_local

    echo, echo_thread, echo_port = listen_local(EchoHandler)
    key_echo, key_thread, key_echo_port = listen_local(EchoHandler)
    _ = echo_thread, key_thread

    mixed_port, controller_port, authority_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    refused_port = unused_port()
    authority_scratch = scratch / "authority"
    ssh_process, authority_stdout, authority_stderr, _host_key = start_authority(
        authority,
        authority_scratch,
        authority_port,
        authorized_key=authorized_key,
    )

    profile_home = scratch / ".config" / "mihomo"
    profile_home.mkdir(parents=True)
    shutil.copy2(private_key_path, profile_home / "id_ed25519")
    (profile_home / "id_ed25519").chmod(0o600)

    config = scratch / "config.yaml"
    write_config(
        config,
        mixed_port=mixed_port,
        controller_port=controller_port,
        authority_port=authority_port,
        keyfile_port=key_echo_port,
        refused_port=refused_port,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        time.sleep(0.3)

        ready = wait_exchange(process, mixed_port, "echo.ssh.test", echo_port, b"ssh-ready")
        time.sleep(2.5)
        after_keepalive = exchange_once(
            mixed_port, "127.0.0.1", echo_port, b"after-keepalive"
        )
        reuse_second = exchange_once(mixed_port, "127.0.0.1", echo_port, b"reuse-second")
        concurrent_ok = concurrent_tcp(mixed_port, "127.0.0.1", echo_port, CONCURRENT)
        cancel_ok = cancel_churn(mixed_port, "127.0.0.1", echo_port, CANCEL_ROUNDS)
        after_cancel = exchange_once(mixed_port, "127.0.0.1", echo_port, b"after-cancel")
        passphrase_file = wait_exchange(
            process, mixed_port, "127.0.0.1", key_echo_port, b"passphrase-file"
        )

        target_refused = rejected_exchange(mixed_port, "127.0.0.1", refused_port)
        after_refused = exchange_once(mixed_port, "127.0.0.1", echo_port, b"after-refused")

        soak_ok = short_soak(mixed_port, "127.0.0.1", echo_port, SOAK_ROUNDS)

        stop(ssh_process)
        authority_stdout.close()
        authority_stderr.close()
        time.sleep(0.3)
        during_restart = rejected_exchange(mixed_port, "127.0.0.1", echo_port)
        authority_scratch2 = scratch / "authority-restart"
        ssh_process, authority_stdout, authority_stderr, _ = start_authority(
            authority,
            authority_scratch2,
            authority_port,
            authorized_key=authorized_key,
        )
        time.sleep(0.5)
        after_restart = wait_exchange(
            process,
            mixed_port,
            "127.0.0.1",
            echo_port,
            b"after-restart",
            deadline_secs=20.0,
        )
        reload_via_controller(process, controller_port, config, secret=SECRET)
        after_reload = wait_exchange(
            process, mixed_port, "echo.ssh.test", echo_port, b"after-reload"
        )

        return {
            "ready": ready,
            "after-keepalive": after_keepalive,
            "reuse-second": reuse_second,
            "concurrent": concurrent_ok,
            "cancel-churn": cancel_ok,
            "after-cancel": after_cancel,
            "passphrase-file": passphrase_file,
            "target-refused": target_refused,
            "after-refused": after_refused,
            "short-soak": soak_ok,
            "during-restart-rejected": during_restart,
            "after-restart": after_restart,
            "after-reload": after_reload,
            "alive": process.poll() is None,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop(ssh_process)
        authority_stdout.close()
        authority_stderr.close()
        echo.shutdown()
        echo.server_close()
        key_echo.shutdown()
        key_echo.server_close()


def rust_wrong_algorithm_rejected(binary: pathlib.Path, authority: pathlib.Path, scratch: pathlib.Path) -> bool:
    from phase6j_ssh_tcp import listen_local

    echo, echo_thread, echo_port = listen_local(EchoHandler)
    _ = echo_thread
    mixed_port, controller_port, authority_port = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
    )
    ssh_process, authority_stdout, authority_stderr, host_key = start_authority(
        authority, scratch / "authority", authority_port
    )
    extra = ""
    if host_key:
        extra += f"    host-key:\n      - {host_key}\n"
    extra += extra_lines(host_key_algorithms=["rsa-sha2-256"])
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
proxies:
{ssh_record("inline-ssh", authority_port, extra=extra)}
rules:
  - MATCH,inline-ssh
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        return rejected_exchange(mixed_port, "127.0.0.1", echo_port)
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop(ssh_process)
        authority_stdout.close()
        authority_stderr.close()
        echo.shutdown()
        echo.server_close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase-6jb-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6JSSH_CARGO_TARGET", "phase-6ja")
        authority = authority_binary()
        if not authority.exists():
            raise RuntimeError(f"rewrite-ssh-authority was not built: {authority}")
        key_scratch = root / "shared-key"
        private_key_path = key_scratch / "id_ed25519"
        authorized_key = generate_encrypted_key(private_key_path)
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(
                    binaries[name],
                    authority,
                    scratch,
                    private_key_path,
                    authorized_key,
                )
            observations["rust-host-key-algorithms-accepted"] = config_validation(
                binaries["rust"],
                root / "rust-validate-algs",
                "proxies:\n"
                "  - name: algs\n"
                "    type: ssh\n"
                "    server: 127.0.0.1\n"
                "    port: 22\n"
                f"    username: {USERNAME}\n"
                f"    password: {PASSWORD}\n"
                "    host-key-algorithms: [ssh-ed25519]\n",
            )
            observations["rust-udp-rejected"] = not config_validation(
                binaries["rust"],
                root / "rust-validate-udp",
                "proxies:\n"
                "  - name: deferred\n"
                "    type: ssh\n"
                "    server: 127.0.0.1\n"
                "    port: 22\n"
                f"    username: {USERNAME}\n"
                f"    password: {PASSWORD}\n"
                "    udp: true\n",
            )
            observations["rust-wrong-host-key-algorithm-rejected"] = (
                rust_wrong_algorithm_rejected(
                    binaries["rust"], authority, root / "rust-wrong-alg"
                )
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
        "cancel-churn",
        "after-cancel",
        "passphrase-file",
        "target-refused",
        "after-refused",
        "short-soak",
        "during-restart-rejected",
        "after-restart",
        "after-reload",
        "alive",
    )
    if (
        go != rust
        or not all(rust.get(key) for key in required)
        or not observations.get("rust-host-key-algorithms-accepted", False)
        or not observations.get("rust-udp-rejected", False)
        or not observations.get("rust-wrong-host-key-algorithm-rejected", False)
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {
                    "go": go,
                    "rust": rust,
                    "rust-host-key-algorithms-accepted": observations.get(
                        "rust-host-key-algorithms-accepted"
                    ),
                    "rust-udp-rejected": observations.get("rust-udp-rejected"),
                    "rust-wrong-host-key-algorithm-rejected": observations.get(
                        "rust-wrong-host-key-algorithm-rejected"
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("6J-B SSH lifecycle differential passed")
    print(json.dumps(rust, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

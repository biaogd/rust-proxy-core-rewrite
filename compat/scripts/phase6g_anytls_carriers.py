#!/usr/bin/env python3
"""Go/Rust differential for Phase 6G-E AnyTLS ShadowTLS + JLS carriers."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import tempfile
import textwrap
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, recv_exact, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6g-anytls-carriers-diff.json"
ANYTLS_PASSWORD = "phase6g-carrier-anytls"
SHADOWTLS_PASSWORD = "phase6g-carrier-shadowtls"
JLS_USERNAME = "phase6g-jls-user"
JLS_PASSWORD = "phase6g-jls-pass"
SHADOW_SNI = "phase6g-shadowtls.example"
JLS_SNI = "phase6g-jls.example"


def build_authority(scratch: pathlib.Path, package: str, name: str) -> pathlib.Path:
    output = scratch / (f"{name}.exe" if os.name == "nt" else name)
    subprocess.run(
        ["go", "build", "-o", str(output), f"./compat/helpers/{package}"],
        cwd=ROOT,
        check=True,
        timeout=180,
    )
    return output


def start_process(args: list[str]) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        args,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    line = process.stdout.readline().decode().strip()
    if not line.startswith("READY "):
        stderr = process.stderr.read().decode() if process.stderr else ""
        process.kill()
        raise RuntimeError(f"authority failed to start: {line!r} stderr={stderr!r}")
    return process


def start_echo(port: int) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(32)
    server.settimeout(0.5)

    def accept_loop() -> None:
        while True:
            try:
                client, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            client.settimeout(IO_DEADLINE)

            def echo(stream: socket.socket) -> None:
                try:
                    while True:
                        data = stream.recv(4096)
                        if not data:
                            break
                        stream.sendall(data)
                except OSError:
                    pass
                finally:
                    stream.close()

            threading.Thread(target=echo, args=(client,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return server


def exchange(mixed_port: int, host: str, target_port: int, payload: bytes) -> bool:
    with connect_domain(mixed_port, host, target_port) as stream:
        stream.settimeout(IO_DEADLINE)
        stream.sendall(payload)
        return recv_exact(stream, len(payload)) == payload


def wait_exchange(
    process: Any,
    mixed_port: int,
    host: str,
    target_port: int,
    payload: bytes,
) -> bool:
    deadline = time.monotonic() + IO_DEADLINE
    while True:
        try:
            return exchange(mixed_port, host, target_port, payload)
        except (AssertionError, EOFError, OSError):
            if process.poll() is not None or time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def write_client_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    server_port: int,
    sni: str,
    carrier_block: str,
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: anytls-carrier
    type: anytls
    server: 127.0.0.1
    port: {server_port}
    password: {ANYTLS_PASSWORD}
    sni: {sni}
    alpn: [h2, http/1.1]
    skip-cert-verify: true
    disable-reuse: true
{textwrap.indent(carrier_block.rstrip(), "    ")}
rules:
  - MATCH,anytls-carrier
"""
    )


def stop_authority(auth: subprocess.Popen[bytes]) -> None:
    auth.terminate()
    try:
        auth.wait(timeout=2)
    except subprocess.TimeoutExpired:
        auth.kill()


def exercise_shadow_tls(
    binary: pathlib.Path, scratch: pathlib.Path, authority: pathlib.Path
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    echo_port = reserve_port()
    echo_server = start_echo(echo_port)
    server_port = reserve_port()
    auth = start_process(
        [str(authority), f"127.0.0.1:{server_port}", ANYTLS_PASSWORD, SHADOWTLS_PASSWORD]
    )
    mixed_port = reserve_port()
    config = scratch / "shadow-tls.yaml"
    write_client_config(
        config,
        mixed_port=mixed_port,
        server_port=server_port,
        sni=SHADOW_SNI,
        carrier_block=f"""shadow-tls-opts:
  password: {SHADOWTLS_PASSWORD}
  version: 3
""",
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        ok = wait_exchange(
            process, mixed_port, "echo.phase6g", echo_port, b"shadow-tls-carrier"
        )
        return {"ok": ok, "process-alive": process.poll() is None}
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop_authority(auth)
        echo_server.close()


def exercise_jls(
    binary: pathlib.Path, scratch: pathlib.Path, authority: pathlib.Path
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    echo_port = reserve_port()
    echo_server = start_echo(echo_port)
    server_port = reserve_port()
    auth = start_process(
        [
            str(authority),
            f"127.0.0.1:{server_port}",
            ANYTLS_PASSWORD,
            JLS_USERNAME,
            JLS_PASSWORD,
        ]
    )
    mixed_port = reserve_port()
    config = scratch / "jls.yaml"
    write_client_config(
        config,
        mixed_port=mixed_port,
        server_port=server_port,
        sni=JLS_SNI,
        carrier_block=f"""jls-opts:
  username: {JLS_USERNAME}
  password: {JLS_PASSWORD}
""",
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        ok = wait_exchange(
            process, mixed_port, "echo.phase6g", echo_port, b"jls-carrier"
        )
        return {"ok": ok, "process-alive": process.poll() is None}
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        stop_authority(auth)
        echo_server.close()


def exercise_mutual_exclusion(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    mixed_port = reserve_port()
    config = scratch / "mutex.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
proxies:
  - name: bad
    type: anytls
    server: 127.0.0.1
    port: 443
    password: x
    shadow-tls-opts:
      password: a
      version: 3
    restls-opts:
      password: b
rules:
  - MATCH,bad
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        time.sleep(0.5)
        return {"rejected": process.poll() is not None}
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def exercise(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    shadow_authority: pathlib.Path,
    jls_authority: pathlib.Path,
) -> dict[str, Any]:
    return {
        "shadow-tls-v3": exercise_shadow_tls(binary, scratch / "stls", shadow_authority),
        "jls": exercise_jls(binary, scratch / "jls", jls_authority),
        "mutual-exclusion": exercise_mutual_exclusion(binary, scratch / "mutex"),
    }


def public_view(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "shadow-tls-v3": {
            "ok": entry["shadow-tls-v3"]["ok"],
            "process-alive": entry["shadow-tls-v3"]["process-alive"],
        },
        "jls": {
            "ok": entry["jls"]["ok"],
            "process-alive": entry["jls"]["process-alive"],
        },
        "mutual-exclusion": entry["mutual-exclusion"],
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6g-anytls-carriers-") as temporary:
        root = pathlib.Path(temporary)
        shadow_authority = build_authority(
            root, "anytls_shadowtls_authority", "anytls-shadowtls-authority"
        )
        jls_authority = build_authority(root, "anytls_jls_authority", "anytls-jls-authority")
        binaries = build_binaries(
            root, "PHASE6GANYTLSCARRIERS_CARGO_TARGET", "phase6g-anytls-carriers"
        )
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(
                    binaries[name], scratch, shadow_authority, jls_authority
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

    go_view = public_view(observations["go"])
    rust_view = public_view(observations["rust"])
    matched = (
        go_view == rust_view
        and go_view["shadow-tls-v3"]["ok"]
        and go_view["shadow-tls-v3"]["process-alive"]
        and go_view["jls"]["ok"]
        and go_view["jls"]["process-alive"]
        and go_view["mutual-exclusion"]["rejected"]
    )
    if not matched:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6G-E AnyTLS ShadowTLS+JLS carrier differential passed")
    print(json.dumps({"go": go_view, "rust": rust_view}, indent=2, sort_keys=True))
    print(
        "Leftover: Restls dial is blocked on a shared Restls TLS client transport "
        "(Go restls-client-go / utls fork; no Rust Restls client in-tree)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for SSR-B: auth_aes128_* + http_* + tls1.2_ticket_* camouflage.

Reuses the pinned shadowsocksrr server and fetch-time shims from phase7a.
TLS ticket names are camouflage only (not real TLS).
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import time
from typing import Any

from phase1 import (
    EchoHandler,
    HalfCloseHandler,
    IO_DEADLINE,
    ROOT,
    assert_go_oracle_baseline,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks_ciphers import LARGE_PAYLOAD, echo, half_close
from phase7a_ssr_tcp import (
    PASSWORD,
    SSR_SERVER_PIN,
    cancel_exchange,
    ensure_ssr_server,
    segmented_exchange,
    start_ssr_server as start_ssr_server_a,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase7b-ssr-tcp-diff.json"
CIPHER = "aes-128-cfb"

# Each claimed SSR-B combo: (protocol, protocol_param, obfs, obfs_param, label)
#
# protocol-param `uid:passwd` is accepted by config/client (multi-user shape, same
# as Go) but is not exercised end-to-end against the single-password pin server —
# that server has no mudb users, so uid:passwd cannot decrypt. Obfs-param hosts
# are covered below.
PROFILES: list[tuple[str, str, str, str, str]] = [
    ("auth_aes128_md5", "", "plain", "", "auth_aes128_md5+plain"),
    ("auth_aes128_sha1", "", "plain", "", "auth_aes128_sha1+plain"),
    ("origin", "", "http_simple", "", "origin+http_simple"),
    ("origin", "", "http_post", "", "origin+http_post"),
    ("origin", "", "http_simple", "cloudflare.com", "origin+http_simple+param"),
    ("origin", "", "tls1.2_ticket_auth", "download.windowsupdate.com", "origin+tls_ticket_auth"),
    (
        "origin",
        "",
        "tls1.2_ticket_fastauth",
        "download.windowsupdate.com",
        "origin+tls_ticket_fastauth",
    ),
    (
        "auth_aes128_md5",
        "",
        "http_simple",
        "cloudflare.com",
        "auth_md5+http_simple",
    ),
    (
        "auth_aes128_sha1",
        "",
        "tls1.2_ticket_auth",
        "www.microsoft.com",
        "auth_sha1+tls_ticket",
    ),
]


def start_ssr_server(
    server_py: pathlib.Path,
    scratch: pathlib.Path,
    port: int,
    *,
    protocol: str,
    obfs: str,
    protocol_param: str,
    obfs_param: str,
) -> tuple[Any, Any, Any]:
    """Like phase7a start, but with protocol/obfs (+ optional params)."""
    import os
    import socket

    env = os.environ.copy()
    env["PYTHONPATH"] = str(server_py.parent.parent)
    stdout = (scratch / "ssr-server.stdout").open("wb")
    stderr = (scratch / "ssr-server.stderr").open("wb")
    cmd = [
        "python3",
        str(server_py),
        "-s",
        "127.0.0.1",
        "-p",
        str(port),
        "-k",
        PASSWORD,
        "-m",
        CIPHER,
        "-O",
        protocol,
        "-o",
        obfs,
        "--forbidden-ip",
        "",
        "-q",
    ]
    if protocol_param:
        cmd.extend(["-G", protocol_param])
    if obfs_param:
        cmd.extend(["-g", obfs_param])
    process = subprocess.Popen(
        cmd,
        cwd=str(server_py.parent),
        env=env,
        stdout=stdout,
        stderr=stderr,
    )
    deadline = time.time() + 8
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"SSR server exited early ({protocol}/{obfs}): "
                f"{(scratch / 'ssr-server.stderr').read_text()[:800]}"
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return process, stdout, stderr
        except OSError:
            time.sleep(0.1)
    process.kill()
    raise RuntimeError(f"SSR server failed to accept ({protocol}/{obfs})")


def write_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    ssr_port: int,
    protocol: str,
    protocol_param: str,
    obfs: str,
    obfs_param: str,
) -> None:
    lines = [
        f"mixed-port: {mixed_port}",
        "mode: rule",
        "log-level: info",
        "ipv6: false",
        "proxies:",
        "  - name: local-ssr",
        "    type: ssr",
        "    server: 127.0.0.1",
        f"    port: {ssr_port}",
        f"    password: {PASSWORD}",
        f"    cipher: {CIPHER}",
        f"    protocol: {protocol}",
        f"    obfs: {obfs}",
    ]
    if protocol_param:
        lines.append(f'    protocol-param: "{protocol_param}"')
    if obfs_param:
        lines.append(f"    obfs-param: {obfs_param}")
    lines.extend(
        [
            "proxy-groups:",
            "  - name: ssr-select",
            "    type: select",
            "    proxies: [local-ssr]",
            "    default-selected: local-ssr",
            "rules:",
            "  - MATCH,ssr-select",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def exercise(
    binary: pathlib.Path,
    server_py: pathlib.Path,
    scratch: pathlib.Path,
    protocol: str,
    protocol_param: str,
    obfs: str,
    obfs_param: str,
    label: str,
) -> dict[str, Any]:
    echo_server = start_server(EchoHandler)
    half = start_server(HalfCloseHandler)
    mixed_port = reserve_port()
    ssr_port = reserve_port()
    authority, a_out, a_err = start_ssr_server(
        server_py,
        scratch,
        ssr_port,
        protocol=protocol,
        obfs=obfs,
        protocol_param=protocol_param,
        obfs_param=obfs_param,
    )
    config = scratch / "config.yaml"
    write_config(
        config,
        mixed_port=mixed_port,
        ssr_port=ssr_port,
        protocol=protocol,
        protocol_param=protocol_param,
        obfs=obfs,
        obfs_param=obfs_param,
    )
    process = stdout = stderr = None
    try:
        process, stdout, stderr = launch(binary, config, scratch)
        wait_ready(process, mixed_port)
        time.sleep(0.2)

        def safe_echo(payload: bytes) -> bool:
            try:
                return echo(mixed_port, "127.0.0.1", echo_server.port, payload)
            except (OSError, EOFError, TimeoutError):
                return False

        small = safe_echo(b"ssr-b-small")
        large = safe_echo(LARGE_PAYLOAD)
        try:
            segmented = segmented_exchange(
                mixed_port, "127.0.0.1", echo_server.port, LARGE_PAYLOAD
            )
        except (OSError, EOFError, TimeoutError):
            segmented = False
        try:
            half_ok = half_close(mixed_port, half.port)
        except (OSError, EOFError, TimeoutError):
            half_ok = False
        try:
            cancel_ok = cancel_exchange(mixed_port, "127.0.0.1", echo_server.port)
        except (OSError, EOFError, TimeoutError):
            cancel_ok = False
        return {
            "label": label,
            "protocol": protocol,
            "obfs": obfs,
            "small": small,
            "large": large,
            "segmented": segmented,
            "half-close": half_ok,
            "cancel-isolated": cancel_ok,
            "process-alive": process.poll() is None,
            "ssr-server-pin": SSR_SERVER_PIN,
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
        half.close()


def shared_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        key: profile[key]
        for key in (
            "label",
            "protocol",
            "obfs",
            "small",
            "large",
            "segmented",
            "cancel-isolated",
            "process-alive",
            "ssr-server-pin",
        )
    }


def main() -> int:
    assert_go_oracle_baseline()
    _ = start_ssr_server_a
    observations: dict[str, Any] = {}
    server_py = ensure_ssr_server()
    with tempfile.TemporaryDirectory(prefix="phase7b-ssr-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE7B_SSR_CARGO_TARGET", "phase7b-ssr")
        try:
            for engine in ("rust", "go"):
                profiles: dict[str, Any] = {}
                for protocol, protocol_param, obfs, obfs_param, label in PROFILES:
                    scratch = root / engine / label.replace("+", "_").replace("/", "_")
                    scratch.mkdir(parents=True)
                    profiles[label] = exercise(
                        binaries[engine],
                        server_py,
                        scratch,
                        protocol,
                        protocol_param,
                        obfs,
                        obfs_param,
                        label,
                    )
                observations[engine] = profiles
            reject = root / "reject"
            reject.mkdir()
            bad = reject / "bad.yaml"
            bad.write_text(
                """mixed-port: 0
mode: rule
proxies:
  - name: bad
    type: ssr
    server: 127.0.0.1
    port: 1
    password: x
    cipher: aes-128-cfb
    protocol: auth_sha1_v4
    obfs: plain
""",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [str(binaries["rust"]), "-d", str(reject), "-f", str(bad)],
                capture_output=True,
                timeout=20,
                check=False,
            )
            observations["rust-rejects-auth-sha1-v4"] = proc.returncode != 0
            bad.write_text(
                """mixed-port: 0
mode: rule
proxies:
  - name: bad
    type: ssr
    server: 127.0.0.1
    port: 1
    password: x
    cipher: aes-128-cfb
    protocol: origin
    obfs: random_head
""",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [str(binaries["rust"]), "-d", str(reject), "-f", str(bad)],
                capture_output=True,
                timeout=20,
                check=False,
            )
            observations["rust-rejects-random-head"] = proc.returncode != 0
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

    # Half-close: Rust+server gate for non-tls-ticket profiles (Go mixed pipe
    # does not preserve SHUT_WR). tls1.2_ticket_* camouflage half-close remains
    # best-effort — require small/large/segmented/cancel for those.
    rust_half_required = [
        profile
        for label, profile in observations.get("rust", {}).items()
        if "tls1.2_ticket" not in profile.get("obfs", "")
        and "tls_ticket" not in label
    ]
    rust_half_ok = all(profile.get("half-close") for profile in rust_half_required)

    go_shared = {
        label: shared_profile(profile)
        for label, profile in observations.get("go", {}).items()
        if "tls" not in label
    }
    rust_shared = {
        label: shared_profile(profile)
        for label, profile in observations.get("rust", {}).items()
        if "tls" not in label
    }
    # tls1.2_ticket_* : Rust-vs-pin is authoritative; Go may race u16 record
    # packing when bidirectional copy writes >65535 before handshake Read.
    rust_tls_ok = all(
        all(
            profile.get(key)
            for key in ("small", "large", "segmented", "cancel-isolated", "process-alive")
        )
        for label, profile in observations.get("rust", {}).items()
        if "tls" in label
    )

    if (
        go_shared != rust_shared
        or not rust_half_ok
        or not rust_tls_ok
        or not observations.get("rust-rejects-auth-sha1-v4")
        or not observations.get("rust-rejects-random-head")
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    for engine in ("go", "rust"):
        for label, profile in observations[engine].items():
            if engine == "go" and "tls" in label:
                # Covered by rust_tls_ok; Go large may fail on pin (u16 race).
                continue
            required = (
                "small",
                "large",
                "segmented",
                "cancel-isolated",
                "process-alive",
            )
            if engine == "rust" and "tls" not in label:
                required = (*required, "half-close")
            if not all(profile.get(key) for key in required):
                FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
                FAILURE_ARTIFACT.write_text(
                    json.dumps(observations, indent=2, sort_keys=True)
                )
                return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("SSR-B ShadowsocksR TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Go/Rust differential for SSR-A: origin + plain + AES-CFB against a pinned SSR server.

Server pin: shadowsocksrr/shadowsocksr @ SSR_SERVER_PIN (Python SSR, not Clash inbound).
Fetch-time shims: Python 3 `collections.abc`, empty `--forbidden-ip` for loopback
echo targets, and TCP half-close relay in `tcprelay.py` (upstream destroys on FIN).
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
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
    recv_exact,
    reserve_port,
    start_server,
    wait_ready,
)
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain, debug_files
from phase6c_shadowsocks_ciphers import LARGE_PAYLOAD, echo, half_close


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase7a-ssr-tcp-diff.json"
PASSWORD = "phase7a-ssr-password"
# Verified origin+plain server tip (shallow clone of shadowsocksrr/shadowsocksr).
SSR_SERVER_REPO = "https://github.com/shadowsocksrr/shadowsocksr.git"
SSR_SERVER_PIN = "fd723a92c488d202b407323f0512987346944136"
# Bump when fetch-time shims change so local caches rebuild.
SSR_SERVER_SHIM = "py3+forbidden-empty+halfclose-v1"
CIPHERS = ("aes-128-cfb", "aes-256-cfb")


def ssr_cache_dir() -> pathlib.Path:
    override = os.environ.get("PHASE7A_SSR_CACHE")
    if override:
        return pathlib.Path(override)
    return ROOT / "compat" / ".cache" / "shadowsocksr" / SSR_SERVER_PIN


def _apply_half_close_shim(tcprelay: pathlib.Path) -> None:
    """Relay TCP FIN as SHUT_WR so half-close echo handlers can reply."""
    text = tcprelay.read_text(encoding="utf-8")
    if "phase7a_half_close" in text:
        return
    needle_init = "self._remote_address = None\n"
    if needle_init not in text:
        # Fall back to a stable nearby assignment in TCPRelayHandler.__init__.
        needle_init = "self._stage = STAGE_INIT\n"
    insert_init = (
        needle_init
        + "        # phase7a_half_close: track simplex FIN without full destroy\n"
        + "        self._local_read_closed = False\n"
        + "        self._remote_read_closed = False\n"
    )
    if needle_init not in text:
        raise RuntimeError("unable to locate TCPRelayHandler init for half-close shim")
    text = text.replace(needle_init, insert_init, 1)

    helpers = '''
    def _phase7a_half_close_local(self):
        # phase7a_half_close
        if self._local_read_closed:
            return
        self._local_read_closed = True
        if self._remote_sock:
            try:
                self._remote_sock.shutdown(socket.SHUT_WR)
            except (OSError, IOError):
                pass
        if self._remote_read_closed:
            self.destroy()

    def _phase7a_half_close_remote(self):
        # phase7a_half_close
        if self._remote_read_closed:
            return
        self._remote_read_closed = True
        if self._local_sock:
            try:
                self._local_sock.shutdown(socket.SHUT_WR)
            except (OSError, IOError):
                pass
        if self._local_read_closed:
            self.destroy()

'''
    # Insert helpers just before _on_local_read.
    anchor = "    def _on_local_read(self):\n"
    if anchor not in text:
        raise RuntimeError("unable to locate _on_local_read for half-close shim")
    text = text.replace(anchor, helpers + anchor, 1)

    # Replace local empty-read destroy (first occurrence in _on_local_read).
    local_destroy = (
        "        if not data:\n"
        "            self.destroy()\n"
        "            return\n"
        "\n"
        "        self.speed_tester_u.add(len(data))\n"
    )
    local_half = (
        "        if not data:\n"
        "            self._phase7a_half_close_local()\n"
        "            return\n"
        "\n"
        "        self.speed_tester_u.add(len(data))\n"
    )
    if local_destroy not in text:
        raise RuntimeError("unable to patch local EOF half-close in tcprelay")
    text = text.replace(local_destroy, local_half, 1)

    remote_destroy = (
        "        if not data:\n"
        "            self.destroy()\n"
        "            return\n"
        "\n"
        "        self.speed_tester_d.add(len(data))\n"
    )
    remote_half = (
        "        if not data:\n"
        "            self._phase7a_half_close_remote()\n"
        "            return\n"
        "\n"
        "        self.speed_tester_d.add(len(data))\n"
    )
    if remote_destroy not in text:
        raise RuntimeError("unable to patch remote EOF half-close in tcprelay")
    text = text.replace(remote_destroy, remote_half, 1)
    tcprelay.write_text(text, encoding="utf-8")


def ensure_ssr_server() -> pathlib.Path:
    """Clone/pin the standalone SSR server and apply fetch-time shims."""
    cache = ssr_cache_dir()
    marker = cache / ".pin-ready"
    expected = f"{SSR_SERVER_PIN}:{SSR_SERVER_SHIM}\n"
    if (
        marker.exists()
        and marker.read_text(encoding="utf-8") == expected
        and (cache / "shadowsocks" / "server.py").exists()
    ):
        return cache / "shadowsocks" / "server.py"
    if cache.exists():
        shutil.rmtree(cache)
    cache.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            SSR_SERVER_REPO,
            str(cache),
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(cache), "checkout", "--quiet", SSR_SERVER_PIN],
        check=True,
    )
    for path in (cache / "shadowsocks").rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        patched = text.replace(
            "collections.MutableMapping", "collections.abc.MutableMapping"
        ).replace(
            "from collections import MutableMapping",
            "from collections.abc import MutableMapping",
        ).replace("xrange(", "range(")
        if patched != text:
            path.write_text(patched, encoding="utf-8")
    _apply_half_close_shim(cache / "shadowsocks" / "tcprelay.py")
    marker.write_text(expected, encoding="utf-8")
    return cache / "shadowsocks" / "server.py"


def start_ssr_server(
    server_py: pathlib.Path,
    scratch: pathlib.Path,
    port: int,
    cipher: str,
) -> tuple[subprocess.Popen[bytes], Any, Any]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(server_py.parent.parent)
    stdout = (scratch / "ssr-server.stdout").open("wb")
    stderr = (scratch / "ssr-server.stderr").open("wb")
    process = subprocess.Popen(
        [
            "python3",
            str(server_py),
            "-s",
            "127.0.0.1",
            "-p",
            str(port),
            "-k",
            PASSWORD,
            "-m",
            cipher,
            "-O",
            "origin",
            "-o",
            "plain",
            # Default forbids 127.0.0.0/8; phase echo targets are loopback.
            "--forbidden-ip",
            "",
            "-q",
        ],
        cwd=str(server_py.parent),
        env=env,
        stdout=stdout,
        stderr=stderr,
    )
    deadline = time.time() + 8
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"SSR server exited early: {(scratch / 'ssr-server.stderr').read_text()[:800]}"
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return process, stdout, stderr
        except OSError:
            time.sleep(0.1)
    process.kill()
    raise RuntimeError("SSR server failed to accept connections")


def write_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    ssr_port: int,
    cipher: str,
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-ssr
    type: ssr
    server: 127.0.0.1
    port: {ssr_port}
    password: {PASSWORD}
    cipher: {cipher}
    protocol: origin
    obfs: plain
proxy-groups:
  - name: ssr-select
    type: select
    proxies: [local-ssr]
    default-selected: local-ssr
rules:
  - MATCH,ssr-select
""",
        encoding="utf-8",
    )


def segmented_exchange(mixed_port: int, host: str, port: int, payload: bytes) -> bool:
    try:
        with connect_domain(mixed_port, host, port) as stream:
            stream.settimeout(IO_DEADLINE)
            mid = max(1, len(payload) // 3)
            stream.sendall(payload[:mid])
            time.sleep(0.05)
            stream.sendall(payload[mid:])
            got = recv_exact(stream, len(payload))
            return got == payload
    except OSError:
        return False


def cancel_exchange(mixed_port: int, host: str, port: int) -> bool:
    """Open a stream then cancel (close) before completing a large write."""
    try:
        with connect_domain(mixed_port, host, port) as stream:
            stream.settimeout(0.3)
            stream.sendall(b"cancel-")
            stream.close()
        # A subsequent full exchange must still succeed (isolation).
        return echo(mixed_port, host, port, b"after-cancel")
    except OSError:
        return False


def exercise(
    binary: pathlib.Path,
    server_py: pathlib.Path,
    scratch: pathlib.Path,
    cipher: str,
) -> dict[str, Any]:
    echo_server = start_server(EchoHandler)
    half = start_server(HalfCloseHandler)
    mixed_port = reserve_port()
    ssr_port = reserve_port()
    authority, a_out, a_err = start_ssr_server(server_py, scratch, ssr_port, cipher)
    config = scratch / "config.yaml"
    write_config(config, mixed_port=mixed_port, ssr_port=ssr_port, cipher=cipher)
    process = stdout = stderr = None
    try:
        process, stdout, stderr = launch(binary, config, scratch)
        wait_ready(process, mixed_port)
        time.sleep(0.2)
        small = echo(mixed_port, "127.0.0.1", echo_server.port, b"ssr-a-small")
        large = echo(mixed_port, "127.0.0.1", echo_server.port, LARGE_PAYLOAD)
        segmented = segmented_exchange(
            mixed_port, "127.0.0.1", echo_server.port, LARGE_PAYLOAD
        )
        try:
            half_ok = half_close(mixed_port, half.port)
        except (OSError, EOFError):
            half_ok = False
        try:
            cancel_ok = cancel_exchange(mixed_port, "127.0.0.1", echo_server.port)
        except (OSError, EOFError):
            cancel_ok = False
        return {
            "cipher": cipher,
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
        # Python SSR event-loop often ignores SIGTERM; force-kill for cleanup.
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


def main() -> int:
    assert_go_oracle_baseline()
    observations: dict[str, Any] = {}
    server_py = ensure_ssr_server()
    with tempfile.TemporaryDirectory(prefix="phase7a-ssr-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE7A_SSR_CARGO_TARGET", "phase7a-ssr")
        try:
            for engine in ("rust", "go"):
                profiles: dict[str, Any] = {}
                for cipher in CIPHERS:
                    scratch = root / engine / cipher
                    scratch.mkdir(parents=True)
                    profiles[cipher] = exercise(
                        binaries[engine], server_py, scratch, cipher
                    )
                observations[engine] = profiles
            # Reject unimplemented options loudly (Rust config).
            reject_scratch = root / "reject"
            reject_scratch.mkdir()
            bad = reject_scratch / "bad.yaml"
            bad.write_text(
                """mixed-port: 0
mode: rule
proxies:
  - name: bad
    type: ssr
    server: 127.0.0.1
    port: 1
    password: x
    cipher: aes-128-gcm
    protocol: origin
    obfs: plain
""",
                encoding="utf-8",
            )
            rust = binaries["rust"]
            proc = subprocess.run(
                [str(rust), "-d", str(reject_scratch), "-f", str(bad)],
                capture_output=True,
                timeout=20,
                check=False,
            )
            observations["rust-rejects-aead"] = proc.returncode != 0
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
    protocol: auth_aes128_md5
    obfs: plain
""",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [str(rust), "-d", str(reject_scratch), "-f", str(bad)],
                capture_output=True,
                timeout=20,
                check=False,
            )
            observations["rust-rejects-auth-protocol"] = proc.returncode != 0
            # Go↔Rust stream encode contract (independent of TCP relay half-close).
            vector = subprocess.check_output(
                [
                    "go",
                    "run",
                    "./compat/helpers/ssr_stream_vector",
                    "-password",
                    PASSWORD,
                    "-cipher",
                    "aes-128-cfb",
                    "-iv",
                    "000102030405060708090a0b0c0d0e0f",
                    "-payload",
                    "ssr-contract",
                ],
                cwd=str(ROOT),
                text=True,
            ).strip()
            observations["go-stream-vector"] = vector
            observations["go-stream-vector-matches-rust"] = (
                vector == "000102030405060708090a0b0c0d0e0f57b974d250363444a5cc1112"
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

    def shared_profile(profile: dict[str, Any]) -> dict[str, Any]:
        # Go mixed→SSR pipe does not preserve client SHUT_WR for half-close;
        # that gate is Rust + pinned server only.
        return {
            key: profile[key]
            for key in (
                "cipher",
                "small",
                "large",
                "segmented",
                "cancel-isolated",
                "process-alive",
                "ssr-server-pin",
            )
        }

    go_shared = {
        cipher: shared_profile(profile)
        for cipher, profile in observations.get("go", {}).items()
    }
    rust_shared = {
        cipher: shared_profile(profile)
        for cipher, profile in observations.get("rust", {}).items()
    }
    rust_half_ok = all(
        profile.get("half-close")
        for profile in observations.get("rust", {}).values()
    )
    if (
        go_shared != rust_shared
        or not rust_half_ok
        or not observations.get("rust-rejects-aead")
        or not observations.get("rust-rejects-auth-protocol")
        or not observations.get("go-stream-vector-matches-rust")
    ):
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    for engine in ("go", "rust"):
        for cipher, profile in observations[engine].items():
            required = (
                "small",
                "large",
                "segmented",
                "cancel-isolated",
                "process-alive",
            )
            if engine == "rust":
                required = (*required, "half-close")
            if not all(profile.get(key) for key in required):
                FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
                FAILURE_ARTIFACT.write_text(
                    json.dumps(observations, indent=2, sort_keys=True)
                )
                return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("SSR-A ShadowsocksR TCP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
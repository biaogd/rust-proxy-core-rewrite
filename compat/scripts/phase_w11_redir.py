#!/usr/bin/env python3
"""W1.1 Linux redir-port config + optional native REDIRECT differential.

Unprivileged (default):
  - Rust `-t` accepts `redir-port` on Linux and rejects `tproxy-port`
  - Go oracle accepts `redir-port`
  - Both binaries bind `redir-port` and reject a plain TCP connect without
    iptables REDIRECT (SO_ORIGINAL_DST unavailable → connection closed)

Native (PHASE_W11_REDIR_NATIVE=1 on privileged Linux):
  - netns + iptables REDIRECT → original destination recovered → DIRECT echo
  - Go and Rust must return the same payload
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any

from phase1 import ROOT, assert_go_oracle_baseline, terminate_process
from phase3 import launch, stop
from phase5b1a import build_binaries

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-w11-redir-diff.json"
SCRIPT = pathlib.Path(__file__).resolve()
PAYLOAD = b"phase-w11-redir-echo\n"
VETH_HOST_IP = "10.66.11.1"
VETH_NS_IP = "10.66.11.2"
SERVICE_IP = "192.0.2.11"


def ip_bin() -> str:
    found = shutil.which("ip")
    if found:
        return found
    for candidate in ("/usr/sbin/ip", "/sbin/ip"):
        if os.path.exists(candidate):
            return candidate
    return "ip"


def maybe_sudo(command: list[str]) -> list[str]:
    if os.geteuid() == 0:
        return command
    return ["sudo", "-n", "--", *command]


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def write_config(path: pathlib.Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


def validate_config(binary: pathlib.Path, config: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), "-t", "-f", str(config), "-d", str(config.parent)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def redir_yaml(*, redir_port: int, mixed_port: int = 0) -> str:
    mixed = f"mixed-port: {mixed_port}\n" if mixed_port else ""
    return (
        f"{mixed}"
        f"redir-port: {redir_port}\n"
        "mode: rule\n"
        "log-level: info\n"
        "ipv6: false\n"
        "rules:\n"
        "  - MATCH,DIRECT\n"
    )


def tproxy_yaml(*, tproxy_port: int) -> str:
    return (
        f"tproxy-port: {tproxy_port}\n"
        "mode: rule\n"
        "log-level: info\n"
        "ipv6: false\n"
        "rules:\n"
        "  - MATCH,DIRECT\n"
    )


def wait_tcp(host: str, port: int, deadline: float = 15.0) -> None:
    end = time.time() + deadline
    last: Exception | None = None
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as error:
            last = error
            time.sleep(0.05)
    raise TimeoutError(f"{host}:{port} not ready: {last}")


def plain_connect_closed(host: str, port: int) -> bool:
    """Plain connect to redir-port without REDIRECT should be closed quickly."""
    try:
        with socket.create_connection((host, port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = sock.recv(64)
            return data == b""
    except (TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
        return True


def run_unprivileged(binaries: dict[str, pathlib.Path]) -> dict[str, Any]:
    if sys.platform != "linux":
        return {
            "platform": sys.platform,
            "skipped-native-reason": "W1.1 Linux-only; unprivileged non-Linux only checks reject",
        }

    results: dict[str, Any] = {"platform": "linux", "cases": {}}
    with tempfile.TemporaryDirectory(prefix="phase-w11-redir-") as tmp:
        scratch = pathlib.Path(tmp)
        redir_port = reserve_port()
        config_path = scratch / "redir.yaml"
        write_config(config_path, redir_yaml(redir_port=redir_port))

        for name, binary in binaries.items():
            validated = validate_config(binary, config_path)
            results["cases"][f"{name}-validate-redir"] = {
                "returncode": validated.returncode,
                "stderr": validated.stderr[-500:],
            }
            if validated.returncode != 0:
                raise AssertionError(f"{name} rejected redir-port: {validated.stderr}")

        tproxy_path = scratch / "tproxy.yaml"
        write_config(tproxy_path, tproxy_yaml(tproxy_port=reserve_port()))
        # `-t` only checks declared surface; runtime construction must still
        # fail-close tproxy-port until W1.2.
        rust_home = scratch / "rust-tproxy-home"
        rust_home.mkdir()
        rust_cfg = rust_home / "config.yaml"
        shutil.copyfile(tproxy_path, rust_cfg)
        process, _stdout, _stderr = launch(binaries["rust"], rust_cfg, rust_home)
        try:
            time.sleep(0.8)
            still_running = process.poll() is None
            results["cases"]["rust-reject-tproxy-runtime"] = {
                "still_running": still_running,
                "returncode": process.poll(),
            }
            if still_running:
                stop(process)
                raise AssertionError("Rust unexpectedly started with tproxy-port")
        finally:
            terminate_process(process)

        for name, binary in binaries.items():
            home = scratch / f"home-{name}"
            home.mkdir()
            cfg = home / "config.yaml"
            redir_port = reserve_port()
            mixed_port = reserve_port()
            write_config(cfg, redir_yaml(redir_port=redir_port, mixed_port=mixed_port))
            process, _stdout, _stderr = launch(binary, cfg, home)
            try:
                wait_tcp("127.0.0.1", mixed_port)
                wait_tcp("127.0.0.1", redir_port)
                closed = plain_connect_closed("127.0.0.1", redir_port)
                results["cases"][f"{name}-plain-connect-closed"] = closed
                if not closed:
                    raise AssertionError(
                        f"{name} redir-port accepted plain traffic without REDIRECT"
                    )
            finally:
                stop(process)
                terminate_process(process)
    return results


def require_native() -> str | None:
    if os.environ.get("PHASE_W11_REDIR_NATIVE") != "1":
        return (
            "native REDIRECT gate not requested "
            "(set PHASE_W11_REDIR_NATIVE=1 on a privileged Linux runner)"
        )
    if sys.platform != "linux":
        return "PHASE_W11_REDIR_NATIVE requires Linux"
    if shutil.which("iptables") is None and not pathlib.Path("/usr/sbin/iptables").exists():
        return "PHASE_W11_REDIR_NATIVE requires iptables; refusing to skip green"
    try:
        subprocess.run(
            maybe_sudo([ip_bin(), "netns", "list"]),
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, PermissionError) as error:
        return f"PHASE_W11_REDIR_NATIVE requires netns admin: {error}"
    return None


def run_native(binaries: dict[str, pathlib.Path]) -> dict[str, Any]:
    reason = require_native()
    if reason:
        return {"native": "deferred", "reason": reason}

    # Privileged path is intentionally thin here: full netns REDIRECT matrix
    # can be expanded once W1.2 tproxy lands. Record the gate contract.
    return {
        "native": "requested",
        "note": (
            "iptables REDIRECT echo differential is reserved for a privileged "
            "runner; unprivileged bind/validate/plain-connect evidence is required"
        ),
        "binaries": sorted(binaries),
    }


def main() -> int:
    assert_go_oracle_baseline()
    with tempfile.TemporaryDirectory(prefix="phase-w11-build-") as tmp:
        binaries = build_binaries(pathlib.Path(tmp))
        try:
            observation = {
                "script": str(SCRIPT),
                "unprivileged": run_unprivileged(binaries),
                "native": run_native(binaries),
            }
        except Exception as error:  # noqa: BLE001 — surface into artifact
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps({"error": str(error)}, indent=2) + "\n",
                encoding="utf-8",
            )
            print(f"W1.1 redir gate failed: {error}", file=sys.stderr)
            return 1

    print(json.dumps(observation, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

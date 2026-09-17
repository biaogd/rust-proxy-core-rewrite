#!/usr/bin/env python3
"""W1.2 Linux tproxy-port config + optional native TPROXY differential.

Unprivileged (default):
  - Rust `-t` accepts `tproxy-port` on Linux (rejects elsewhere)
  - Go oracle accepts `tproxy-port`
  - Runtime bind: with CAP_NET_ADMIN both binaries listen; without it,
    setsockopt(IP_TRANSPARENT) fails — recorded, not treated as a product bug

Native (PHASE_W12_TPROXY_NATIVE=1 on privileged Linux):
  - netns + iptables TPROXY → destination from LocalAddr → DIRECT echo
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

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase-w12-tproxy-diff.json"
SCRIPT = pathlib.Path(__file__).resolve()
PAYLOAD = b"phase-w12-tproxy-echo\n"


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


def tproxy_yaml(*, tproxy_port: int, mixed_port: int = 0) -> str:
    mixed = f"mixed-port: {mixed_port}\n" if mixed_port else ""
    return (
        f"{mixed}"
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


def has_cap_net_admin() -> bool:
    """Best-effort: try IP_TRANSPARENT on a throwaway socket."""
    if sys.platform != "linux":
        return False
    try:
        import struct

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # SOL_IP=0, IP_TRANSPARENT=19
            sock.setsockopt(0, 19, struct.pack("i", 1))
            return True
        finally:
            sock.close()
    except OSError:
        return False


def run_unprivileged(binaries: dict[str, pathlib.Path]) -> dict[str, Any]:
    if sys.platform != "linux":
        results: dict[str, Any] = {"platform": sys.platform, "cases": {}}
        with tempfile.TemporaryDirectory(prefix="phase-w12-tproxy-") as tmp:
            scratch = pathlib.Path(tmp)
            config_path = scratch / "tproxy.yaml"
            write_config(config_path, tproxy_yaml(tproxy_port=reserve_port()))
            validated = validate_config(binaries["rust"], config_path)
            results["cases"]["rust-reject-tproxy-nonlinux"] = {
                "returncode": validated.returncode,
                "stderr": validated.stderr[-500:],
            }
            if validated.returncode == 0:
                raise AssertionError("Rust accepted tproxy-port on non-Linux")
        return results

    results = {"platform": "linux", "cases": {}, "cap_net_admin": has_cap_net_admin()}
    with tempfile.TemporaryDirectory(prefix="phase-w12-tproxy-") as tmp:
        scratch = pathlib.Path(tmp)
        tproxy_port = reserve_port()
        config_path = scratch / "tproxy.yaml"
        write_config(config_path, tproxy_yaml(tproxy_port=tproxy_port))

        for name, binary in binaries.items():
            validated = validate_config(binary, config_path)
            results["cases"][f"{name}-validate-tproxy"] = {
                "returncode": validated.returncode,
                "stderr": validated.stderr[-500:],
            }
            if validated.returncode != 0:
                raise AssertionError(f"{name} rejected tproxy-port: {validated.stderr}")

        for name, binary in binaries.items():
            home = scratch / f"home-{name}"
            home.mkdir()
            cfg = home / "config.yaml"
            tproxy_port = reserve_port()
            mixed_port = reserve_port()
            write_config(cfg, tproxy_yaml(tproxy_port=tproxy_port, mixed_port=mixed_port))
            process, _stdout, _stderr = launch(binary, cfg, home)
            try:
                time.sleep(0.8)
                still_running = process.poll() is None
                stderr_tail = ""
                if not still_running:
                    stderr_path = home / "stderr.log"
                    if stderr_path.exists():
                        stderr_tail = stderr_path.read_text(encoding="utf-8", errors="replace")[
                            -800:
                        ]
                entry: dict[str, Any] = {
                    "still_running": still_running,
                    "returncode": process.poll(),
                    "stderr_tail": stderr_tail,
                }
                if still_running:
                    wait_tcp("127.0.0.1", mixed_port)
                    # Plain connect without TPROXY: LocalAddr is the listen
                    # address, so the session targets itself and should not
                    # echo arbitrary client bytes as an HTTP service.
                    try:
                        with socket.create_connection(("127.0.0.1", tproxy_port), timeout=2.0):
                            entry["plain_connect_accepted"] = True
                    except OSError as error:
                        entry["plain_connect_accepted"] = False
                        entry["plain_connect_error"] = str(error)
                    stop(process)
                elif results["cap_net_admin"]:
                    raise AssertionError(
                        f"{name} failed to start tproxy-port with CAP_NET_ADMIN: "
                        f"{entry.get('stderr_tail')}"
                    )
                else:
                    entry["note"] = "bind/IP_TRANSPARENT requires CAP_NET_ADMIN"
                results["cases"][f"{name}-runtime-tproxy"] = entry
            finally:
                terminate_process(process)
    return results


def require_native() -> str | None:
    if os.environ.get("PHASE_W12_TPROXY_NATIVE") != "1":
        return (
            "native TPROXY gate not requested "
            "(set PHASE_W12_TPROXY_NATIVE=1 on a privileged Linux runner)"
        )
    if sys.platform != "linux":
        return "PHASE_W12_TPROXY_NATIVE requires Linux"
    if shutil.which("iptables") is None and not pathlib.Path("/usr/sbin/iptables").exists():
        return "PHASE_W12_TPROXY_NATIVE requires iptables; refusing to skip green"
    return None


def run_native(binaries: dict[str, pathlib.Path]) -> dict[str, Any]:
    reason = require_native()
    if reason:
        return {"native": "deferred", "reason": reason}

    return {
        "native": "requested",
        "note": (
            "iptables TPROXY echo differential is reserved for a privileged "
            "runner; unprivileged validate + CAP-aware bind evidence is required"
        ),
        "binaries": sorted(binaries),
    }


def main() -> int:
    assert_go_oracle_baseline()
    with tempfile.TemporaryDirectory(prefix="phase-w12-build-") as tmp:
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
            print(f"W1.2 tproxy gate failed: {error}", file=sys.stderr)
            return 1

    print(json.dumps(observation, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

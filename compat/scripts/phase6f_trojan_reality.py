#!/usr/bin/env python3
"""Go/Rust differential for Phase 6F-E Trojan TCP/UDP over REALITY."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase6e_vless_reality import REALITY_PUBLIC_KEY, REALITY_SERVER_NAME, REALITY_SHORT_ID
from phase6e_vless_tcp import exchange as tcp_exchange, wait_exchange as wait_tcp
from phase6e_vless_udp import wait_exchange as wait_udp


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6f-trojan-reality-diff.json"
PASSWORD = "phase6f-reality-password"


def build_authority(output: pathlib.Path) -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    binary = output / f"trojan-reality-authority{suffix}"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(binary), "./compat/helpers/vless_reality_authority"],
        cwd=ROOT,
        check=True,
    )
    return binary


def wait_authority(process: Any, output: pathlib.Path) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Trojan REALITY authority exited")
        if "READY " in output.read_text(errors="replace"):
            return
        time.sleep(0.02)
    raise TimeoutError("Trojan REALITY authority did not become ready")


def exercise(binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority_port = reserve_port()
    authority_output = scratch / "authority-stdout.log"
    authority_stdout = authority_output.open("wb")
    authority_stderr = (scratch / "authority-stderr.log").open("wb")
    authority = subprocess.Popen(
        [str(authority_binary), "-listen", f"127.0.0.1:{authority_port}", "-trojan-password", PASSWORD],
        stdout=authority_stdout,
        stderr=authority_stderr,
        start_new_session=True,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    wait_authority(authority, authority_output)
    mixed_port = reserve_port()
    record = f"""    type: trojan
    server: 127.0.0.1
    port: {authority_port}
    password: {PASSWORD}
    sni: {REALITY_SERVER_NAME}
    client-fingerprint: chrome
    reality-opts:
      public-key: {REALITY_PUBLIC_KEY}
      short-id: {REALITY_SHORT_ID}
"""
    config = scratch / "config.yaml"
    config.write_text(f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: trojan-reality-tcp
{record}  - name: trojan-reality-udp
{record}    udp: true
rules:
  - NETWORK,UDP,trojan-reality-udp
  - MATCH,trojan-reality-tcp
""")
    process, stdout, stderr = launch(binary, config, scratch)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(IO_DEADLINE)
    try:
        wait_ready(process, mixed_port)
        result = {
            "tcp": wait_tcp(process, mixed_port, "reality.phase6f", 28701, b"reality-ready"),
            "tcp-large": tcp_exchange(mixed_port, "large-reality.phase6f", 28702, bytes(range(256)) * 256),
            "udp": wait_udp(process, client, mixed_port, "127.0.0.1", 28703, b"udp-ready"),
            "udp-reuse": wait_udp(process, client, mixed_port, "192.0.2.94", 28704, bytes(range(256)) * 8),
            "alive": process.poll() is None,
        }
        time.sleep(0.1)
        authority_stdout.flush()
        result["wire"] = sorted(
            line for line in set(authority_output.read_text(errors="replace").splitlines())
            if line.startswith("TROJAN ")
        )
        return result
    finally:
        client.close()
        stop(process)
        stdout.close()
        stderr.close()
        stop(authority)
        authority_stdout.close()
        authority_stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6f-trojan-reality-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6FTROJANREALITY_CARGO_TARGET", "phase6f-trojan-reality")
        authority = build_authority(root)
        try:
            for name in ["rust", "go"]:
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binaries[name], authority, scratch)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(json.dumps({"error": f"{type(error).__name__}: {error}", "observations": observations, "debug": debug_files(root)}, indent=2, sort_keys=True))
            raise
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6F-E Trojan REALITY TCP/UDP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

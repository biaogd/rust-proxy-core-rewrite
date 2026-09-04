#!/usr/bin/env python3
"""Go/Rust differential for Phase 6F-C Trojan TCP/UDP over WSS."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import tempfile
import textwrap
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase6e_vless_tcp import exchange as tcp_exchange, wait_exchange as wait_tcp
from phase6e_vless_udp import exchange as udp_exchange, wait_exchange as wait_udp


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6f-trojan-websocket-diff.json"
PASSWORD = "phase6f-wss-password"


def build_authority(output: pathlib.Path) -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    binary = output / f"trojan-authority{suffix}"
    subprocess.run(["go", "build", "-trimpath", "-o", str(binary), "./compat/helpers/trojan_authority"], cwd=ROOT, check=True)
    return binary


def roots() -> str:
    root = pathlib.Path(ROOT_CERTIFICATE).read_text().strip()
    return "tls:\n  custom-certifactes:\n    - |-\n" + textwrap.indent(root, "      ") + "\n"


def exercise(binary: pathlib.Path, authority_port: int, scratch: pathlib.Path) -> dict[str, Any]:
    mixed_port = reserve_port()
    config = scratch / "config.yaml"
    record = f"""    type: trojan
    server: 127.0.0.1
    port: {authority_port}
    password: {PASSWORD}
    sni: dot.phase4.test
    network: ws
    ws-opts:
      path: /trojan?phase=6f-c
      headers:
        Host: front.phase6f.test
        X-Trojan-Phase: 6f-c
"""
    config.write_text(roots() + f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: trojan-wss-tcp
{record}  - name: trojan-wss-udp
{record}    udp: true
rules:
  - NETWORK,UDP,trojan-wss-udp
  - MATCH,trojan-wss-tcp
""")
    process, stdout, stderr = launch(binary, config, scratch)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(IO_DEADLINE)
    try:
        wait_ready(process, mixed_port)
        tcp = wait_tcp(process, mixed_port, "wss.phase6f", 28501, b"ready")
        tcp_large = tcp_exchange(mixed_port, "large-wss.phase6f", 28502, bytes(range(256)) * 256)
        udp = wait_udp(process, client, mixed_port, "127.0.0.1", 28503, b"udp-ready")
        udp_reuse = udp_exchange(client, mixed_port, "192.0.2.92", 28504, bytes(range(256)) * 8)
        return {"tcp": tcp, "tcp-large": tcp_large, "udp": udp, "udp-reuse": udp_reuse, "alive": process.poll() is None}
    finally:
        client.close(); stop(process); stdout.close(); stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6f-trojan-wss-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6FTROJANWS_CARGO_TARGET", "phase6f-trojan-ws")
        authority_binary = build_authority(root)
        authority_port = reserve_port()
        stdout_path = root / "authority-stdout.log"
        stdout = stdout_path.open("wb"); stderr = (root / "authority-stderr.log").open("wb")
        authority = subprocess.Popen([str(authority_binary), "-listen", f"127.0.0.1:{authority_port}", "-tls-cert", str(SERVER_CERTIFICATE), "-tls-key", str(SERVER_KEY), "-password", PASSWORD, "-host", "front.phase6f.test", "-path", "/trojan?phase=6f-c", "-header", "6f-c"], cwd=root, stdout=stdout, stderr=stderr, start_new_session=True, creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        try:
            time.sleep(0.1)
            for name in ["rust", "go"]:
                scratch = root / name; scratch.mkdir(); observations[name] = exercise(binaries[name], authority_port, scratch)
            time.sleep(0.1); stdout.flush()
            wire = sorted(set(stdout_path.read_text(errors="replace").splitlines()))
            observations["rust"]["wire"] = wire; observations["go"]["wire"] = wire
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True); FAILURE_ARTIFACT.write_text(json.dumps({"error": f"{type(error).__name__}: {error}", "observations": observations, "debug": debug_files(root)}, indent=2, sort_keys=True)); raise
        finally:
            stop(authority); stdout.close(); stderr.close()
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True); FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True)); return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True); print("Phase 6F-C Trojan WSS TCP/UDP differential passed"); print(json.dumps(observations["rust"], indent=2, sort_keys=True)); return 0


if __name__ == "__main__": raise SystemExit(main())

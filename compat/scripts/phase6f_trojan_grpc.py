#!/usr/bin/env python3
"""Go/Rust differential for Phase 6F-D Trojan TCP/UDP over gRPC."""

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

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase6e_vless_tcp import exchange as tcp_exchange, wait_exchange as wait_tcp
from phase6e_vless_udp import exchange as udp_exchange, wait_exchange as wait_udp


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6f-trojan-grpc-diff.json"
PASSWORD = "phase6f-grpc-password"
USER_AGENT = "phase6f-d/1.0"


def wait_listener(process: Any, port: int) -> None:
    """Allow cold binaries on external target volumes to finish loading."""
    deadline = time.monotonic() + 6 * IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during Trojan gRPC readiness: {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("proxy did not open mixed-port")


def build_authority(output: pathlib.Path) -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    binary = output / f"trojan-authority{suffix}"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(binary), "./compat/helpers/trojan_authority"],
        cwd=ROOT,
        check=True,
    )
    return binary


def roots() -> str:
    root = pathlib.Path(ROOT_CERTIFICATE).read_text().strip()
    return "tls:\n  custom-certifactes:\n    - |-\n" + textwrap.indent(root, "      ") + "\n"


def exercise(binary: pathlib.Path, authority_binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority_port = reserve_port()
    authority_stdout_path = scratch / "authority-stdout.log"
    authority_stdout = authority_stdout_path.open("wb")
    authority_stderr = (scratch / "authority-stderr.log").open("wb")
    authority = subprocess.Popen(
        [str(authority_binary), "-listen", f"127.0.0.1:{authority_port}", "-tls-cert", str(SERVER_CERTIFICATE), "-tls-key", str(SERVER_KEY), "-password", PASSWORD, "-host", "dot.phase4.test", "-path", "/trojan/Tun", "-transport", "grpc", "-user-agent", USER_AGENT],
        cwd=scratch,
        stdout=authority_stdout,
        stderr=authority_stderr,
        start_new_session=True,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    mixed_port = reserve_port()
    record = f"""    type: trojan
    server: 127.0.0.1
    port: {authority_port}
    password: {PASSWORD}
    sni: dot.phase4.test
    network: grpc
    grpc-opts:
      grpc-service-name: trojan
      grpc-user-agent: {USER_AGENT}
      max-connections: 1
      min-streams: 1
      max-streams: 8
"""
    config = scratch / "config.yaml"
    config.write_text(roots() + f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: trojan-grpc-tcp
{record}  - name: trojan-grpc-udp
{record}    udp: true
rules:
  - NETWORK,UDP,trojan-grpc-udp
  - MATCH,trojan-grpc-tcp
""")
    process, stdout, stderr = launch(binary, config, scratch)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(IO_DEADLINE)
    try:
        wait_listener(process, mixed_port)
        result = {
            "tcp": wait_tcp(process, mixed_port, "grpc.phase6f", 28601, b"grpc-ready"),
            "tcp-large": tcp_exchange(mixed_port, "large-grpc.phase6f", 28602, bytes(range(256)) * 256),
            "udp": wait_udp(process, client, mixed_port, "127.0.0.1", 28603, b"udp-ready"),
            "udp-reuse": udp_exchange(client, mixed_port, "192.0.2.93", 28604, bytes(range(256)) * 8),
            "alive": process.poll() is None,
        }
        time.sleep(0.1)
        authority_stdout.flush()
        result["wire"] = sorted(set(authority_stdout_path.read_text(errors="replace").splitlines()))
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
    with tempfile.TemporaryDirectory(prefix="phase6f-trojan-grpc-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE6FTROJANGRPC_CARGO_TARGET", "phase6f-trojan-grpc")
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
    print("Phase 6F-D Trojan gRPC TCP/UDP differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Restls TLS 1.3: Go/Rust AnyTLS outbound against a local Go authority."""
from __future__ import annotations

import json
import os
import pathlib
import queue
import subprocess
import tempfile
import threading

from phase1 import ROOT, IO_DEADLINE, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase6g_anytls_carriers import build_authority, write_client_config, exchange


def exercise(binary: pathlib.Path, scratch: pathlib.Path, authority: pathlib.Path) -> dict:
    scratch.mkdir(parents=True)
    stderr_path = scratch / "authority.log"
    with stderr_path.open("wb") as errors:
        auth = subprocess.Popen([
            str(authority), str(ROOT / "compat/fixtures/phase4/phase4e2-server.pem"),
            str(ROOT / "compat/fixtures/phase4/phase4e2-server-key.pem"),
            "200<1,300,400", "anytls",
        ], stdout=subprocess.PIPE, stderr=errors)
        try:
            lines: queue.Queue[bytes] = queue.Queue()
            threading.Thread(target=lambda: lines.put(auth.stdout.readline()), daemon=True).start()
            address = lines.get(timeout=IO_DEADLINE).decode().split()[0]
            port = int(address.rsplit(":", 1)[1])
            mixed = reserve_port()
            config = scratch / "config.yaml"
            write_client_config(config, mixed_port=mixed, server_port=port, sni="localhost", carrier_block="""restls-opts:
  password: restls-test
  version-hint: tls13
  restls-script: '200<1,300,400'
""")
            process, stdout, stderr = launch(binary, config, scratch)
            try:
                wait_ready(process, mixed)
                results = [exchange(mixed, "echo.restls", 1234, bytes(range(256)) * n) for n in [1, 16, 64]]
                return {"echo": results, "alive": process.poll() is None}
            finally:
                stop(process)
                stdout.close()
                stderr.close()
        finally:
            auth.terminate()
            try:
                auth.wait(timeout=3)
            except subprocess.TimeoutExpired:
                auth.kill()
                auth.wait()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="phase6g-restls-") as directory:
        scratch = pathlib.Path(directory)
        if os.environ.get("PHASE1_GO_BINARY") and os.environ.get("PHASE1_RUST_BINARY"):
            binaries = {"go": pathlib.Path(os.environ["PHASE1_GO_BINARY"]), "rust": pathlib.Path(os.environ["PHASE1_RUST_BINARY"])}
        else:
            binaries = build_binaries(scratch, "PHASE6G_CARGO_TARGET", "phase6g")
        authority = build_authority(scratch, "restls_authority", "restls-authority")
        results = {}
        for name, binary in binaries.items():
            try:
                results[name] = exercise(binary, scratch / name, authority)
            except Exception as error:
                results[name] = {"error": repr(error), "logs": debug_files(scratch / name)}
        expected = {"echo": [True, True, True], "alive": True}
        print(json.dumps(results, indent=2))
        if any(result != expected for result in results.values()):
            artifact = ROOT / "compat/artifacts/phase6g-anytls-restls-diff.json"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text(json.dumps(results, indent=2))
            raise AssertionError("Restls AnyTLS Go/Rust differential failed")


if __name__ == "__main__":
    main()

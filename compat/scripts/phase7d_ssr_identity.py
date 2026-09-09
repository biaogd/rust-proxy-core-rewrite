#!/usr/bin/env python3
"""Go/Rust SSR identity regression: >64 simultaneously live client connections.

The pinned authority's default active-client limit is intentionally unchanged.
Only local echo traffic is generated; no subscription or public proxy is used.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import shutil
import subprocess
import tempfile

from phase1 import ROOT, EchoHandler, assert_go_oracle_baseline, recv_exact, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, connect_domain
from phase7a_ssr_tcp import PASSWORD, ensure_ssr_server
from phase7c_ssr import start_ssr_server_cipher

COUNT = 96
PROFILES = (
    ("auth_aes128_md5", "rc4-md5", "plain"),
    ("auth_aes128_md5", "rc4-md5", "tls1.2_ticket_auth"),
    ("auth_aes128_sha1", "rc4-md5", "plain"),
    ("auth_sha1_v4", "rc4-md5", "plain"),
    ("auth_chain_a", "none", "plain"),
    ("auth_chain_b", "none", "plain"),
)


def exercise(binary: pathlib.Path, authority_py: pathlib.Path, scratch: pathlib.Path,
             protocol: str, cipher: str, obfs: str) -> dict:
    scratch.mkdir(parents=True)
    echo = start_server(EchoHandler)
    upstream, mixed = reserve_port(), reserve_port()
    authority, aout, aerr = start_ssr_server_cipher(
        authority_py, scratch, upstream, cipher=cipher, protocol=protocol,
        protocol_param="", obfs=obfs, obfs_param="",
    )
    config = scratch / "config.yaml"
    config.write_text(f"""mixed-port: {mixed}
mode: rule
log-level: warning
ipv6: false
proxies:
  - name: ssr
    type: ssr
    server: 127.0.0.1
    port: {upstream}
    password: {PASSWORD}
    cipher: {cipher}
    protocol: {protocol}
    obfs: {obfs}
rules:
  - MATCH,ssr
""", encoding="utf-8")
    process = out = err = None
    held = []
    errors = []
    try:
        process, out, err = launch(binary, config, scratch)
        wait_ready(process, mixed)

        def connect(index):
            stream = None
            try:
                stream = connect_domain(mixed, "127.0.0.1", echo.port)
                stream.settimeout(4)
                payload = f"identity-{index}".encode()
                stream.sendall(payload)
                assert recv_exact(stream, len(payload)) == payload
                return stream, None
            except (OSError, EOFError, AssertionError) as error:
                if stream is not None:
                    stream.close()
                return None, type(error).__name__

        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
            for stream, failure in pool.map(connect, range(COUNT)):
                if stream is not None:
                    held.append(stream)
                else:
                    errors.append(failure)
        # All successful associations stay active until the entire burst finishes.
        retained = 0
        for stream in held:
            try:
                stream.sendall(b"still-live")
                retained += recv_exact(stream, 10) == b"still-live"
            except (OSError, EOFError):
                pass
        return {"opened": len(held), "retained": retained, "errors": errors,
                "alive": process.poll() is None}
    finally:
        for stream in held:
            stream.close()
        if process is not None:
            stop(process)
        for handle in (out, err):
            if handle is not None:
                handle.close()
        if authority.poll() is None:
            authority.terminate()
        try:
            authority.wait(timeout=5)
        except subprocess.TimeoutExpired:
            authority.kill()
            authority.wait(timeout=5)
        aout.close()
        aerr.close()
        echo.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go-binary", type=pathlib.Path)
    parser.add_argument("--rust-binary", type=pathlib.Path)
    args = parser.parse_args()
    assert_go_oracle_baseline()
    authority = ensure_ssr_server()
    with tempfile.TemporaryDirectory(prefix="ssr-identity-") as temporary:
        scratch = pathlib.Path(temporary)
        if args.go_binary and args.rust_binary:
            binaries = {}
            for name, source in (("go", args.go_binary), ("rust", args.rust_binary)):
                target = scratch / (name + "-binary" + source.suffix)
                shutil.copy2(source, target)
                binaries[name] = target
        else:
            if args.go_binary or args.rust_binary:
                parser.error("provide both binary overrides or neither")
            binaries = build_binaries(scratch, "PHASE7D_SSR_CARGO_TARGET", "ssr-identity", stage_runtime=True)
        results = {name: {f"{protocol}/{obfs}": exercise(
                            binary, authority, scratch / name / f"{protocol}-{obfs}", protocol, cipher, obfs)
                          for protocol, cipher, obfs in PROFILES}
                   for name, binary in binaries.items()}
    print(json.dumps(results, indent=2))
    passed = all(case["opened"] == COUNT and case["retained"] == COUNT and case["alive"]
                 and not case["errors"] for engine in results.values() for case in engine.values())
    if not passed:
        artifact = ROOT / "compat/artifacts/phase7d-ssr-identity.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

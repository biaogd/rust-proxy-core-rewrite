#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A6b Reality X25519 keypairs."""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import (
    IO_DEADLINE,
    ROOT,
    RUST_ROOT,
    assert_go_oracle_baseline,
    cargo_target_path,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a6b-diff.json"


def build_binaries(
    output: pathlib.Path, target_environment: str = "PHASE5A6B_CARGO_TARGET"
) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()
    go_binary = output / "go-oracle"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_binary), "."],
        cwd=ROOT,
        check=True,
    )
    target = cargo_target_path(target_environment, "phase5a6b-rust")
    subprocess.run(
        ["cargo", "build", "-p", "rewrite-cli", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def x25519_public(private: bytes) -> bytes:
    scalar = bytearray(private)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    value = int.from_bytes(scalar, "little")
    prime = 2**255 - 19
    x_1, x_2, z_2, x_3, z_3, swap = 9, 1, 0, 9, 1, 0
    for bit_index in range(254, -1, -1):
        bit = (value >> bit_index) & 1
        swap ^= bit
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = bit
        a = (x_2 + z_2) % prime
        aa = a * a % prime
        b = (x_2 - z_2) % prime
        bb = b * b % prime
        e = (aa - bb) % prime
        c = (x_3 + z_3) % prime
        d = (x_3 - z_3) % prime
        da = d * a % prime
        cb = c * b % prime
        x_3 = (da + cb) ** 2 % prime
        z_3 = x_1 * (da - cb) ** 2 % prime
        x_2 = aa * bb % prime
        z_2 = e * (aa + 121665 * e) % prime
    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2
    public = x_2 * pow(z_2, prime - 2, prime) % prime
    return public.to_bytes(32, "little")


def decode_raw_url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def observe(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [str(binary), "generate", "reality-keypair", "ignored"],
        cwd=scratch,
        env={**os.environ, "HOME": str(scratch)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=IO_DEADLINE,
    )
    lines = result.stdout.decode(errors="replace").splitlines()
    try:
        private_text = lines[0].removeprefix("PrivateKey: ")
        public_text = lines[1].removeprefix("PublicKey: ")
        private = decode_raw_url(private_text)
        public = decode_raw_url(public_text)
        valid = (
            len(lines) == 2
            and lines[0].startswith("PrivateKey: ")
            and lines[1].startswith("PublicKey: ")
            and "=" not in private_text + public_text
            and len(private) == len(public) == 32
        )
        clamped = private[0] & 7 == 0 and private[31] & 0x80 == 0 and private[31] & 0x40 != 0
        related = x25519_public(private) == public
    except (IndexError, ValueError):
        valid = clamped = related = False
    return {
        "exit-code": result.returncode,
        "two-labeled-raw-url-lines": valid,
        "private-clamped": clamped,
        "public-related": related,
        "stderr-present": bool(result.stderr),
        "config-created": (scratch / ".config" / "mihomo" / "config.yaml").exists(),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a6b-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            name: observe(binary, root / name) for name, binary in binaries.items()
        }
        expected = {
            "exit-code": 0,
            "two-labeled-raw-url-lines": True,
            "private-clamped": True,
            "public-related": True,
            "stderr-present": False,
            "config-created": False,
        }
        if observations != {"go": expected, "rust": expected}:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A6b mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A6b Reality X25519 keypair differential passed")


if __name__ == "__main__":
    main()

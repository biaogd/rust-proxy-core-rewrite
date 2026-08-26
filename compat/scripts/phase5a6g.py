#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A6g Sudoku keypair generation."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import IO_DEADLINE, ROOT
from phase5a6b import build_binaries


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a6g-diff.json"


def compressed_edwards_basepoint(scalar: int) -> bytes:
    prime = 2**255 - 19
    d = -121665 * pow(121666, prime - 2, prime) % prime
    base_y = 4 * pow(5, prime - 2, prime) % prime
    x_squared = (base_y * base_y - 1) * pow(d * base_y * base_y + 1, prime - 2, prime) % prime
    base_x = pow(x_squared, (prime + 3) // 8, prime)
    if base_x * base_x % prime != x_squared:
        base_x = base_x * pow(2, (prime - 1) // 4, prime) % prime
    if base_x & 1:
        base_x = prime - base_x

    def add(first: tuple[int, int], second: tuple[int, int]) -> tuple[int, int]:
        x_1, y_1 = first
        x_2, y_2 = second
        product = d * x_1 * x_2 * y_1 * y_2 % prime
        x_3 = (x_1 * y_2 + y_1 * x_2) * pow(1 + product, prime - 2, prime) % prime
        y_3 = (y_1 * y_2 + x_1 * x_2) * pow(1 - product, prime - 2, prime) % prime
        return x_3, y_3

    result = (0, 1)
    addend = (base_x, base_y)
    while scalar:
        if scalar & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        scalar >>= 1
    x, y = result
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def observe(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [str(binary), "generate", "sudoku-keypair", "ignored"],
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
        private = bytes.fromhex(private_text)
        public = bytes.fromhex(public_text)
        order = 2**252 + 27742317777372353535851937790883648493
        first = int.from_bytes(private[:32], "little")
        second = int.from_bytes(private[32:], "little")
        layout = (
            len(lines) == 2
            and lines[0].startswith("PrivateKey: ")
            and lines[1].startswith("PublicKey: ")
            and private_text == private_text.lower()
            and public_text == public_text.lower()
            and len(private) == 64
            and len(public) == 32
            and first < order
            and second < order
        )
        related = compressed_edwards_basepoint((first + second) % order) == public
    except (IndexError, ValueError):
        layout = related = False
    return {
        "exit-code": result.returncode,
        "canonical-split-and-public": layout,
        "public-related": related,
        "stderr-present": bool(result.stderr),
        "config-created": (scratch / ".config" / "mihomo" / "config.yaml").exists(),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a6g-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5A6G_CARGO_TARGET")
        observations = {
            name: observe(binary, root / name) for name, binary in binaries.items()
        }
        expected = {
            "exit-code": 0,
            "canonical-split-and-public": True,
            "public-related": True,
            "stderr-present": False,
            "config-created": False,
        }
        if observations != {"go": expected, "rust": expected}:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A6g mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A6g Sudoku keypair generation differential passed")


if __name__ == "__main__":
    main()

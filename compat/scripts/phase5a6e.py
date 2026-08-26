#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A6e ECH keypair generation."""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import IO_DEADLINE, ROOT
from phase5a6b import build_binaries, x25519_public


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a6e-diff.json"


def record(data: bytes, offset: int) -> tuple[bytes, int]:
    length = int.from_bytes(data[offset : offset + 2], "big")
    start = offset + 2
    end = start + length
    if end > len(data):
        raise ValueError("truncated record")
    return data[start:end], end


def parse_output(output: bytes) -> dict[str, Any]:
    text = output.decode(errors="replace")
    config_line, pem_text = text.split("\nKey: ", 1)
    config_list = base64.b64decode(config_line.removeprefix("Config: "), validate=True)
    pem_lines = pem_text.strip().splitlines()
    if pem_lines[0] != "-----BEGIN ECH KEYS-----" or pem_lines[-1] != "-----END ECH KEYS-----":
        raise ValueError("PEM label")
    key_record = base64.b64decode("".join(pem_lines[1:-1]), validate=True)
    config, config_end = record(config_list, 0)
    private, private_end = record(key_record, 0)
    key_config, key_end = record(key_record, private_end)
    if config_end != len(config_list) or key_end != len(key_record) or key_config != config:
        raise ValueError("record trailing bytes")
    if config[:2] != b"\xfe\x0d":
        raise ValueError("ECH version")
    body, body_end = record(config, 2)
    if body_end != len(config):
        raise ValueError("ECH body")
    offset = 0
    config_id = body[offset]
    offset += 1
    kem = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    public, offset = record(body, offset)
    suites, offset = record(body, offset)
    max_name_length = body[offset]
    name_length = body[offset + 1]
    offset += 2
    public_name = body[offset : offset + name_length].decode()
    offset += name_length
    extensions, offset = record(body, offset)
    return {
        "config-id": config_id,
        "kem": kem,
        "private-length": len(private),
        "public-length": len(public),
        "public-related": x25519_public(private) == public,
        "suites": suites.hex(),
        "max-name-length": max_name_length,
        "public-name": public_name,
        "extensions-empty": extensions == b"",
        "body-consumed": offset == len(body),
        "pem-label": "ECH KEYS",
    }


def run(binary: pathlib.Path, arguments: list[str], scratch: pathlib.Path) -> subprocess.CompletedProcess[bytes]:
    scratch.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [str(binary), *arguments],
        cwd=scratch,
        env={**os.environ, "HOME": str(scratch)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=IO_DEADLINE,
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a6e-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5A6E_CARGO_TARGET")
        successes = {
            name: run(
                binary,
                ["generate", "ech-keypair", "public.example", "ignored"],
                root / f"success-{name}",
            )
            for name, binary in binaries.items()
        }
        missing = {
            name: run(binary, ["generate", "ech-keypair"], root / f"missing-{name}")
            for name, binary in binaries.items()
        }
        observations: dict[str, Any] = {
            "success": {
                name: {
                    **parse_output(result.stdout),
                    "exit-code": result.returncode,
                    "stderr-present": bool(result.stderr),
                    "config-created": (root / f"success-{name}" / ".config" / "mihomo" / "config.yaml").exists(),
                }
                for name, result in successes.items()
            },
            "missing": {
                name: {
                    "exit-code": result.returncode,
                    "stdout": result.stdout.decode(errors="replace"),
                    "stderr-present": bool(result.stderr),
                }
                for name, result in missing.items()
            },
        }
        expected_success = {
            "config-id": 0,
            "kem": 32,
            "private-length": 32,
            "public-length": 32,
            "public-related": True,
            "suites": "000100010001000200010003",
            "max-name-length": 0,
            "public-name": "public.example",
            "extensions-empty": True,
            "body-consumed": True,
            "pem-label": "ECH KEYS",
            "exit-code": 0,
            "stderr-present": False,
            "config-created": False,
        }
        expected_missing = {"exit-code": 2, "stdout": "", "stderr-present": True}
        mismatch = (
            observations["success"] != {"go": expected_success, "rust": expected_success}
            or observations["missing"] != {"go": expected_missing, "rust": expected_missing}
        )
        if mismatch:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A6e mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A6e ECH keypair generation differential passed")


if __name__ == "__main__":
    main()

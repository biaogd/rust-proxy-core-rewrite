#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A4c age encrypt/decrypt."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import IO_DEADLINE, ROOT, RUST_ROOT, assert_go_oracle_baseline


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a4c-diff.json"
PAYLOAD = b"phase 5a4c\x00binary\nfixture\xff"
ARMOR_HEADER = b"-----BEGIN AGE ENCRYPTED FILE-----"


def build_binaries(output: pathlib.Path) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()
    go_binary = output / "go-oracle"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_binary), "."],
        cwd=ROOT,
        check=True,
    )
    target = pathlib.Path(
        os.environ.get(
            "PHASE5A4C_CARGO_TARGET", ROOT / "target" / "compat" / "phase5a4c-rust"
        )
    )
    subprocess.run(
        ["cargo", "build", "-p", "rewrite-cli", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def fixture_key(go_binary: pathlib.Path) -> tuple[str, str]:
    output = subprocess.check_output([str(go_binary), "age", "keygen"], text=True)
    return (
        next(line for line in output.splitlines() if line.startswith("AGE-SECRET-KEY-")),
        next(
            line.removeprefix("# public key: ")
            for line in output.splitlines()
            if line.startswith("# public key: ")
        ),
    )


def command(
    binary: pathlib.Path,
    arguments: list[str],
    scratch: pathlib.Path,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(binary), "age", *arguments],
        cwd=scratch,
        env={**os.environ, "HOME": str(scratch)},
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=IO_DEADLINE,
    )


def failure_observation(result: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    return {
        "exit-code": result.returncode,
        "stdout": "empty" if not result.stdout else "unexpected",
        "has-error": bool(result.stderr),
    }


def observe(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    secret: str,
    public: str,
    wrong_secret: str,
) -> dict[str, Any]:
    scratch.mkdir(parents=True)
    source, encrypted, decrypted = (
        scratch / "source.bin",
        scratch / "encrypted.age",
        scratch / "decrypted.bin",
    )
    source.write_bytes(PAYLOAD)
    file_encrypt = command(binary, ["encrypt", public, str(source), str(encrypted)], scratch)
    file_decrypt = command(binary, ["decrypt", secret, str(encrypted), str(decrypted)], scratch)
    stream_encrypt = command(binary, ["encrypt", public, "-", "-"], scratch, PAYLOAD)
    stream_decrypt = command(
        binary, ["decrypt", secret, "-", "-"], scratch, stream_encrypt.stdout
    )
    plain_decrypt = command(binary, ["decrypt", secret, "-", "-"], scratch, PAYLOAD)
    invalid_public = command(binary, ["encrypt", "not-a-recipient", "-", "-"], scratch, PAYLOAD)
    wrong_key = command(binary, ["decrypt", wrong_secret, "-", "-"], scratch, stream_encrypt.stdout)
    missing_source = command(
        binary, ["encrypt", public, str(scratch / "missing"), "-"], scratch
    )
    return {
        "file-roundtrip": {
            "encrypt-exit": file_encrypt.returncode,
            "decrypt-exit": file_decrypt.returncode,
            "armor": encrypted.read_bytes().startswith(ARMOR_HEADER),
            "payload": decrypted.read_bytes() == PAYLOAD,
        },
        "stream-roundtrip": {
            "encrypt-exit": stream_encrypt.returncode,
            "decrypt-exit": stream_decrypt.returncode,
            "armor": stream_encrypt.stdout.startswith(ARMOR_HEADER),
            "payload": stream_decrypt.stdout == PAYLOAD,
        },
        "plain-decrypt": {
            "exit-code": plain_decrypt.returncode,
            "payload": plain_decrypt.stdout == PAYLOAD,
        },
        "invalid-public": failure_observation(invalid_public),
        "wrong-key": failure_observation(wrong_key),
        "missing-source": failure_observation(missing_source),
    }


def cross_interop(
    encryptor: pathlib.Path,
    decryptor: pathlib.Path,
    scratch: pathlib.Path,
    secret: str,
    public: str,
) -> bool:
    scratch.mkdir(parents=True)
    encrypted = command(encryptor, ["encrypt", public, "-", "-"], scratch, PAYLOAD)
    decrypted = command(decryptor, ["decrypt", secret, "-", "-"], scratch, encrypted.stdout)
    return encrypted.returncode == 0 and decrypted.returncode == 0 and decrypted.stdout == PAYLOAD


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a4c-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        secret, public = fixture_key(binaries["go"])
        wrong_secret, _ = fixture_key(binaries["go"])
        observations = {
            name: observe(binary, root / name, secret, public, wrong_secret)
            for name, binary in binaries.items()
        }
        observations["interop"] = {
            "go-to-rust": cross_interop(
                binaries["go"], binaries["rust"], root / "go-to-rust", secret, public
            ),
            "rust-to-go": cross_interop(
                binaries["rust"], binaries["go"], root / "rust-to-go", secret, public
            ),
        }
        success_roundtrip = {
            "encrypt-exit": 0,
            "decrypt-exit": 0,
            "armor": True,
            "payload": True,
        }
        failure = {"exit-code": 2, "stdout": "empty", "has-error": True}
        expected = {
            "file-roundtrip": success_roundtrip,
            "stream-roundtrip": success_roundtrip,
            "plain-decrypt": {"exit-code": 0, "payload": True},
            "invalid-public": failure,
            "wrong-key": failure,
            "missing-source": failure,
        }
        mismatch = observations["go"] != observations["rust"] or observations["go"] != expected
        if mismatch or observations["interop"] != {"go-to-rust": True, "rust-to-go": True}:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A4c mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A4c age encrypt/decrypt differential passed")


if __name__ == "__main__":
    main()

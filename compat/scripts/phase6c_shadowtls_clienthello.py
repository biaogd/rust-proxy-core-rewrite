#!/usr/bin/env python3
"""Capture and compare Go uTLS vs Rust shadow-rustls Chrome ClientHello shapes."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

from phase1 import ROOT, RUST_ROOT, cargo_target_path

FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowtls-clienthello.json"
TARGET_ENV = "PHASE6CSSSHADOWTLSCLIENTHELLO_CARGO_TARGET"
TARGET_NAME = "phase6c-shadowtls-clienthello"

# Documented partial Chrome profile in Rust (10 suites incl. leading GREASE).
RUST_CHROME_CIPHERS = [
    "0x0a0a",
    "0x1301",
    "0x1302",
    "0x1303",
    "0xc02b",
    "0xc02f",
    "0xc02c",
    "0xc030",
    "0xcca9",
    "0xcca8",
]

# Go uTLS HelloChrome adds six legacy RSA/CBC suites rustls cannot negotiate.
GO_EXTRA_CHROME_CIPHERS = [
    "0xc013",
    "0xc014",
    "0x009c",
    "0x009d",
    "0x002f",
    "0x0035",
]


def target_dir() -> pathlib.Path:
    return cargo_target_path(TARGET_ENV, TARGET_NAME)


def go_capture_binary() -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    return target_dir() / f"capture-clienthello-chrome-go{suffix}"


def rust_capture_binary() -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    return target_dir() / "debug" / "examples" / f"capture_clienthello_chrome{suffix}"


def build_tools() -> tuple[pathlib.Path, pathlib.Path]:
    output = target_dir()
    output.mkdir(parents=True, exist_ok=True)
    go_binary = go_capture_binary()
    subprocess.run(
        [
            "go",
            "build",
            "-o",
            str(go_binary),
            "./compat/helpers/capture_clienthello_chrome",
        ],
        cwd=ROOT,
        check=True,
        timeout=120,
    )
    subprocess.run(
        [
            "cargo",
            "build",
            "--example",
            "capture_clienthello_chrome",
            "-p",
            "rewrite-outbound",
            "--target-dir",
            str(output),
        ],
        cwd=RUST_ROOT,
        check=True,
        timeout=300,
    )
    rust_binary = rust_capture_binary()
    if not rust_binary.is_file():
        raise RuntimeError(f"missing rust capture binary: {rust_binary}")
    return go_binary, rust_binary


def capture(binary: pathlib.Path) -> dict[str, object]:
    output = subprocess.check_output([str(binary)], text=True, timeout=30)
    return json.loads(output)


def extension_set(values: list[str]) -> set[str]:
    return set(values)


def compare(go: dict[str, object], rust: dict[str, object]) -> dict[str, object]:
    go_ciphers = list(go["cipher_suites"])
    rust_ciphers = list(rust["cipher_suites"])
    go_ext = list(go["extensions"])
    rust_ext = list(rust["extensions"])

    expected_go = RUST_CHROME_CIPHERS + GO_EXTRA_CHROME_CIPHERS
    checks = {
        "go-has-grease": bool(go.get("has_grease")),
        "rust-has-grease": bool(rust.get("has_grease")),
        "rust-cipher-profile": rust_ciphers == RUST_CHROME_CIPHERS,
        "go-cipher-profile": go_ciphers == expected_go,
        "go-contains-rust-ciphers": all(item in go_ciphers for item in RUST_CHROME_CIPHERS),
        "extension-set-parity": extension_set(go_ext) == extension_set(rust_ext),
        "extension-count-parity": len(go_ext) == len(rust_ext),
    }
    return {
        "checks": checks,
        "go": {"cipher_count": len(go_ciphers), "extension_count": len(go_ext)},
        "rust": {"cipher_count": len(rust_ciphers), "extension_count": len(rust_ext)},
        "passed": all(checks.values()),
    }


def main() -> int:
    try:
        go_binary, rust_binary = build_tools()
        go_shape = capture(go_binary)
        rust_shape = capture(rust_binary)
        result = compare(go_shape, rust_shape)
    except Exception as error:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps({"error": f"{type(error).__name__}: {error}"}, indent=2)
        )
        print(f"Phase 6C-M6 ShadowTLS ClientHello differential failed: {error}", file=sys.stderr)
        return 1

    if not result["passed"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {"go": go_shape, "rust": rust_shape, "result": result},
                indent=2,
                sort_keys=True,
            )
        )
        print(
            "Phase 6C-M6 ShadowTLS ClientHello differential failed:",
            json.dumps(result, indent=2),
            file=sys.stderr,
        )
        return 1

    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6C-M6 ShadowTLS ClientHello differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

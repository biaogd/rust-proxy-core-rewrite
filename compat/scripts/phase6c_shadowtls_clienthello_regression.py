#!/usr/bin/env python3
"""Per-runtime partial Chrome ClientHello regression on production ShadowTLS v3 paths.

Captures on-wire ClientHello bytes through the same production entry points used in
live traffic (Go: ``shadowtls.NewShadowTLS``; Rust: ``connect_shadow_tls`` →
``connect_with_session_id_generator``), then pins each runtime against its own
documented partial-Chrome baseline.

This is **not** a Go/Rust wire parity differential. Chrome fingerprint parity
remains partial (Rust 10 cipher suites vs Go/uTLS 16; different extension order
and counts). Protocol wire parity is covered separately by
``phase6c_shadowsocks_shadow_tls.py``.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

from phase1 import ROOT, RUST_ROOT, cargo_target_path

FAILURE_ARTIFACT = (
    ROOT / "compat" / "artifacts" / "phase6c-shadowtls-clienthello-regression.json"
)
TARGET_ENV = "PHASE6CSSSHADOWTLSCLIENTHELLO_REGRESSION_CARGO_TARGET"
TARGET_NAME = "phase6c-shadowtls-clienthello-regression"

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

# Go uTLS HelloChrome_133 baseline (16 suites incl. leading GREASE).
GO_CHROME_CIPHERS = RUST_CHROME_CIPHERS + [
    "0xc013",
    "0xc014",
    "0x009c",
    "0x009d",
    "0x002f",
    "0x0035",
]

# Production ShadowTLS v3 + chrome captures (on-wire ClientHello extension types).
GO_V3_CHROME_EXTENSIONS = [
    "0x0000",
    "0x0005",
    "0x000a",
    "0x000b",
    "0x000d",
    "0x0010",
    "0x0012",
    "0x0017",
    "0x0023",
    "0x002b",
    "0x002d",
    "0x0033",
    "0xff01",
]

RUST_V3_CHROME_EXTENSIONS = [
    "0x0a0a",
    "0xfe0d",
    "0x0017",
    "0x0023",
    "0x0012",
    "0x0033",
    "0xff01",
    "0x002d",
    "0x000d",
    "0x000a",
    "0x0005",
    "0x001b",
    "0x002b",
    "0x44cd",
    "0x000b",
    "0x0010",
    "0x0000",
    "0x0a0a",
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
            "rewrite-transport",
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


def regress_go(shape: dict[str, object]) -> dict[str, object]:
    ciphers = list(shape["cipher_suites"])
    extensions = list(shape["extensions"])
    checks = {
        "has-grease": bool(shape.get("has_grease")),
        "session-id-hmac": bool(shape.get("session_id_hmac_valid")),
        "cipher-profile": ciphers == GO_CHROME_CIPHERS,
        "extension-types": sorted(set(extensions)) == sorted(set(GO_V3_CHROME_EXTENSIONS)),
        "extension-count": len(extensions) == len(GO_V3_CHROME_EXTENSIONS),
    }
    return {
        "runtime": "go",
        "checks": checks,
        "cipher_count": len(ciphers),
        "extension_count": len(extensions),
        "passed": all(checks.values()),
    }


def regress_rust(shape: dict[str, object]) -> dict[str, object]:
    ciphers = list(shape["cipher_suites"])
    extensions = list(shape["extensions"])
    checks = {
        "has-grease": bool(shape.get("has_grease")),
        "session-id-hmac": bool(shape.get("session_id_hmac_valid")),
        "cipher-profile": ciphers == RUST_CHROME_CIPHERS,
        "extension-types": sorted(set(extensions)) == sorted(set(RUST_V3_CHROME_EXTENSIONS)),
        "extension-count": len(extensions) == len(RUST_V3_CHROME_EXTENSIONS),
        "extension-grease-bookends": bool(
            extensions
            and extensions[0] == "0x0a0a"
            and extensions[-1] == "0x0a0a"
        ),
    }
    return {
        "runtime": "rust",
        "checks": checks,
        "cipher_count": len(ciphers),
        "extension_count": len(extensions),
        "passed": all(checks.values()),
    }


def main() -> int:
    try:
        go_binary, rust_binary = build_tools()
        go_shape = capture(go_binary)
        rust_shape = capture(rust_binary)
        go_result = regress_go(go_shape)
        rust_result = regress_rust(rust_shape)
        result = {
            "mode": "per-runtime-regression",
            "go": go_result,
            "rust": rust_result,
            "passed": go_result["passed"] and rust_result["passed"],
        }
    except Exception as error:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps({"error": f"{type(error).__name__}: {error}"}, indent=2)
        )
        print(
            "Phase 6C-M6 ShadowTLS ClientHello regression failed: "
            f"{error}",
            file=sys.stderr,
        )
        return 1

    if not result["passed"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps(
                {
                    "go_shape": go_shape,
                    "rust_shape": rust_shape,
                    "result": result,
                },
                indent=2,
                sort_keys=True,
            )
        )
        print(
            "Phase 6C-M6 ShadowTLS ClientHello regression failed:",
            json.dumps(result, indent=2),
            file=sys.stderr,
        )
        return 1

    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6C-M6 ShadowTLS ClientHello regression passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

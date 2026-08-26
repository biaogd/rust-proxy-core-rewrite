#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A5d domain MRS encoding."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from phase1 import IO_DEADLINE, ROOT, RUST_ROOT, assert_go_oracle_baseline


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a5d-diff.json"
PROCESS_DEADLINE = max(IO_DEADLINE, 15.0)
EXPECTED = (
    "*.wild.example\n"
    "+.example.net\n"
    "+.suffix.example\n"
    "exact.example\n"
    "sub.*.middle.example\n"
)


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
            "PHASE5A5D_CARGO_TARGET", ROOT / "target" / "compat" / "phase5a5d-rust"
        )
    )
    subprocess.run(
        ["cargo", "build", "-p", "rewrite-cli", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def run(
    binary: pathlib.Path,
    arguments: list[str],
    scratch: pathlib.Path,
) -> subprocess.CompletedProcess[bytes]:
    scratch.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [str(binary), *arguments],
        cwd=scratch,
        env={**os.environ, "HOME": str(scratch)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=PROCESS_DEADLINE,
    )


def encode(
    binary: pathlib.Path,
    format_name: str,
    source: pathlib.Path,
    target: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    result = run(
        binary,
        [
            "convert-ruleset",
            "domain",
            format_name,
            str(source),
            str(target),
            "ignored",
        ],
        scratch,
    )
    return {
        "exit-code": result.returncode,
        "stdout": result.stdout.decode(errors="replace"),
        "stderr-present": bool(result.stderr),
        "target-created": target.exists(),
        "target-nonempty": target.exists() and target.stat().st_size > 0,
        "config-created": (scratch / ".config" / "mihomo" / "config.yaml").exists(),
    }


def decode(
    binary: pathlib.Path,
    source: pathlib.Path,
    target: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    result = run(
        binary,
        ["convert-ruleset", "domain", "mrs", str(source), str(target)],
        scratch,
    )
    return {
        "exit-code": result.returncode,
        "stderr-present": bool(result.stderr),
        "target": target.read_text() if target.exists() else None,
    }


def empty_case(
    binary: pathlib.Path,
    source: pathlib.Path,
    target: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    result = run(
        binary,
        ["convert-ruleset", "domain", "text", str(source), str(target)],
        scratch,
    )
    return {
        "exit-code": result.returncode,
        "stdout": result.stdout.decode(errors="replace"),
        "stderr-present": bool(result.stderr),
        "target-created": target.exists(),
        "target-size": target.stat().st_size if target.exists() else None,
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a5d-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        text_source = root / "domains.txt"
        text_source.write_text(
            "# deterministic trie\n"
            "EXACT.example\n"
            "*.wild.example\n"
            "+.suffix.example\n"
            ".example.net\n"
            "sub.*.middle.example\n"
        )
        yaml_source = root / "domains.yaml"
        yaml_source.write_text(
            "rules:\n"
            "  - EXACT.example\n"
            "  - '*.wild.example'\n"
            "  - '+.suffix.example'\n"
            "  - .example.net\n"
            "  - 'sub.*.middle.example'\n"
        )

        observations: dict[str, Any] = {}
        for format_name, source in (("text", text_source), ("yaml", yaml_source)):
            observations[format_name] = {}
            encoded_paths: dict[str, pathlib.Path] = {}
            for encoder_name, encoder in binaries.items():
                encoded = root / f"{format_name}-{encoder_name}.mrs"
                encoded_paths[encoder_name] = encoded
                observations[format_name][encoder_name] = {
                    "encode": encode(
                        encoder,
                        format_name,
                        source,
                        encoded,
                        root / f"encode-{format_name}-{encoder_name}",
                    )
                }
            for encoder_name, encoded in encoded_paths.items():
                observations[format_name][encoder_name]["decode"] = {
                    decoder_name: decode(
                        decoder,
                        encoded,
                        root / f"{format_name}-{encoder_name}-{decoder_name}.txt",
                        root / f"decode-{format_name}-{encoder_name}-{decoder_name}",
                    )
                    for decoder_name, decoder in binaries.items()
                }

        invalid = root / "invalid.txt"
        invalid.write_text("# comments only\n// no semantic domain rules\n")
        observations["empty"] = {
            name: empty_case(
                binary,
                invalid,
                root / f"empty-{name}.mrs",
                root / f"empty-{name}",
            )
            for name, binary in binaries.items()
        }

        expected_encode = {
            "exit-code": 0,
            "stdout": "",
            "stderr-present": False,
            "target-created": True,
            "target-nonempty": True,
            "config-created": False,
        }
        expected_decode = {
            "exit-code": 0,
            "stderr-present": False,
            "target": EXPECTED,
        }
        expected_empty = {
            "exit-code": 2,
            "stdout": "",
            "stderr-present": True,
            "target-created": True,
            "target-size": 0,
        }
        mismatch = observations["empty"] != {
            "go": expected_empty,
            "rust": expected_empty,
        }
        for format_name in ("text", "yaml"):
            for encoder_name in binaries:
                result = observations[format_name][encoder_name]
                mismatch |= result["encode"] != expected_encode
                mismatch |= result["decode"] != {
                    "go": expected_decode,
                    "rust": expected_decode,
                }
        if mismatch:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A5d mismatch; see {FAILURE_ARTIFACT}")

    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A5d domain text/YAML encoding differential passed")


if __name__ == "__main__":
    main()

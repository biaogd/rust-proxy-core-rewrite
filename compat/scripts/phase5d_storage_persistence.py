#!/usr/bin/env python3
"""Restart, limits, eviction and Go/Rust bbolt storage interchange."""

from __future__ import annotations

import json
import pathlib
import tempfile
from typing import Any

from phase1 import ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5d_storage import request
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat/artifacts/phase5d-storage-persistence-diff.json"


def write_config(path: pathlib.Path, mixed: int, controller: int) -> None:
    path.write_text(
        f"""mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
    )


def run_actions(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    config: pathlib.Path,
    mixed: int,
    controller: int,
    actions: list[tuple[str, str, bytes | None]],
) -> list[dict[str, Any]]:
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed)
        wait_controller(process, controller)
        results = []
        for method, key, body in actions:
            status, payload, _ = request(controller, method, f"/storage/{key}", body)
            results.append({"status": status, "body": payload.decode()})
        return results
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    mixed, controller = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    write_config(config, mixed, controller)
    first = run_actions(
        binary,
        scratch,
        config,
        mixed,
        controller,
        [
            ("PUT", "persist", b'{"generation":1}'),
            ("PUT", "k" * 65, b"true"),
            ("GET", "k" * 65, None),
        ],
    )
    restarted = run_actions(
        binary,
        scratch,
        config,
        mixed,
        controller,
        [("GET", "persist", None), ("DELETE", "persist", None)],
    )
    deleted = run_actions(
        binary,
        scratch,
        config,
        mixed,
        controller,
        [("GET", "persist", None)],
    )
    large = b'"' + b"x" * 400_000 + b'"'
    eviction_write = run_actions(
        binary,
        scratch,
        config,
        mixed,
        controller,
        [("PUT", "oldest", large), ("PUT", "middle", large), ("PUT", "newest", large)],
    )
    eviction_read = run_actions(
        binary,
        scratch,
        config,
        mixed,
        controller,
        [("GET", "oldest", None), ("GET", "middle", None), ("GET", "newest", None)],
    )
    return {
        "initial-status": [item["status"] for item in first],
        "long-key-read": first[2]["body"],
        "restart-read": restarted[0],
        "delete-status": restarted[1]["status"],
        "deleted-after-restart": deleted[0],
        "eviction-write-status": [item["status"] for item in eviction_write],
        "eviction": [
            {"status": item["status"], "present": item["body"] != "null"}
            for item in eviction_read
        ],
    }


def interchange(binaries: dict[str, pathlib.Path], scratch: pathlib.Path) -> dict[str, Any]:
    mixed, controller = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    write_config(config, mixed, controller)
    go_write = run_actions(
        binaries["go"], scratch, config, mixed, controller,
        [("PUT", "shared-go", b'{"writer":"go"}')],
    )
    rust_exchange = run_actions(
        binaries["rust"], scratch, config, mixed, controller,
        [
            ("GET", "shared-go", None),
            ("PUT", "shared-rust", b'{"writer":"rust"}'),
            ("DELETE", "shared-go", None),
        ],
    )
    go_read = run_actions(
        binaries["go"], scratch, config, mixed, controller,
        [("GET", "shared-go", None), ("GET", "shared-rust", None)],
    )
    return {"go-write": go_write, "rust-exchange": rust_exchange, "go-read": go_read}


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-storage-persist-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE5DSTORAGEPERSIST_CARGO_TARGET", "phase5d-storage-persistence"
        )
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
            shared = root / "interchange"
            shared.mkdir()
            observations["interchange"] = interchange(binaries, shared)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(json.dumps({
                "error": f"{type(error).__name__}: {error}",
                "observations": observations,
                "debug": debug_files(root),
            }, indent=2, sort_keys=True))
            raise
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps({"observations": observations}, indent=2, sort_keys=True))
        return 1
    expected_interchange = {
        "go-write": [{"status": 204, "body": ""}],
        "rust-exchange": [
            {"status": 200, "body": '{"writer":"go"}'},
            {"status": 204, "body": ""},
            {"status": 204, "body": ""},
        ],
        "go-read": [
            {"status": 200, "body": "null"},
            {"status": 200, "body": '{"writer":"rust"}'},
        ],
    }
    if observations["interchange"] != expected_interchange:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps({"observations": observations}, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5D persistent storage/interchange differential passed")
    print(json.dumps(observations, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

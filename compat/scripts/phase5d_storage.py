#!/usr/bin/env python3
"""Go/Rust differential for the controller JSON storage lifecycle."""

from __future__ import annotations

import http.client
import json
import pathlib
import tempfile
import urllib.parse
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5d-storage-diff.json"


def request(
    port: int, method: str, path: str, body: bytes | None = None
) -> tuple[int, bytes, str | None]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    headers = {"Authorization": f"Bearer {SECRET}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    try:
        return response.status, response.read(), response.getheader("Content-Type")
    finally:
        response.close()
        connection.close()


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    key = urllib.parse.quote("ui state/中文", safe="")
    path = f"/storage/{key}"
    first = b' { "enabled": true, "items": [1, 2] } \n'
    second = b'["replacement",null]'
    oversized = b'"' + (b"x" * (1024 * 1024)) + b'"'
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        missing = request(controller_port, "GET", path)
        put_first = request(controller_port, "PUT", path, first)
        read_first = request(controller_port, "GET", path)
        put_second = request(controller_port, "PUT", path, second)
        read_second = request(controller_port, "GET", path)
        malformed = request(controller_port, "PUT", path, b"{")
        after_malformed = request(controller_port, "GET", path)
        too_large = request(controller_port, "PUT", path, oversized)
        after_too_large = request(controller_port, "GET", path)
        deleted = request(controller_port, "DELETE", path)
        after_delete = request(controller_port, "GET", path)
        delete_missing = request(controller_port, "DELETE", path)

        return {
            "missing": response(missing),
            "put-first": empty_response(put_first),
            "raw-round-trip": response(read_first),
            "put-replacement": empty_response(put_second),
            "replacement": response(read_second),
            "malformed": error_response(malformed),
            "malformed-rollback": response(after_malformed),
            "too-large": error_response(too_large),
            "too-large-rollback": response(after_too_large),
            "delete": empty_response(deleted),
            "after-delete": response(after_delete),
            "delete-missing": empty_response(delete_missing),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def response(result: tuple[int, bytes, str | None]) -> dict[str, Any]:
    status, body, content_type = result
    return {
        "status": status,
        "body": body.decode(),
        "content-type": content_type,
    }


def empty_response(result: tuple[int, bytes, str | None]) -> dict[str, Any]:
    status, body, _ = result
    return {"status": status, "empty-body": body == b""}


def error_response(result: tuple[int, bytes, str | None]) -> dict[str, Any]:
    status, body, _ = result
    return {"status": status, "message": json.loads(body)["message"]}


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-storage-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE5DSTORAGE_CARGO_TARGET", "phase5d-storage"
        )
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "error": f"{type(error).__name__}: {error}",
                        "observations": observations,
                        "debug": debug_files(root),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            raise
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(
            json.dumps({"observations": observations}, indent=2, sort_keys=True)
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5D controller storage differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

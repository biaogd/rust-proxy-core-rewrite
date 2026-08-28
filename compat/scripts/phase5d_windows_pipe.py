#!/usr/bin/env python3
"""Native Windows named-pipe controller differential."""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import tempfile
import time
import uuid
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5d_transports import parse_http


FAILURE_ARTIFACT = ROOT / "compat/artifacts/phase5d-windows-pipe-diff.json"


POWERSHELL_CLIENT = r"""
$pipeName = $env:MIHOMO_PIPE_NAME
$request = [Convert]::FromBase64String($env:MIHOMO_PIPE_REQUEST)
$client = [System.IO.Pipes.NamedPipeClientStream]::new(
  ".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut,
  [System.IO.Pipes.PipeOptions]::None)
$client.Connect(1000)
$client.Write($request, 0, $request.Length)
$client.Flush()
$buffer = New-Object byte[] 4096
$memory = [System.IO.MemoryStream]::new()
while (($count = $client.Read($buffer, 0, $buffer.Length)) -gt 0) {
  $memory.Write($buffer, 0, $count)
}
$client.Dispose()
[Convert]::ToBase64String($memory.ToArray())
"""


def pipe_request(pipe_name: str, secret: str) -> tuple[int, dict[str, str], bytes]:
    request = (
        "GET / HTTP/1.1\r\n"
        "Host: controller\r\n"
        f"Authorization: Bearer {secret}\r\n"
        "Connection: close\r\n\r\n"
    )
    environment = os.environ.copy()
    environment["MIHOMO_PIPE_NAME"] = pipe_name
    environment["MIHOMO_PIPE_REQUEST"] = base64.b64encode(request.encode()).decode()
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-Command", POWERSHELL_CLIENT],
        capture_output=True,
        text=True,
        timeout=min(3, IO_DEADLINE),
        check=True,
        env=environment,
    )
    return parse_http(base64.b64decode(completed.stdout.strip()))


def wait_pipe(process: Any, pipe_name: str) -> tuple[int, dict[str, str], bytes]:
    deadline = time.monotonic() + IO_DEADLINE * 3
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"controller exited during pipe readiness: {process.returncode}")
        try:
            return pipe_request(pipe_name, "wrong-secret")
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            last_error = error
            time.sleep(0.05)
    raise TimeoutError("Windows named-pipe controller did not become ready") from last_error


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    mixed = reserve_port()
    short_name = f"mihomo-5d-{uuid.uuid4().hex[:12]}"
    configured = rf"\\.\pipe\{short_name}"
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed}
external-controller-pipe: '{configured}'
secret: must-not-apply-to-local-pipe
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed)
        status, headers, body = wait_pipe(process, short_name)
        return {
            "status": status,
            "content-type": headers.get("content-type"),
            "body": body.decode(),
            "secret-bypassed": status == 200,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def main() -> int:
    if os.name != "nt":
        print("Phase 5D Windows named-pipe differential skipped on non-Windows host")
        return 0
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-pipe-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5DPIPE_CARGO_TARGET", "phase5d-windows-pipe")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
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
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5D Windows named-pipe controller differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

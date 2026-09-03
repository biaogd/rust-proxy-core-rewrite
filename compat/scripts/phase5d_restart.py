#!/usr/bin/env python3
"""Controller restart response and re-exec lifecycle differential."""

from __future__ import annotations

import http.client
import json
import os
import pathlib
import subprocess
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat/artifacts/phase5d-restart-diff.json"


def request(port: int, method: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    connection.request(method, "/restart/", headers={"Authorization": f"Bearer {SECRET}"})
    response = connection.getresponse()
    try:
        return response.status, response.read()
    finally:
        response.close()
        connection.close()


def windows_listener_pid(port: int) -> int | None:
    """Return the PID owning a Windows TCP listener without extra modules."""
    if os.name != "nt":
        return None
    result = subprocess.run(
        ["netstat", "-ano", "-p", "tcp"],
        text=True,
        capture_output=True,
        check=False,
    )
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0].upper() != "TCP":
            continue
        if fields[3].upper() != "LISTENING":
            continue
        try:
            local_port = int(fields[1].rsplit(":", 1)[1])
            pid = int(fields[4])
        except (IndexError, ValueError):
            continue
        if local_port == port:
            return pid
    return None


def stop_windows_listener(pid: int) -> None:
    subprocess.run(
        ["taskkill", "/F", "/T", "/PID", str(pid)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def wait_reexec(process: Any, controller: int) -> int:
    deadline = time.monotonic() + IO_DEADLINE * 2
    saw_unavailable = False
    while time.monotonic() < deadline:
        original_exited = process.poll() is not None
        if original_exited and os.name != "nt":
            raise RuntimeError(f"restart process exited with {process.returncode}")
        try:
            connection = http.client.HTTPConnection("127.0.0.1", controller, timeout=0.1)
            connection.request("GET", "/", headers={"Authorization": f"Bearer {SECRET}"})
            response = connection.getresponse()
            body = response.read()
            response.close()
            connection.close()
            ready = response.status == 200 and json.loads(body)["hello"] == "mihomo"
            if ready and (saw_unavailable or original_exited):
                return windows_listener_pid(controller) or process.pid
        except (OSError, TimeoutError):
            saw_unavailable = True
        time.sleep(0.01)
    # Very fast local exec can reopen between polling samples. A live endpoint
    # after the bounded re-exec window is still required, while process death is
    # always a failure.
    if os.name == "nt" and process.poll() is not None:
        raise RuntimeError("restarted child did not reopen the controller")
    wait_controller(process, controller)
    return windows_listener_pid(controller) or process.pid


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    mixed, controller = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
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
    process, stdout, stderr = launch(binary, config, scratch)
    original_pid = process.pid
    restarted_pid = original_pid
    try:
        wait_ready(process, mixed)
        wait_controller(process, controller)
        wrong_method = request(controller, "GET")
        restarted = request(controller, "POST")
        restarted_pid = wait_reexec(process, controller)
        return {
            "wrong-method-status": wrong_method[0],
            "restart-status": restarted[0],
            "restart-body": json.loads(restarted[1]),
            "same-pid": restarted_pid == original_pid,
            "alive-after-reexec": windows_listener_pid(controller) is not None
            if os.name == "nt"
            else process.poll() is None,
        }
    finally:
        listener_pid = windows_listener_pid(controller)
        if os.name == "nt" and listener_pid is not None:
            stop_windows_listener(listener_pid)
            deadline = time.monotonic() + IO_DEADLINE
            while windows_listener_pid(controller) is not None and time.monotonic() < deadline:
                time.sleep(0.02)
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-restart-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5DRESTART_CARGO_TARGET", "phase5d-restart")
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
    print("Phase 5D restart/re-exec differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

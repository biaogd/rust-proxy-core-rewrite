#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E18 DoQ lifecycle."""

from __future__ import annotations

import concurrent.futures
import json
import pathlib
import subprocess
import tempfile
import time
from typing import Any, Callable

from phase1 import IO_DEADLINE, ROOT, reload_via_declared_controller, reserve_port
from phase4 import build_binaries, dns_query, launch, observe_response, stop, wait_dns_ready
from phase4e5 import encrypted_udp_query
from phase4e17 import (
    SERVER_NAME,
    build_authority,
    render_config,
    start_authority,
    stop_authority,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e18-diff.json"
CONCURRENT_STREAMS = 8


def read_authority(
    path: pathlib.Path, predicate: Callable[[dict[str, Any]], bool]
) -> dict[str, Any]:
    deadline = time.monotonic() + IO_DEADLINE
    latest: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        try:
            latest = json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.02)
            continue
        if predicate(latest):
            return latest
        time.sleep(0.02)
    raise TimeoutError(f"DoQ authority state did not converge: {latest}")


def normalize_authority(observation: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(observation)
    normalized["max_in_flight"] = (
        "overlap" if observation["max_in_flight"] >= 2 else "serialized"
    )
    return normalized


def start_case(
    binary: pathlib.Path, scratch: pathlib.Path, mode: str
) -> tuple[
    subprocess.Popen[str],
    pathlib.Path,
    int,
    pathlib.Path,
    Any,
    Any,
    subprocess.Popen[bytes],
]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority, upstream_port, observation = start_authority(scratch, mode)
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=reserve_port(),
        dns_port=dns_port,
        upstream_port=upstream_port,
        server_name=SERVER_NAME,
    )
    config.write_text(
        config.read_text()
        + f"external-controller: 127.0.0.1:{reserve_port()}\n"
    )
    process, stdout, stderr = launch(binary, config, scratch)
    wait_dns_ready(process, dns_port)
    time.sleep(0.1)
    return authority, observation, dns_port, config, stdout, stderr, process


def finish_case(
    authority: subprocess.Popen[str],
    stdout: Any,
    stderr: Any,
    process: subprocess.Popen[bytes],
) -> int:
    exit_code = stop(process)
    stdout.close()
    stderr.close()
    stop_authority(authority)
    return exit_code


def query(dns_port: int, name: str, identifier: int) -> dict[str, Any]:
    response = encrypted_udp_query(dns_port, dns_query(name, identifier))
    return observe_response(response, identifier)


def exercise_reuse_and_concurrency(
    binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    authority, path, dns_port, _, stdout, stderr, process = start_case(
        binary, scratch, "delay"
    )
    try:
        sequential = [
            query(dns_port, f"sequential-{index}.doq.phase4.test", 0xB100 + index)
            for index in range(2)
        ]

        def concurrent_query(index: int) -> dict[str, Any]:
            return query(
                dns_port,
                f"concurrent-{index}.doq.phase4.test",
                0xB200 + index,
            )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=CONCURRENT_STREAMS
        ) as executor:
            concurrent_responses = list(
                executor.map(concurrent_query, range(CONCURRENT_STREAMS))
            )
        expected = 2 + CONCURRENT_STREAMS
        snapshot = read_authority(
            path,
            lambda current: current["queries"] == expected
            and current["active_streams"] == 0,
        )
        return {
            "sequential": sequential,
            "concurrent": concurrent_responses,
            "authority": normalize_authority(snapshot),
            "exit-code": finish_case(authority, stdout, stderr, process),
        }
    finally:
        if process.poll() is None:
            finish_case(authority, stdout, stderr, process)


def exercise_bounded_retry(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority, path, dns_port, _, stdout, stderr, process = start_case(
        binary, scratch, "retry-twice"
    )
    try:
        first = query(dns_port, "before-retry.doq.phase4.test", 0xB310)
        second = query(dns_port, "during-retry.doq.phase4.test", 0xB320)
        snapshot = read_authority(
            path,
            lambda current: current["connections"] == 3
            and current["queries"] == 4
            and current["active_streams"] == 0,
        )
        return {
            "first": first,
            "second": second,
            "authority": normalize_authority(snapshot),
            "exit-code": finish_case(authority, stdout, stderr, process),
        }
    finally:
        if process.poll() is None:
            finish_case(authority, stdout, stderr, process)


def exercise_reload_reset(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority, path, dns_port, config, stdout, stderr, process = start_case(
        binary, scratch, "answer"
    )
    try:
        first = query(dns_port, "before-reset.doq.phase4.test", 0xB410)
        before = read_authority(
            path,
            lambda current: current["connections"] == 1
            and current["queries"] == 1
            and current["active_streams"] == 0,
        )
        config.touch()
        reload_via_declared_controller(process, config)
        reset = read_authority(
            path, lambda current: current["active_connections"] == 0
        )
        second = query(dns_port, "after-reset.doq.phase4.test", 0xB420)
        after = read_authority(
            path,
            lambda current: current["connections"] == 2
            and current["queries"] == 2
            and current["active_streams"] == 0,
        )
        return {
            "first": first,
            "before": normalize_authority(before),
            "reset": normalize_authority(reset),
            "second": second,
            "after": normalize_authority(after),
            "exit-code": finish_case(authority, stdout, stderr, process),
        }
    finally:
        if process.poll() is None:
            finish_case(authority, stdout, stderr, process)


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    return {
        "reuse-concurrency": exercise_reuse_and_concurrency(
            binary, scratch / "reuse-concurrency"
        ),
        "bounded-retry": exercise_bounded_retry(binary, scratch / "bounded-retry"),
        "reload-reset": exercise_reload_reset(binary, scratch / "reload-reset"),
    }


def successful(response: dict[str, Any]) -> bool:
    return response.get("address") == "192.0.2.42" and response.get("id-echoed") is True


def handshakes_are_full(authority: dict[str, Any]) -> bool:
    return all(
        handshake == {
            "alpn": "doq",
            "server_name": "",
            "used_0rtt": False,
            "did_resume": False,
        }
        for handshake in authority["handshakes"]
    )


def satisfies_phase_contract(observation: dict[str, Any]) -> bool:
    reuse = observation["reuse-concurrency"]
    reuse_authority = reuse["authority"]
    if (
        any(not successful(response) for response in reuse["sequential"])
        or any(not successful(response) for response in reuse["concurrent"])
        or reuse_authority["connections"] != 1
        or reuse_authority["streams"] != 2 + CONCURRENT_STREAMS
        or reuse_authority["queries"] != 2 + CONCURRENT_STREAMS
        or reuse_authority["max_in_flight"] != "overlap"
        or not handshakes_are_full(reuse_authority)
        or reuse["exit-code"] != 0
    ):
        return False
    retry = observation["bounded-retry"]
    retry_authority = retry["authority"]
    if (
        not successful(retry["first"])
        or not successful(retry["second"])
        or retry_authority["connections"] != 3
        or retry_authority["streams"] != 4
        or retry_authority["queries"] != 4
        or not handshakes_are_full(retry_authority)
        or retry["exit-code"] != 0
    ):
        return False
    reset = observation["reload-reset"]
    return (
        successful(reset["first"])
        and successful(reset["second"])
        and reset["before"]["connections"] == 1
        and reset["reset"]["active_connections"] == 0
        and reset["after"]["connections"] == 2
        and handshakes_are_full(reset["after"])
        and reset["exit-code"] == 0
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e18-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        build_authority()
        observations = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if observations["go"] != observations["rust"] or not satisfies_phase_contract(
            observations["go"]
        ):
            FAILURE_ARTIFACT.write_text(
                json.dumps(observations, indent=2, sort_keys=True)
            )
            raise SystemExit(f"Phase 4E18 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E18 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E15 DoH HTTP/2."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, cargo_target_path, reserve_port
from phase4 import (
    build_binaries,
    dns_query,
    launch,
    observe_response,
    stop,
    tcp_query,
    wait_dns_ready,
)
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase4e5 import encrypted_udp_query
from phase4e13 import exercise as exercise_h1


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e15-diff.json"
SERVER_NAME = "dot.phase4.test"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path("PHASE4_CARGO_TARGET", "phase4-rust")
    return target / "debug" / "rewrite-h2-authority"


def start_authority(
    scratch: pathlib.Path,
) -> tuple[subprocess.Popen[str], int, pathlib.Path]:
    observation = scratch / "h2-authority.json"
    process = subprocess.Popen(
        [
            str(authority_binary()),
            str(SERVER_CERTIFICATE),
            str(SERVER_KEY),
            str(observation),
        ],
        cwd=scratch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    line = process.stdout.readline().strip()
    if not line:
        stderr = process.stderr.read() if process.stderr is not None else ""
        raise RuntimeError(f"HTTP/2 authority failed to start: {stderr}")
    return process, int(line), observation


def read_authority(path: pathlib.Path, request_count: int) -> dict[str, Any]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        try:
            observation = json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.02)
            continue
        if len(observation["requests"]) >= request_count:
            return observation
        time.sleep(0.02)
    raise TimeoutError("HTTP/2 authority observation did not become ready")


def stop_authority(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=IO_DEADLINE)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=IO_DEADLINE)
    if process.stdout is not None:
        process.stdout.close()
    if process.stderr is not None:
        process.stderr.close()


def render_config(
    path: pathlib.Path,
    *,
    mixed_port: int,
    dns_port: int,
    upstream_port: int,
) -> None:
    root_pem = "\n".join(
        f"      {line}" for line in ROOT_CERTIFICATE.read_text().splitlines()
    )
    path.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
tls:
  custom-certifactes:
    - |-
{root_pem}
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  nameserver:
    - https://127.0.0.1:{upstream_port}/dns-query#name-cert-verify={SERVER_NAME}
rules:
  - MATCH,DIRECT
"""
    )


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    valid = scratch / "valid.yaml"
    render_config(
        valid,
        mixed_port=reserve_port(),
        dns_port=reserve_port(),
        upstream_port=reserve_port(),
    )
    wrong_scheme = scratch / "wrong-scheme.yaml"
    wrong_scheme.write_text(valid.read_text().replace("https://", "bogus://"))
    return {
        name: subprocess.run(
            [str(binary), "-t", "-f", str(path)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        for name, path in {"valid": valid, "wrong-scheme": wrong_scheme}.items()
    }


def exercise_h2(
    binary: pathlib.Path,
    scratch: pathlib.Path,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority, upstream_port, observation_path = start_authority(scratch)
    mixed_port, dns_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        upstream_port=upstream_port,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        first_name = f"first.{scratch.name}.phase4.test"
        second_name = f"second.{scratch.name}.phase4.test"
        first = encrypted_udp_query(dns_port, dns_query(first_name, 0x9010))
        second = tcp_query(dns_port, dns_query(second_name, 0x9020))
        cached = encrypted_udp_query(dns_port, dns_query(first_name, 0x9030))
        authority_observation = read_authority(observation_path, 2)
        return {
            "first": observe_response(first, 0x9010),
            "second": observe_response(second, 0x9020),
            "cached": observe_response(cached, 0x9030),
            "h2-authority": authority_observation,
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        stop_authority(authority)


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    config = validation(binary, scratch)
    if config != {"valid": 0, "wrong-scheme": 1}:
        return {"config": config, "runtime": "not-run"}
    return {
        "config": config,
        "runtime": {
            "h2": exercise_h2(binary, scratch / "h2"),
            "h1-fallback": exercise_h1(
                binary,
                scratch / "h1-fallback",
                behavior="answer",
                configured_path="/dns-query",
                credentials=None,
            ),
        },
    }


def satisfies_phase_contract(observation: dict[str, Any]) -> bool:
    if observation["config"] != {"valid": 0, "wrong-scheme": 1}:
        return False
    h2_case = observation["runtime"]["h2"]
    authority = h2_case["h2-authority"]
    if (
        h2_case["first"].get("address") != "192.0.2.42"
        or h2_case["second"].get("address") != "192.0.2.42"
        or h2_case["cached"].get("address") != "192.0.2.42"
        or authority["connections"] != 1
        or authority["negotiated_protocols"] != ["h2"]
        or authority["server_names"] != [None]
        or authority["queries"] != 2
        or len(authority["requests"]) != 2
        or any(
            request["method"] != "GET"
            or request["scheme"] != "https"
            or request["authority_matches_listener"] is not True
            or request["path"] != "/dns-query"
            or request["query_keys"] != ["dns"]
            or request["accept"] != "application/dns-message"
            or request["dns_id_zero"] is not True
            or request["request_body_empty"] is not True
            or request["valid"] is not True
            for request in authority["requests"]
        )
        or h2_case["exit-code"] != 0
    ):
        return False
    h1_case = observation["runtime"]["h1-fallback"]
    h1_authority = h1_case["https-authority"]
    return (
        h1_case["first"].get("address") == "192.0.2.42"
        and h1_case["cached"].get("address") == "192.0.2.42"
        and h1_authority["connections"] == 1
        and h1_authority["queries"] == {"https": 1}
        and len(h1_authority["requests"]) == 1
        and h1_authority["requests"][0]["valid"] is True
        and h1_case["exit-code"] == 0
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e15-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        if not authority_binary().is_file():
            raise RuntimeError("rewrite-h2-authority was not built")
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
            raise SystemExit(f"Phase 4E15 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E15 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

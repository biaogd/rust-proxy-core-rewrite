#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E16 DoH HTTP/3."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, cargo_target_path, reserve_port
from phase4 import build_binaries, dns_query, launch, observe_response, stop, wait_dns_ready
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase4e5 import encrypted_udp_query


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e16-diff.json"
SERVER_NAME = "dot.phase4.test"


def authority_binary() -> pathlib.Path:
    target = cargo_target_path("PHASE4_CARGO_TARGET", "phase4-rust")
    return target / "debug" / "phase4e16-h3-authority"


def build_authority() -> None:
    binary = authority_binary()
    binary.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "go",
            "build",
            "-trimpath",
            "-o",
            str(binary),
            "./compat/helpers/h3-authority",
        ],
        cwd=ROOT,
        check=True,
    )


def start_authority(
    scratch: pathlib.Path, mode: str
) -> tuple[subprocess.Popen[str], int, pathlib.Path]:
    observation = scratch / "h3-authority.json"
    process = subprocess.Popen(
        [
            str(authority_binary()),
            str(SERVER_CERTIFICATE),
            str(SERVER_KEY),
            str(observation),
            mode,
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
        raise RuntimeError(f"HTTP/3 authority failed to start: {stderr}")
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
    raise TimeoutError("HTTP/3 authority observation did not become ready")


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
    prefer_h3: bool,
    force_h3: bool,
) -> None:
    root_pem = "\n".join(
        f"      {line}" for line in ROOT_CERTIFICATE.read_text().splitlines()
    )
    fragment = f"name-cert-verify={SERVER_NAME}"
    if force_h3:
        fragment += "&h3=true"
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
  prefer-h3: {str(prefer_h3).lower()}
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  nameserver:
    - https://127.0.0.1:{upstream_port}/dns-query#{fragment}
rules:
  - MATCH,DIRECT
"""
    )


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    cases = {
        "forced-h3": (False, True),
        "preferred-h3": (True, False),
        "ordinary-http": (False, False),
    }
    result: dict[str, int] = {}
    for name, (prefer_h3, force_h3) in cases.items():
        path = scratch / f"validation-{name}.yaml"
        render_config(
            path,
            mixed_port=reserve_port(),
            dns_port=reserve_port(),
            upstream_port=reserve_port(),
            prefer_h3=prefer_h3,
            force_h3=force_h3,
        )
        result[name] = subprocess.run(
            [str(binary), "-t", "-f", str(path)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
    return result


def exercise_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    authority_mode: str,
    prefer_h3: bool,
    force_h3: bool,
    reconnect: bool = False,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority, upstream_port, observation_path = start_authority(
        scratch, authority_mode
    )
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=reserve_port(),
        dns_port=dns_port,
        upstream_port=upstream_port,
        prefer_h3=prefer_h3,
        force_h3=force_h3,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        first_name = f"first.{scratch.name}.phase4.test"
        second_name = f"second.{scratch.name}.phase4.test"
        first = encrypted_udp_query(dns_port, dns_query(first_name, 0x9110))
        read_authority(observation_path, 1)
        if reconnect:
            time.sleep(0.8)
        second = encrypted_udp_query(dns_port, dns_query(second_name, 0x9120))
        authority_observation = read_authority(observation_path, 2)
        return {
            "first": observe_response(first, 0x9110),
            "second": observe_response(second, 0x9120),
            "authority": authority_observation,
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
    if config != {"forced-h3": 0, "ordinary-http": 0, "preferred-h3": 0}:
        return {"config": config, "runtime": "not-run"}
    return {
        "config": config,
        "runtime": {
            "forced": exercise_case(
                binary,
                scratch / "forced",
                authority_mode="h3-only",
                prefer_h3=False,
                force_h3=True,
            ),
            "preferred-h3": exercise_case(
                binary,
                scratch / "preferred-h3",
                authority_mode="h3-faster",
                prefer_h3=True,
                force_h3=False,
            ),
            "preferred-h2-fallback": exercise_case(
                binary,
                scratch / "preferred-h2-fallback",
                authority_mode="h2-only",
                prefer_h3=True,
                force_h3=False,
            ),
            "zero-rtt-reconnect": exercise_case(
                binary,
                scratch / "zero-rtt-reconnect",
                authority_mode="close-first",
                prefer_h3=False,
                force_h3=True,
                reconnect=True,
            ),
        },
    }


def valid_case(case: dict[str, Any], protocol: str) -> bool:
    authority = case["authority"]
    return (
        case["first"].get("address") == "192.0.2.42"
        and case["second"].get("address") == "192.0.2.42"
        and authority["queries"] == 2
        and len(authority["requests"]) == 2
        and all(
            request["protocol"] == protocol
            and request["method"] == "GET"
            and request["authority_matches_listener"] is True
            and request["path"] == "/dns-query"
            and request["query_keys"] == ["dns"]
            and request["accept"] == "application/dns-message"
            and request["dns_id_zero"] is True
            and request["request_body_empty"] is True
            and request["valid"] is True
            for request in authority["requests"]
        )
        and case["exit-code"] == 0
    )


def satisfies_phase_contract(observation: dict[str, Any]) -> bool:
    if observation["config"] != {
        "forced-h3": 0,
        "ordinary-http": 0,
        "preferred-h3": 0,
    }:
        return False
    runtime = observation["runtime"]
    forced = runtime["forced"]
    preferred_h3 = runtime["preferred-h3"]
    fallback = runtime["preferred-h2-fallback"]
    reconnect = runtime["zero-rtt-reconnect"]
    return (
        valid_case(forced, "h3")
        and forced["authority"]["h3_connections"] == 1
        and valid_case(preferred_h3, "h3")
        and preferred_h3["authority"]["h3_connections"] >= 2
        and valid_case(fallback, "h2")
        and fallback["authority"]["h2_connections"] >= 2
        and valid_case(reconnect, "h3")
        and reconnect["authority"]["h3_connections"] == 2
        and all(
            request["used_0rtt"] is False
            for request in reconnect["authority"]["requests"]
        )
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e16-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        build_authority()
        if not authority_binary().is_file():
            raise RuntimeError("rewrite-h3-authority was not built")
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
            raise SystemExit(f"Phase 4E16 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E16 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

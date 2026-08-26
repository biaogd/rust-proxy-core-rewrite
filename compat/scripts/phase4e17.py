#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E17 verified DoQ framing."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase4 import build_binaries, dns_query, launch, observe_response, stop, wait_dns_ready
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY, rejected_query
from phase4e5 import encrypted_udp_query


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e17-diff.json"
SERVER_NAME = "dot.phase4.test"


def authority_binary() -> pathlib.Path:
    target = pathlib.Path(
        os.environ.get(
            "PHASE4_CARGO_TARGET", ROOT / "target" / "compat" / "phase4-rust"
        )
    )
    return target / "debug" / "phase4e17-doq-authority"


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
            "./compat/helpers/doq-authority",
        ],
        cwd=ROOT,
        check=True,
    )


def start_authority(
    scratch: pathlib.Path, mode: str
) -> tuple[subprocess.Popen[str], int, pathlib.Path]:
    observation = scratch / "doq-authority.json"
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
        raise RuntimeError(f"DoQ authority failed to start: {stderr}")
    return process, int(line), observation


def read_authority(path: pathlib.Path, frame_count: int) -> dict[str, Any]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        try:
            observation = json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.02)
            continue
        if len(observation["frames"]) >= frame_count:
            return observation
        time.sleep(0.02)
    raise TimeoutError("DoQ authority observation did not become ready")


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
    server_name: str,
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
    - quic://127.0.0.1:{upstream_port}#name-cert-verify={server_name}
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
        server_name=SERVER_NAME,
    )
    wrong_scheme = scratch / "wrong-scheme.yaml"
    wrong_scheme.write_text(valid.read_text().replace("quic://", "bogus://"))
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


def exercise(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    authority_mode: str,
    server_name: str,
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
        server_name=server_name,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        identifier = 0xA110
        query = dns_query(f"{scratch.name}.doq.phase4.test", identifier)
        if authority_mode == "answer" and server_name == SERVER_NAME:
            response = observe_response(
                encrypted_udp_query(dns_port, query), identifier
            )
        else:
            response = rejected_query(encrypted_udp_query, dns_port, query)
        frame_count = 0 if server_name != SERVER_NAME else 1
        authority_observation = read_authority(observation_path, frame_count)
        return {
            "response": response,
            "doq-authority": authority_observation,
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
            "verified": exercise(
                binary,
                scratch / "verified",
                authority_mode="answer",
                server_name=SERVER_NAME,
            ),
            "wrong-name": exercise(
                binary,
                scratch / "wrong-name",
                authority_mode="answer",
                server_name="wrong.phase4.test",
            ),
            "empty-response": exercise(
                binary,
                scratch / "empty-response",
                authority_mode="empty",
                server_name=SERVER_NAME,
            ),
        },
    }


def rejected_contract(response: dict[str, Any]) -> bool:
    return (
        response.get("id-echoed") is True
        and response.get("flags", "")[-1:] == "2"
        and response.get("questions") == 1
        and response.get("answers") == 0
    )


def satisfies_phase_contract(observation: dict[str, Any]) -> bool:
    if observation["config"] != {"valid": 0, "wrong-scheme": 1}:
        return False
    runtime = observation["runtime"]
    verified = runtime["verified"]
    authority = verified["doq-authority"]
    if (
        verified["response"].get("address") != "192.0.2.42"
        or verified["response"].get("id-echoed") is not True
        or verified["exit-code"] != 0
        or authority["connections"] != 1
        or authority["streams"] != 1
        or authority["queries"] != 1
        or len(authority["frames"]) != 1
    ):
        return False
    frame = authority["frames"][0]
    if (
        frame["alpn"] != "doq"
        or frame["server_name"] != ""
        or frame["declared_length"] != frame["payload_length"]
        or frame["payload_length"] < 12
        or frame["trailing_bytes"] != 0
        or frame["dns_id_zero"] is not True
        or frame["fin_received"] is not True
        or frame["valid"] is not True
    ):
        return False
    wrong_name = runtime["wrong-name"]
    empty = runtime["empty-response"]
    return (
        rejected_contract(wrong_name["response"])
        and wrong_name["doq-authority"]["queries"] == 0
        and wrong_name["exit-code"] == 0
        and rejected_contract(empty["response"])
        and empty["doq-authority"]["queries"] == 1
        and empty["exit-code"] == 0
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e17-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        build_authority()
        if not authority_binary().is_file():
            raise RuntimeError("phase4e17-doq-authority was not built")
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
            raise SystemExit(f"Phase 4E17 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E17 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

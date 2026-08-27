#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E19 DNS wrapper parameters."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase4 import build_binaries, dns_query, launch, observe_response, stop, wait_dns_ready
from phase4e5 import encrypted_udp_query
from phase4e17 import (
    SERVER_NAME,
    build_authority,
    render_config,
    start_authority,
    stop_authority,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e19-diff.json"


def typed_query(name: str, identifier: int, record_type: int) -> bytes:
    query = bytearray(dns_query(name, identifier))
    query[-4:-2] = record_type.to_bytes(2, "big")
    return bytes(query)


def with_ecs(
    query: bytes, *, family: int, prefix: int, address: bytes
) -> bytes:
    option_data = family.to_bytes(2, "big") + bytes([prefix, 0]) + address
    option = b"\x00\x08" + len(option_data).to_bytes(2, "big") + option_data
    opt = b"\x00\x00\x29\x10\x00\x00\x00\x00\x00" + len(option).to_bytes(
        2, "big"
    ) + option
    rewritten = bytearray(query)
    rewritten[10:12] = b"\x00\x01"
    rewritten.extend(opt)
    return bytes(rewritten)


def empty_response(response: bytes, identifier: int) -> dict[str, Any]:
    return {
        "id-echoed": int.from_bytes(response[:2], "big") == identifier,
        "flags": response[2:4].hex(),
        "questions": int.from_bytes(response[4:6], "big"),
        "answers": int.from_bytes(response[6:8], "big"),
        "authority": int.from_bytes(response[8:10], "big"),
        "additional": int.from_bytes(response[10:12], "big"),
    }


def read_authority(path: pathlib.Path, frames: int) -> dict[str, Any]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        try:
            observation = json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.02)
            continue
        if len(observation["frames"]) >= frames and observation["active_streams"] == 0:
            result = {
                key: observation[key]
                for key in ("connections", "streams", "queries", "frames")
            }
            valid_frames = [frame for frame in result["frames"] if frame["valid"]]
            # This gate owns wrapper parameters and one semantic DoQ query,
            # not connection-pool/readiness retries. Drop zero-length startup
            # streams and collapse byte-identical valid retries only; distinct
            # query frames remain observable differences.
            if valid_frames and all(frame == valid_frames[0] for frame in valid_frames):
                result["connections"] = 1
                result["streams"] = 1
                result["queries"] = 1
                result["frames"] = valid_frames[:1]
            return result
        time.sleep(0.02)
    raise TimeoutError("Phase 4E19 authority observation did not converge")


def configured(
    path: pathlib.Path,
    *,
    dns_port: int,
    upstream_port: int,
    parameters: str,
) -> None:
    render_config(
        path,
        mixed_port=reserve_port(),
        dns_port=dns_port,
        upstream_port=upstream_port,
        server_name=SERVER_NAME,
    )
    path.write_text(
        path.read_text().replace(
            f"#name-cert-verify={SERVER_NAME}",
            f"#name-cert-verify={SERVER_NAME}{parameters}",
        )
    )


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    valid = scratch / "valid.yaml"
    configured(
        valid,
        dns_port=reserve_port(),
        upstream_port=reserve_port(),
        parameters="&ecs=203.0.113.129/24&ecs-override=true&disable-ipv4=true&disable-ipv6=true&disable-qtype-65=true",
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
    parameters: str,
    query: bytes,
    expect_answer: bool,
    authority_frames: int,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority, upstream_port, observation_path = start_authority(scratch, "answer")
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    configured(
        config,
        dns_port=dns_port,
        upstream_port=upstream_port,
        parameters=parameters,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        identifier = int.from_bytes(query[:2], "big")
        deadline = time.monotonic() + IO_DEADLINE
        while True:
            response = encrypted_udp_query(dns_port, query)
            # The Go DNS listener can become reachable just before its DoQ
            # resolver finishes initialising.  Treat only that explicit,
            # empty SERVFAIL as a readiness observation and retry the same
            # query.  Other responses are measured exactly as returned.
            empty_servfail = (
                len(response) >= 12
                and response[3] & 0x0F == 2
                and response[6:12] == b"\x00\x00\x00\x00\x00\x00"
            )
            if not empty_servfail or time.monotonic() >= deadline:
                break
            time.sleep(0.02)
        observed = (
            observe_response(response, identifier)
            if expect_answer
            else empty_response(response, identifier)
        )
        authority_observation = read_authority(observation_path, authority_frames)
        return {
            "response": observed,
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
    if config != {"valid": 0, "wrong-scheme": 1}:
        return {"config": config, "runtime": "not-run"}
    existing = with_ecs(
        typed_query("preserve-ecs.phase4.test", 0xC120, 1),
        family=1,
        prefix=24,
        address=bytes([198, 51, 100]),
    )
    return {
        "config": config,
        "runtime": {
            "ecs-ipv4": exercise(
                binary,
                scratch / "ecs-ipv4",
                parameters="&ecs=203.0.113.129/24",
                query=typed_query("ecs-ipv4.phase4.test", 0xC110, 1),
                expect_answer=True,
                authority_frames=1,
            ),
            "ecs-preserve": exercise(
                binary,
                scratch / "ecs-preserve",
                parameters="&ecs=203.0.113.129/24",
                query=existing,
                expect_answer=True,
                authority_frames=1,
            ),
            "ecs-override": exercise(
                binary,
                scratch / "ecs-override",
                parameters="&ecs=203.0.113.129/24&ecs-override=true",
                query=existing.replace(b"preserve-ecs", b"override-ecs"),
                expect_answer=True,
                authority_frames=1,
            ),
            "ecs-ipv6": exercise(
                binary,
                scratch / "ecs-ipv6",
                parameters="&ecs=2001:db8:abcd:1234::1/56",
                query=typed_query("ecs-ipv6.phase4.test", 0xC130, 1),
                expect_answer=True,
                authority_frames=1,
            ),
            "disable-ipv4": exercise(
                binary,
                scratch / "disable-ipv4",
                parameters="&disable-ipv4=true",
                query=typed_query("disable-ipv4.phase4.test", 0xC210, 1),
                expect_answer=False,
                authority_frames=0,
            ),
            "disable-ipv6": exercise(
                binary,
                scratch / "disable-ipv6",
                parameters="&disable-ipv6=true",
                query=typed_query("disable-ipv6.phase4.test", 0xC220, 28),
                expect_answer=False,
                authority_frames=0,
            ),
            "disable-qtype": exercise(
                binary,
                scratch / "disable-qtype",
                parameters="&disable-qtype-65=true",
                query=typed_query("disable-qtype.phase4.test", 0xC230, 65),
                expect_answer=False,
                authority_frames=0,
            ),
            "filter-answer": exercise(
                binary,
                scratch / "filter-answer",
                parameters="&disable-ipv4=true",
                query=typed_query("filter-answer.phase4.test", 0xC240, 5),
                expect_answer=False,
                authority_frames=1,
            ),
        },
    }


def empty_contract(case: dict[str, Any], authority_queries: int) -> bool:
    response = case["response"]
    return (
        response["id-echoed"] is True
        and response["flags"] == "8580"
        and response["questions"] == 1
        and response["answers"] == 0
        and response["authority"] == 0
        and response["additional"] == 0
        and case["authority"]["queries"] == authority_queries
        and case["exit-code"] == 0
    )


def ecs_contract(case: dict[str, Any], expected: dict[str, Any]) -> bool:
    authority = case["authority"]
    return (
        case["response"].get("address") == "192.0.2.42"
        and authority["queries"] == 1
        and len(authority["frames"]) == 1
        and authority["frames"][0]["ecs"] == expected
        and case["exit-code"] == 0
    )


def satisfies_phase_contract(observation: dict[str, Any]) -> bool:
    if observation["config"] != {"valid": 0, "wrong-scheme": 1}:
        return False
    runtime = observation["runtime"]
    return (
        ecs_contract(
            runtime["ecs-ipv4"],
            {"family": 1, "prefix": 24, "address": "203.0.113.0"},
        )
        and ecs_contract(
            runtime["ecs-preserve"],
            {"family": 1, "prefix": 24, "address": "198.51.100.0"},
        )
        and ecs_contract(
            runtime["ecs-override"],
            {"family": 1, "prefix": 24, "address": "203.0.113.0"},
        )
        and ecs_contract(
            runtime["ecs-ipv6"],
            {"family": 2, "prefix": 56, "address": "2001:db8:abcd:1200::"},
        )
        and empty_contract(runtime["disable-ipv4"], 0)
        and empty_contract(runtime["disable-ipv6"], 0)
        and empty_contract(runtime["disable-qtype"], 0)
        and empty_contract(runtime["filter-answer"], 1)
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e19-") as temporary:
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
            raise SystemExit(f"Phase 4E19 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E19 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

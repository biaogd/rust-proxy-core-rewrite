#!/usr/bin/env python3
"""Go/Rust differential suite for Phase 4F6 classic DNS wrappers."""

from __future__ import annotations

import ipaddress
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, RUST_ROOT, reserve_port
from phase4 import (
    build_binaries,
    dns_name,
    dns_query,
    dns_question_end,
    launch,
    observe_response,
    stop,
    udp_query,
    wait_dns_ready,
)
from phase4f2 import LocalAuthority, config_text


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f6-diff.json"


def skip_name(message: bytes, offset: int) -> int:
    while True:
        length = message[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length


def record_end(message: bytes, offset: int) -> tuple[int, int]:
    name_end = skip_name(message, offset)
    record_type = int.from_bytes(message[name_end : name_end + 2], "big")
    length = int.from_bytes(message[name_end + 8 : name_end + 10], "big")
    return record_type, name_end + 10 + length


def request_ecs(message: bytes) -> dict[str, Any] | None:
    counts = [
        int.from_bytes(message[index : index + 2], "big")
        for index in (4, 6, 8, 10)
    ]
    offset = 12
    for _ in range(counts[0]):
        offset = skip_name(message, offset) + 4
    for count in counts[1:3]:
        for _ in range(count):
            _, offset = record_end(message, offset)
    for _ in range(counts[3]):
        name_end = skip_name(message, offset)
        record_type, end = record_end(message, offset)
        if record_type == 41:
            option_offset = name_end + 10
            while option_offset < end:
                code = int.from_bytes(message[option_offset : option_offset + 2], "big")
                length = int.from_bytes(
                    message[option_offset + 2 : option_offset + 4], "big"
                )
                data = message[option_offset + 4 : option_offset + 4 + length]
                if code == 8:
                    family = int.from_bytes(data[:2], "big")
                    prefix = data[2]
                    width = 4 if family == 1 else 16
                    address = data[4:] + bytes(width - len(data[4:]))
                    decoded = ipaddress.ip_address(address)
                    return {
                        "family": family,
                        "prefix": prefix,
                        "address": str(decoded),
                    }
                option_offset += 4 + length
        offset = end
    return None


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


def typed_query(name: str, identifier: int, record_type: int) -> bytes:
    query = bytearray(dns_query(name, identifier))
    query[-4:-2] = record_type.to_bytes(2, "big")
    return bytes(query)


def rr(record_type: int, data: bytes, owner: bytes = b"\xc0\x0c") -> bytes:
    return (
        owner
        + record_type.to_bytes(2, "big")
        + b"\x00\x01\x00\x00\x00\x1e"
        + len(data).to_bytes(2, "big")
        + data
    )


class WrapperAuthorityState:
    def __init__(self, mode: str, wait_for: int = 1) -> None:
        self.mode = mode
        self.wait_for = wait_for
        self.condition = threading.Condition()
        self.frames: list[dict[str, Any]] = []

    def answer(self, query: bytes, transport: str) -> bytes:
        end = dns_question_end(query)
        qtype = int.from_bytes(query[end - 4 : end - 2], "big")
        with self.condition:
            self.frames.append(
                {"transport": transport, "qtype": qtype, "ecs": request_ecs(query)}
            )
            self.condition.notify_all()
            deadline = time.monotonic() + IO_DEADLINE
            while len(self.frames) < self.wait_for and time.monotonic() < deadline:
                self.condition.wait(deadline - time.monotonic())

        if self.mode == "filter":
            answers = [
                rr(1, socket.inet_aton("192.0.2.10")),
                rr(5, dns_name("alias.phase4f6.test")),
                rr(28, ipaddress.IPv6Address("2001:db8::10").packed),
            ]
            authority = [
                rr(1, socket.inet_aton("192.0.2.11")),
                rr(2, dns_name("ns.phase4f6.test")),
            ]
            additional = [
                rr(1, socket.inet_aton("192.0.2.12")),
                rr(16, b"\x08retained"),
            ]
            return (
                query[:2]
                + b"\x81\x80\x00\x01"
                + len(answers).to_bytes(2, "big")
                + len(authority).to_bytes(2, "big")
                + len(additional).to_bytes(2, "big")
                + query[12:end]
                + b"".join(answers + authority + additional)
            )

        answer = rr(1, socket.inet_aton("192.0.2.42"))
        return query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:end] + answer

    def snapshot(self) -> list[dict[str, Any]]:
        with self.condition:
            return sorted(
                self.frames,
                key=lambda frame: json.dumps(frame, sort_keys=True),
            )


def response_sections(message: bytes) -> dict[str, Any]:
    counts = [
        int.from_bytes(message[index : index + 2], "big")
        for index in (4, 6, 8, 10)
    ]
    offset = 12
    for _ in range(counts[0]):
        offset = skip_name(message, offset) + 4
    sections: list[list[int]] = []
    for count in counts[1:]:
        types = []
        for _ in range(count):
            record_type, offset = record_end(message, offset)
            types.append(record_type)
        sections.append(types)
    return {
        "flags": message[2:4].hex(),
        "questions": counts[0],
        "answer-types": sections[0],
        "authority-types": sections[1],
        "additional-types": sections[2],
    }


def empty_response(message: bytes, identifier: int) -> dict[str, Any]:
    return {
        "id-echoed": int.from_bytes(message[:2], "big") == identifier,
        "flags": message[2:4].hex(),
        "questions": int.from_bytes(message[4:6], "big"),
        "answers": int.from_bytes(message[6:8], "big"),
        "authority": int.from_bytes(message[8:10], "big"),
        "additional": int.from_bytes(message[10:12], "big"),
    }


def run_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    *,
    transport: str,
    fragments: list[str],
    query: bytes,
    mode: str = "answer",
    wait_for: int = 1,
    response_mode: str = "answer",
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = LocalAuthority("answer")
    state = WrapperAuthorityState(mode, wait_for)
    authority.tcp.state = state  # type: ignore[attr-defined]
    authority.udp.state = state  # type: ignore[attr-defined]
    nameservers = [
        f"{transport}://127.0.0.1:{authority.port}#{fragment}"
        for fragment in fragments
    ]
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(config_text(dns_port, nameservers))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        response = udp_query(dns_port, query)
        deadline = time.monotonic() + 0.5
        while len(state.snapshot()) < wait_for and time.monotonic() < deadline:
            time.sleep(0.01)
        identifier = int.from_bytes(query[:2], "big")
        if response_mode == "empty":
            observed_response = empty_response(response, identifier)
        elif response_mode == "filter":
            observed_response = response_sections(response)
        else:
            observed_response = observe_response(response, identifier)
        exit_code = stop(process)
        return {
            "response": observed_response,
            "frames": state.snapshot(),
            "exit-code": exit_code,
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def validation(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, int]:
    scratch.mkdir(parents=True, exist_ok=True)
    port = reserve_port()
    cases = {
        "valid": [f"udp://127.0.0.1:{port}#ecs=203.0.113.129/24&disable-qtype-65=true"],
        "false-invalid": [f"tcp://127.0.0.1:{port}#ecs=bad&disable-ipv4=false&disable-qtype-65535=true"],
        "different-wrappers": [
            f"udp://127.0.0.1:{port}#ecs=203.0.113.1/24",
            f"udp://127.0.0.1:{port}#disable-ipv4=true",
        ],
    }
    results = {}
    for name, nameservers in cases.items():
        path = scratch / f"{name}.yaml"
        path.write_text(config_text(reserve_port(), nameservers))
        results[name] = subprocess.run(
            [str(binary), "-t", "-f", str(path)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
    return results


def exercise_transport(
    binary: pathlib.Path, scratch: pathlib.Path, transport: str
) -> dict[str, Any]:
    existing = with_ecs(
        typed_query(f"preserve-{transport}.phase4f6.test", 0xF610, 1),
        family=1,
        prefix=24,
        address=bytes([198, 51, 100]),
    )
    return {
        "ecs-inject": run_case(
            binary,
            scratch / "ecs-inject",
            transport=transport,
            fragments=["ecs=203.0.113.129/24"],
            query=typed_query(f"inject-{transport}.phase4f6.test", 0xF611, 1),
        ),
        "ecs-preserve": run_case(
            binary,
            scratch / "ecs-preserve",
            transport=transport,
            fragments=["ecs=203.0.113.129/24"],
            query=existing,
        ),
        "ecs-override": run_case(
            binary,
            scratch / "ecs-override",
            transport=transport,
            fragments=["ecs=203.0.113.129/24&ecs-override=true"],
            query=existing.replace(b"preserve", b"override"),
        ),
        "ecs-ipv6": run_case(
            binary,
            scratch / "ecs-ipv6",
            transport=transport,
            fragments=["ecs=2001:db8:abcd:1234::1/56"],
            query=typed_query(f"ipv6-{transport}.phase4f6.test", 0xF612, 1),
        ),
        "disable-a": run_case(
            binary,
            scratch / "disable-a",
            transport=transport,
            fragments=["disable-ipv4=true"],
            query=typed_query(f"disable-a-{transport}.phase4f6.test", 0xF613, 1),
            wait_for=0,
            response_mode="empty",
        ),
        "disable-aaaa": run_case(
            binary,
            scratch / "disable-aaaa",
            transport=transport,
            fragments=["disable-ipv6=true"],
            query=typed_query(f"disable-aaaa-{transport}.phase4f6.test", 0xF618, 28),
            wait_for=0,
            response_mode="empty",
        ),
        "disable-type65": run_case(
            binary,
            scratch / "disable-type65",
            transport=transport,
            fragments=["disable-qtype-65=true"],
            query=typed_query(f"disable-65-{transport}.phase4f6.test", 0xF614, 65),
            wait_for=0,
            response_mode="empty",
        ),
        "filter-sections": run_case(
            binary,
            scratch / "filter-sections",
            transport=transport,
            fragments=["disable-ipv4=true"],
            query=typed_query(f"filter-{transport}.phase4f6.test", 0xF615, 5),
            mode="filter",
            response_mode="filter",
        ),
        "false-invalid": run_case(
            binary,
            scratch / "false-invalid",
            transport=transport,
            fragments=["ecs=bad&ecs-override=true&disable-ipv4=false&disable-qtype-invalid=true&disable-qtype-65535=true"],
            query=typed_query(f"invalid-{transport}.phase4f6.test", 0xF616, 1),
        ),
        "transport-identity": run_case(
            binary,
            scratch / "transport-identity",
            transport=transport,
            fragments=[
                "ecs=192.0.2.129/24",
                "ecs=192.0.2.129/24",
                "ecs=198.51.100.129/24",
            ],
            query=typed_query(f"identity-{transport}.phase4f6.test", 0xF617, 1),
            wait_for=2,
        ),
    }


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    return {
        "config": validation(binary, scratch / "config"),
        "udp": exercise_transport(binary, scratch / "udp", "udp"),
        "tcp": exercise_transport(binary, scratch / "tcp", "tcp"),
    }


def answer_ok(case: dict[str, Any], ecs: dict[str, Any] | None) -> bool:
    return (
        case["response"].get("address") == "192.0.2.42"
        and len(case["frames"]) == 1
        and case["frames"][0]["ecs"] == ecs
        and case["exit-code"] == 0
    )


def empty_ok(case: dict[str, Any]) -> bool:
    return (
        case["response"]
        == {
            "id-echoed": True,
            "flags": "8580",
            "questions": 1,
            "answers": 0,
            "authority": 0,
            "additional": 0,
        }
        and case["frames"] == []
        and case["exit-code"] == 0
    )


def satisfies_contract(observation: dict[str, Any]) -> bool:
    if observation["config"] != {
        "valid": 0,
        "false-invalid": 0,
        "different-wrappers": 0,
    }:
        return False
    for transport in ("udp", "tcp"):
        cases = observation[transport]
        if not (
            answer_ok(
                cases["ecs-inject"],
                {"family": 1, "prefix": 24, "address": "203.0.113.0"},
            )
            and answer_ok(
                cases["ecs-preserve"],
                {"family": 1, "prefix": 24, "address": "198.51.100.0"},
            )
            and answer_ok(
                cases["ecs-override"],
                {"family": 1, "prefix": 24, "address": "203.0.113.0"},
            )
            and answer_ok(
                cases["ecs-ipv6"],
                {"family": 2, "prefix": 56, "address": "2001:db8:abcd:1200::"},
            )
            and empty_ok(cases["disable-a"])
            and empty_ok(cases["disable-aaaa"])
            and empty_ok(cases["disable-type65"])
            and cases["filter-sections"]["response"]
            == {
                "flags": "8580",
                "questions": 1,
                "answer-types": [5, 28],
                "authority-types": [2],
                "additional-types": [16],
            }
            and len(cases["filter-sections"]["frames"]) == 1
            and cases["filter-sections"]["exit-code"] == 0
            and answer_ok(cases["false-invalid"], None)
        ):
            return False
        identity = cases["transport-identity"]
        if identity["response"].get("address") != "192.0.2.42" or identity["exit-code"] != 0:
            return False
        if [frame["ecs"] for frame in identity["frames"]] != [
            {"family": 1, "prefix": 24, "address": "192.0.2.0"},
            {"family": 1, "prefix": 24, "address": "198.51.100.0"},
        ]:
            return False
    return True


def run_identity_contracts() -> None:
    subprocess.run(
        [
            "go",
            "test",
            "./dns",
            "-run",
            "^TestPhase4F6ClassicWrapperTransportIdentity$",
            "-count=1",
        ],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        ["cargo", "test", "-p", "rewrite-config", "phase_four_f_six"],
        cwd=RUST_ROOT,
        check=True,
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    run_identity_contracts()
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f6-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if observations["go"] != observations["rust"] or not satisfies_contract(
            observations["go"]
        ):
            FAILURE_ARTIFACT.write_text(
                json.dumps(observations, indent=2, sort_keys=True)
            )
            raise SystemExit(f"Phase 4F6 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F6 classic DNS wrapper differential passed")


if __name__ == "__main__":
    main()

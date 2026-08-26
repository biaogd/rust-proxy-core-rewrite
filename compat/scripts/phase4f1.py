#!/usr/bin/env python3
"""Go/Rust differential suite for Phase 4F1 local DNS message semantics."""

from __future__ import annotations

import ipaddress
import json
import pathlib
import socket
import socketserver
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, reserve_port
from phase4 import (
    build_binaries,
    dns_name,
    launch,
    recv_exact,
    render_config,
    stop,
    udp_query,
    wait_dns_ready,
)


ROOT = pathlib.Path(__file__).resolve().parents[2]
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f1-diff.json"


def skip_name(message: bytes, offset: int) -> int:
    while True:
        length = message[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length


def decode_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    end: int | None = None
    seen: set[int] = set()
    while True:
        if offset in seen:
            raise ValueError("DNS name pointer loop")
        seen.add(offset)
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | message[offset + 1]
            continue
        offset += 1
        if length == 0:
            return ".".join(labels), end if end is not None else offset
        labels.append(message[offset : offset + length].decode("ascii"))
        offset += length


def question_end(message: bytes) -> int:
    return skip_name(message, 12) + 4


def query(
    name: str,
    identifier: int,
    record_type: int = 1,
    *,
    udp_size: int | None = None,
    do: bool = False,
) -> bytes:
    message = bytearray(
        identifier.to_bytes(2, "big")
        + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + dns_name(name)
        + record_type.to_bytes(2, "big")
        + b"\x00\x01"
    )
    if udp_size is not None:
        message[10:12] = b"\x00\x01"
        message.extend(
            b"\x00\x00\x29"
            + udp_size.to_bytes(2, "big")
            + (0x8000 if do else 0).to_bytes(4, "big")
            + b"\x00\x00"
        )
    return bytes(message)


def rr(record_type: int, data: bytes, *, ttl: int = 30, owner: bytes = b"\xc0\x0c") -> bytes:
    return (
        owner
        + record_type.to_bytes(2, "big")
        + b"\x00\x01"
        + ttl.to_bytes(4, "big")
        + len(data).to_bytes(2, "big")
        + data
    )


def opt(udp_size: int, *, do: bool) -> bytes:
    return (
        b"\x00\x00\x29"
        + udp_size.to_bytes(2, "big")
        + (0x8000 if do else 0).to_bytes(4, "big")
        + b"\x00\x00"
    )


def response(
    request: bytes,
    flags: int,
    *,
    answers: list[bytes] | None = None,
    authority: list[bytes] | None = None,
    additional: list[bytes] | None = None,
) -> bytes:
    answers = answers or []
    authority = authority or []
    additional = additional or []
    end = question_end(request)
    return (
        request[:2]
        + flags.to_bytes(2, "big")
        + b"\x00\x01"
        + len(answers).to_bytes(2, "big")
        + len(authority).to_bytes(2, "big")
        + len(additional).to_bytes(2, "big")
        + request[12:end]
        + b"".join(answers)
        + b"".join(authority)
        + b"".join(additional)
    )


def request_edns(message: bytes) -> dict[str, Any] | None:
    try:
        counts = [
            int.from_bytes(message[index : index + 2], "big")
            for index in (4, 6, 8, 10)
        ]
        offset = 12
        for _ in range(counts[0]):
            offset = skip_name(message, offset) + 4
        for section, count in enumerate(counts[1:]):
            for _ in range(count):
                name_end = skip_name(message, offset)
                record_type = int.from_bytes(message[name_end : name_end + 2], "big")
                record_class = int.from_bytes(message[name_end + 2 : name_end + 4], "big")
                ttl = int.from_bytes(message[name_end + 4 : name_end + 8], "big")
                length = int.from_bytes(message[name_end + 8 : name_end + 10], "big")
                offset = name_end + 10 + length
                if section == 2 and record_type == 41:
                    return {"udp-size": record_class, "do": bool(ttl & 0x8000)}
    except IndexError:
        return {"malformed": True}
    return None


class AuthorityState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.queries: list[dict[str, Any]] = []

    def answer(self, request: bytes, transport: str) -> bytes:
        name, end = decode_name(request, 12)
        qtype = int.from_bytes(request[end : end + 2], "big")
        with self.lock:
            self.queries.append(
                {
                    "transport": transport,
                    "name": name,
                    "qtype": qtype,
                    "edns": request_edns(request),
                }
            )

        if name.startswith("rrset-"):
            alias = dns_name("alias.phase4.test")
            mail = dns_name("mail.phase4.test")
            soa = (
                dns_name("ns.phase4.test")
                + dns_name("hostmaster.phase4.test")
                + b"".join(value.to_bytes(4, "big") for value in (7, 60, 60, 600, 30))
            )
            return response(
                request,
                0x8180,
                answers=[
                    rr(5, alias),
                    rr(15, b"\x00\x0a" + mail),
                    rr(16, b"\x05phase\x05fourf\x03one"),
                    rr(65280, b"\xde\xad\xbe\xef"),
                ],
                authority=[rr(6, soa)],
                additional=[rr(1, socket.inet_aton("192.0.2.44"), owner=mail)],
            )
        if name.startswith("nxdomain-"):
            soa = (
                dns_name("ns.phase4.test")
                + dns_name("hostmaster.phase4.test")
                + b"".join(value.to_bytes(4, "big") for value in (8, 60, 60, 600, 30))
            )
            return response(request, 0x8183, authority=[rr(6, soa)])
        if name.startswith("empty-"):
            return response(request, 0x8180)
        if name.startswith("notimp-"):
            return response(request, 0x8184)
        if name.startswith("servfail-"):
            return response(request, 0x8182)
        if name.startswith("refused-"):
            return response(request, 0x8185)
        if name.startswith("upstream-opt-"):
            return response(
                request,
                0x8180,
                answers=[rr(1, socket.inet_aton("192.0.2.42"))],
                additional=[opt(4096, do=False)],
            )
        if name.startswith("large-"):
            answers = [
                rr(16, bytes([180]) + bytes([65 + index]) * 180, ttl=0)
                for index in range(10)
            ]
            return response(request, 0x8180, answers=answers)
        return response(
            request,
            0x8180,
            answers=[rr(1, socket.inet_aton("192.0.2.42"))],
        )

    def first(self, name: str) -> dict[str, Any] | None:
        with self.lock:
            return next((query for query in self.queries if query["name"] == name), None)


class TCPAuthority(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TCPAuthorityHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        state: AuthorityState = self.server.state  # type: ignore[attr-defined]
        while True:
            try:
                length = int.from_bytes(recv_exact(self.request, 2), "big")
                request = recv_exact(self.request, length)
            except (EOFError, OSError):
                return
            reply = state.answer(request, "tcp")
            self.request.sendall(len(reply).to_bytes(2, "big") + reply)


class LocalAuthority:
    def __init__(self) -> None:
        self.state = AuthorityState()
        self.server = TCPAuthority(("127.0.0.1", 0), TCPAuthorityHandler)
        self.server.state = self.state  # type: ignore[attr-defined]
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=IO_DEADLINE)


def record_data(message: bytes, record_type: int, start: int, end: int) -> Any:
    data = message[start:end]
    if record_type == 1:
        return str(ipaddress.IPv4Address(data))
    if record_type == 28:
        return str(ipaddress.IPv6Address(data))
    if record_type in (2, 5, 12):
        return decode_name(message, start)[0]
    if record_type == 15:
        return {
            "preference": int.from_bytes(data[:2], "big"),
            "exchange": decode_name(message, start + 2)[0],
        }
    if record_type == 16:
        values: list[str] = []
        offset = start
        while offset < end:
            length = message[offset]
            offset += 1
            values.append(message[offset : offset + length].decode("ascii"))
            offset += length
        return values
    if record_type == 6:
        primary, offset = decode_name(message, start)
        mailbox, offset = decode_name(message, offset)
        return {
            "primary": primary,
            "mailbox": mailbox,
            "values": [
                int.from_bytes(message[index : index + 4], "big")
                for index in range(offset, end, 4)
            ],
        }
    return data.hex()


def observe_response(message: bytes, identifier: int) -> dict[str, Any]:
    counts = [int.from_bytes(message[index : index + 2], "big") for index in (4, 6, 8, 10)]
    offset = 12
    questions = []
    for _ in range(counts[0]):
        name, offset = decode_name(message, offset)
        questions.append(
            {
                "name": name,
                "type": int.from_bytes(message[offset : offset + 2], "big"),
                "class": int.from_bytes(message[offset + 2 : offset + 4], "big"),
            }
        )
        offset += 4
    sections: list[list[dict[str, Any]]] = [[], [], []]
    for section, count in enumerate(counts[1:]):
        for _ in range(count):
            owner, name_end = decode_name(message, offset)
            record_type = int.from_bytes(message[name_end : name_end + 2], "big")
            record_class = int.from_bytes(message[name_end + 2 : name_end + 4], "big")
            ttl = int.from_bytes(message[name_end + 4 : name_end + 8], "big")
            length = int.from_bytes(message[name_end + 8 : name_end + 10], "big")
            start = name_end + 10
            end = start + length
            record = {"owner": owner, "type": record_type}
            if record_type == 41:
                record.update({"udp-size": record_class, "do": bool(ttl & 0x8000)})
            else:
                record.update(
                    {
                        "class": record_class,
                        "ttl": ttl,
                        "data": record_data(message, record_type, start, end),
                    }
                )
            sections[section].append(record)
            offset = end
    flags = int.from_bytes(message[2:4], "big")
    observed = {
        "id-echoed": int.from_bytes(message[:2], "big") == identifier,
        "flags": f"{flags:04x}",
        "rcode": flags & 0xF,
        "tc": bool(flags & 0x0200),
        "questions": questions,
        "answer": sections[0],
        "authority": sections[1],
        "additional": sections[2],
    }
    if questions and questions[0]["name"].startswith("large-"):
        observed["length"] = len(message)
    return observed


def tcp_outcome(port: int, request: bytes, identifier: int) -> dict[str, Any]:
    with socket.create_connection(("127.0.0.1", port), timeout=IO_DEADLINE) as client:
        client.settimeout(0.3)
        client.sendall(len(request).to_bytes(2, "big") + request)
        try:
            length = int.from_bytes(recv_exact(client, 2), "big")
            return {"response": observe_response(recv_exact(client, length), identifier)}
        except socket.timeout:
            return {"outcome": "timeout"}
        except EOFError:
            return {"outcome": "eof"}


def udp_outcome(port: int, request: bytes, identifier: int) -> dict[str, Any]:
    try:
        return {"response": observe_response(udp_query(port, request), identifier)}
    except socket.timeout:
        return {"outcome": "timeout"}


def invalid_cases() -> dict[str, bytes]:
    first = query("first.phase4.test", 0xF101)
    second_question = dns_name("second.phase4.test") + b"\x00\x01\x00\x01"
    zero = bytearray(first[:12])
    zero[4:6] = b"\x00\x00"
    two = bytearray(first + second_question)
    two[4:6] = b"\x00\x02"
    opcode = bytearray(first)
    opcode[2] = 0x29
    answer_count = bytearray(first)
    answer_count[6:8] = b"\x00\x02"
    authority_count = bytearray(first)
    authority_count[8:10] = b"\x00\x02"
    additional_count = bytearray(first)
    additional_count[10:12] = b"\x00\x03"
    malformed_question = first[:12] + b"\x05bad"
    qr = bytearray(first)
    qr[2] |= 0x80
    return {
        "zero-question": bytes(zero),
        "two-questions": bytes(two),
        "unsupported-opcode": bytes(opcode),
        "too-many-answers": bytes(answer_count),
        "too-many-authority": bytes(authority_count),
        "too-many-additional": bytes(additional_count),
        "malformed-question": malformed_question,
        "response-bit": bytes(qr),
        "short-header": b"\xf1\x09\x01\x00\x00",
    }


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = LocalAuthority()
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=reserve_port(),
        dns_port=dns_port,
        upstream_port=authority.port,
        upstream_transport="tcp",
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        regular: dict[str, Any] = {}
        scenarios = [
            ("rrset-udp.phase4.test", 0xF201, 255, "udp", None, False),
            ("rrset-tcp.phase4.test", 0xF202, 255, "tcp", None, False),
            ("nxdomain-udp.phase4.test", 0xF211, 1, "udp", None, False),
            ("empty-tcp.phase4.test", 0xF212, 1, "tcp", None, False),
            ("notimp-udp.phase4.test", 0xF213, 1, "udp", None, False),
            ("servfail-udp.phase4.test", 0xF214, 1, "udp", None, False),
            ("refused-tcp.phase4.test", 0xF215, 1, "tcp", None, False),
            ("edns-echo-udp.phase4.test", 0xF221, 1, "udp", 1400, True),
            ("edns-echo-tcp.phase4.test", 0xF222, 1, "tcp", 1400, True),
            ("upstream-opt-udp.phase4.test", 0xF223, 1, "udp", 1400, True),
            ("large-512.phase4.test", 0xF231, 16, "udp", None, False),
            ("large-256.phase4.test", 0xF232, 16, "udp", 256, False),
            ("large-900.phase4.test", 0xF233, 16, "udp", 900, True),
            ("large-tcp.phase4.test", 0xF234, 16, "tcp", 256, True),
        ]
        for name, identifier, qtype, transport, udp_size, do in scenarios:
            request = query(name, identifier, qtype, udp_size=udp_size, do=do)
            reply = (
                udp_query(dns_port, request)
                if transport == "udp"
                else tcp_outcome(dns_port, request, identifier)["response"]
            )
            regular[name] = (
                observe_response(reply, identifier)
                if isinstance(reply, bytes)
                else reply
            )

        validation: dict[str, Any] = {}
        for name, request in invalid_cases().items():
            identifier = int.from_bytes(request[:2], "big") if len(request) >= 2 else 0
            validation[name] = {
                "udp": udp_outcome(dns_port, request, identifier),
                "tcp": tcp_outcome(dns_port, request, identifier),
            }

        forwarded = {
            name: authority.state.first(name)
            for name in (
                "edns-echo-udp.phase4.test",
                "edns-echo-tcp.phase4.test",
                "upstream-opt-udp.phase4.test",
            )
        }
        time.sleep(0.1)
        return {
            "regular": regular,
            "validation": validation,
            "forwarded": forwarded,
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def response_of(observation: dict[str, Any], name: str) -> dict[str, Any]:
    return observation["regular"][name]


def satisfies_contract(observation: dict[str, Any]) -> bool:
    validation = observation["validation"]
    rejected = (
        "zero-question",
        "two-questions",
        "too-many-answers",
        "too-many-authority",
        "too-many-additional",
        "malformed-question",
    )
    if any(
        validation[name][transport].get("response", {}).get("rcode") != 1
        for name in rejected
        for transport in ("udp", "tcp")
    ):
        return False
    if any(
        validation["unsupported-opcode"][transport]
        .get("response", {})
        .get("rcode")
        != 4
        for transport in ("udp", "tcp")
    ):
        return False
    if any(
        validation[name][transport] != {"outcome": "timeout"}
        for name in ("response-bit", "short-header")
        for transport in ("udp", "tcp")
    ):
        return False

    rrset = response_of(observation, "rrset-udp.phase4.test")
    if (
        [record["type"] for record in rrset["answer"]] != [5, 15, 16, 65280]
        or [record["type"] for record in rrset["authority"]] != [6]
        or [record["type"] for record in rrset["additional"]] != [1]
    ):
        return False
    if response_of(observation, "nxdomain-udp.phase4.test")["rcode"] != 3:
        return False
    if response_of(observation, "notimp-udp.phase4.test")["rcode"] != 4:
        return False
    for name in ("servfail-udp.phase4.test", "refused-tcp.phase4.test"):
        reply = response_of(observation, name)
        if reply["rcode"] != 2 or int(reply["flags"], 16) & 0x0400:
            return False

    for name in ("edns-echo-udp.phase4.test", "edns-echo-tcp.phase4.test"):
        extras = response_of(observation, name)["additional"]
        if extras != [{"owner": "", "type": 41, "udp-size": 1232, "do": True}]:
            return False
    upstream_opt = response_of(observation, "upstream-opt-udp.phase4.test")["additional"]
    if upstream_opt != [{"owner": "", "type": 41, "udp-size": 4096, "do": False}]:
        return False
    if any(
        forwarded is None or forwarded["edns"] != {"udp-size": 1400, "do": True}
        for forwarded in observation["forwarded"].values()
    ):
        return False

    truncated_512 = response_of(observation, "large-512.phase4.test")
    truncated_256 = response_of(observation, "large-256.phase4.test")
    truncated_900 = response_of(observation, "large-900.phase4.test")
    full = response_of(observation, "large-tcp.phase4.test")
    return (
        truncated_512["tc"]
        and truncated_512["length"] <= 512
        and truncated_256["tc"]
        and truncated_256["length"] <= 512
        and truncated_900["tc"]
        and truncated_900["length"] <= 900
        and len(truncated_900["answer"]) > len(truncated_512["answer"])
        and not full["tc"]
        and len(full["answer"]) == 10
        and observation["exit-code"] == 0
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f1-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: exercise(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if observations["go"] != observations["rust"] or not satisfies_contract(
            observations["go"]
        ):
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4F1 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F1 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

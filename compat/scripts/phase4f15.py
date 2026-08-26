#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 4F15 DNS control surfaces."""

from __future__ import annotations

import base64
import http.client
import json
import pathlib
import socket
import socketserver
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase4 import build_binaries, launch, stop, wait_dns_ready
from phase4b import make_query, parse_query
from phase4d4 import wait_rest_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f15-diff.json"
SECRET = "phase4f15-secret"
RECORD_TYPES = {
    "None": 0, "A": 1, "NS": 2, "MD": 3, "MF": 4, "CNAME": 5,
    "SOA": 6, "MB": 7, "MG": 8, "MR": 9, "NULL": 10, "PTR": 12,
    "HINFO": 13, "MINFO": 14, "MX": 15, "TXT": 16, "RP": 17,
    "AFSDB": 18, "X25": 19, "ISDN": 20, "RT": 21, "NSAP-PTR": 23,
    "SIG": 24, "KEY": 25, "PX": 26, "GPOS": 27, "AAAA": 28,
    "LOC": 29, "NXT": 30, "EID": 31, "NIMLOC": 32, "SRV": 33,
    "ATMA": 34, "NAPTR": 35, "KX": 36, "CERT": 37, "DNAME": 39,
    "OPT": 41, "APL": 42, "DS": 43, "SSHFP": 44, "IPSECKEY": 45,
    "RRSIG": 46, "NSEC": 47, "DNSKEY": 48, "DHCID": 49,
    "NSEC3": 50, "NSEC3PARAM": 51, "TLSA": 52, "SMIMEA": 53,
    "HIP": 55, "NINFO": 56, "RKEY": 57, "TALINK": 58, "CDS": 59,
    "CDNSKEY": 60, "OPENPGPKEY": 61, "CSYNC": 62, "ZONEMD": 63,
    "SVCB": 64, "HTTPS": 65, "SPF": 99, "UINFO": 100, "UID": 101,
    "GID": 102, "UNSPEC": 103, "NID": 104, "L32": 105, "L64": 106,
    "LP": 107, "EUI48": 108, "EUI64": 109, "NXNAME": 128,
    "TKEY": 249, "TSIG": 250, "IXFR": 251, "AXFR": 252, "MAILB": 253,
    "MAILA": 254, "ANY": 255, "URI": 256, "CAA": 257, "AVC": 258,
    "AMTRELAY": 260, "TA": 32768, "DLV": 32769, "Reserved": 65535,
}


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


class AuthorityState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.counts: dict[tuple[str, int], int] = {}

    def respond(self, query: bytes) -> bytes:
        name, record_type, question_end = parse_query(query)
        with self.lock:
            key = (name, record_type)
            self.counts[key] = self.counts.get(key, 0) + 1
            count = self.counts[key]
        rdata = self.rdata(name, record_type, count)
        answer = b""
        answer_count = 0
        if rdata is not None:
            answer = (
                b"\xc0\x0c"
                + record_type.to_bytes(2, "big")
                + b"\x00\x01"
                + (30).to_bytes(4, "big")
                + len(rdata).to_bytes(2, "big")
                + rdata
            )
            answer_count = 1
        return (
            query[:2]
            + b"\x81\x80\x00\x01"
            + answer_count.to_bytes(2, "big")
            + b"\x00\x00\x00\x00"
            + query[12:question_end]
            + answer
        )

    @staticmethod
    def rdata(name: str, record_type: int, count: int) -> bytes | None:
        if record_type == 1:
            suffix = min(250, 40 + count) if name.startswith("cache.") else 45
            return socket.inet_aton(f"192.0.2.{suffix}")
        if record_type == 6:
            return (
                dns_name("ns.phase4f15.test")
                + dns_name("hostmaster.phase4f15.test")
                + (2026082601).to_bytes(4, "big")
                + (3600).to_bytes(4, "big")
                + (600).to_bytes(4, "big")
                + (86400).to_bytes(4, "big")
                + (60).to_bytes(4, "big")
            )
        if record_type == 15:
            return (10).to_bytes(2, "big") + dns_name("mail.phase4f15.test")
        if record_type == 16:
            return b"\x05hello\x05world"
        if record_type == 33:
            return b"\x00\x01\x00\x02\x01\xbb" + dns_name("service.phase4f15.test")
        if record_type == 257:
            return b"\x00\x05issueletsencrypt.org"
        return None


class AuthorityServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class AuthorityHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, server_socket = self.request
        state: AuthorityState = self.server.state  # type: ignore[attr-defined]
        server_socket.sendto(state.respond(query), self.client_address)


class LocalAuthority:
    def __init__(self) -> None:
        self.state = AuthorityState()
        self.server = AuthorityServer(("127.0.0.1", 0), AuthorityHandler)
        self.server.state = self.state  # type: ignore[attr-defined]
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=IO_DEADLINE)


def render_config(
    path: pathlib.Path,
    *,
    controller_port: int,
    dns_port: int,
    authority_port: int,
    enabled: bool = True,
) -> None:
    dns = ""
    if enabled:
        dns = f"""dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  nameserver:
    - udp://127.0.0.1:{authority_port}
"""
    path.write_text(
        f"""mixed-port: {reserve_port()}
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:{controller_port}
external-doh-server: /dns-query
secret: {SECRET}
{dns}rules:
  - MATCH,DIRECT
"""
    )


def request(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    content_type: str | None = None,
    authorized: bool = True,
) -> tuple[int, str | None, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    headers = {"Authorization": f"Bearer {SECRET}"} if authorized else {}
    if content_type is not None:
        headers["Content-Type"] = content_type
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    result = (response.status, response.getheader("Content-Type"), response.read())
    connection.close()
    return result


def chunked_doh_request(port: int, body: bytes) -> tuple[int, str | None, bytes]:
    connection = socket.create_connection(("127.0.0.1", port), timeout=IO_DEADLINE)
    connection.settimeout(IO_DEADLINE)
    midpoint = len(body) // 2
    chunks = [body[:midpoint], body[midpoint:]]
    request_head = (
        "POST /dns-query HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Content-Type: application/dns-message\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    encoded = b"".join(
        f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n" for chunk in chunks
    ) + b"0\r\n\r\n"
    connection.sendall(request_head + encoded)
    response = http.client.HTTPResponse(connection)
    response.begin()
    result = (response.status, response.getheader("Content-Type"), response.read())
    connection.close()
    return result


def json_request(port: int, path: str, *, authorized: bool = True) -> dict[str, Any]:
    status, content_type, body = request(port, "GET", path, authorized=authorized)
    return {
        "status": status,
        "content-type": content_type,
        "json": json.loads(body) if body else None,
    }


def normalize_ttl(observation: dict[str, Any]) -> None:
    body = observation["json"]
    if body and body.get("Answer"):
        ttl = body["Answer"][0]["TTL"]
        if not 0 < ttl <= 30:
            raise AssertionError(f"REST TTL outside fixture window: {ttl}")
        body["Answer"][0]["TTL"] = "positive-bounded"


def dns_observation(response: tuple[int, str | None, bytes], identifier: int) -> dict[str, Any]:
    status, content_type, body = response
    if status != 200:
        return {"status": status, "content-type": content_type, "error": "http-error"}
    name, record_type, question_end = parse_query(body)
    answer_count = int.from_bytes(body[6:8], "big")
    data = ""
    if answer_count:
        answer = question_end
        if body[answer : answer + 2] == b"\xc0\x0c":
            answer += 2
        else:
            while body[answer] != 0:
                answer += body[answer] + 1
            answer += 1
        data_length = int.from_bytes(body[answer + 8 : answer + 10], "big")
        data = body[answer + 10 : answer + 10 + data_length].hex()
    return {
        "status": status,
        "content-type": content_type,
        "id-echoed": int.from_bytes(body[:2], "big") == identifier,
        "rcode": body[3] & 0x0F,
        "question": [name, record_type],
        "answers": answer_count,
        "data": data,
    }


def error_observation(response: tuple[int, str | None, bytes]) -> dict[str, Any]:
    status, content_type, body = response
    return {
        "status": status,
        "content-type": content_type,
        "body-class": "non-empty" if body else "empty",
    }


def exercise_enabled(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = LocalAuthority()
    controller_port, dns_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        controller_port=controller_port,
        dns_port=dns_port,
        authority_port=authority.port,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_rest_controller(process, controller_port)
        wait_dns_ready(process, dns_port)
        rest: dict[str, Any] = {}
        for record_type in ["SOA", "MX", "TXT", "SRV", "CAA", "HTTPS", "ANY"]:
            item = json_request(
                controller_port,
                f"/dns/query?name={record_type.lower()}.phase4f15.test&type={record_type}",
            )
            normalize_ttl(item)
            rest[record_type] = item
        rest["default-empty-type"] = json_request(
            controller_port, "/dns/query?name=default.phase4f15.test&type="
        )
        normalize_ttl(rest["default-empty-type"])
        rest["lowercase-invalid"] = json_request(
            controller_port, "/dns/query?name=bad.phase4f15.test&type=soa"
        )
        type_table: dict[str, Any] = {}
        for index, (record_name, record_code) in enumerate(RECORD_TYPES.items()):
            item = json_request(
                controller_port,
                f"/dns/query?name=table-{index}.phase4f15.test&type={record_name}",
            )
            normalize_ttl(item)
            body = item["json"]
            type_table[record_name] = {
                "status": item["status"],
                "question-type": body.get("Question", [{}])[0].get("Qtype")
                if isinstance(body, dict)
                else None,
                "expected-type": record_code,
                "has-answer": bool(body.get("Answer"))
                if isinstance(body, dict)
                else False,
            }
        rest["type-table"] = type_table

        first = json_request(controller_port, "/dns/query?name=cache.phase4f15.test")
        second = json_request(controller_port, "/dns/query?name=cache.phase4f15.test")
        normalize_ttl(first)
        normalize_ttl(second)
        flush = request(controller_port, "POST", "/cache/dns/flush")
        time.sleep(0.1)
        third = json_request(controller_port, "/dns/query?name=cache.phase4f15.test")
        normalize_ttl(third)
        cache = {
            "first-data": first["json"]["Answer"][0]["data"],
            "cached-same": first["json"]["Answer"][0]["data"]
            == second["json"]["Answer"][0]["data"],
            "flush": error_observation(flush),
            "after-flush-changed": first["json"]["Answer"][0]["data"]
            != third["json"]["Answer"][0]["data"],
            "unauthorized": error_observation(
                request(controller_port, "POST", "/cache/dns/flush", authorized=False)
            ),
            "wrong-method": error_observation(
                request(controller_port, "GET", "/cache/dns/flush")
            ),
        }

        query_id = 0x7F15
        query = make_query("doh.phase4f15.test", 1, query_id)
        encoded = base64.urlsafe_b64encode(query).rstrip(b"=").decode()
        doh = {
            "get-public": dns_observation(
                request(
                    controller_port,
                    "GET",
                    f"/dns-query?dns={encoded}",
                    authorized=False,
                ),
                query_id,
            ),
            "post-public": dns_observation(
                request(
                    controller_port,
                    "POST",
                    "/dns-query",
                    body=query,
                    content_type="application/dns-message",
                    authorized=False,
                ),
                query_id,
            ),
            "post-chunked": dns_observation(
                chunked_doh_request(controller_port, query), query_id
            ),
            "child-mount": dns_observation(
                request(
                    controller_port,
                    "GET",
                    f"/dns-query/child?dns={encoded}",
                    authorized=False,
                ),
                query_id,
            ),
            "invalid-base64": error_observation(
                request(controller_port, "GET", "/dns-query?dns=%25", authorized=False)
            ),
            "invalid-content-type": error_observation(
                request(
                    controller_port,
                    "POST",
                    "/dns-query",
                    body=query,
                    content_type="application/octet-stream",
                    authorized=False,
                )
            ),
            "wrong-method": error_observation(
                request(controller_port, "PUT", "/dns-query", authorized=False)
            ),
        }
        result = {"rest": rest, "cache": cache, "doh": doh}
        result["exit-code"] = stop(process)
        return result
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def exercise_disabled(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    controller_port = reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        controller_port=controller_port,
        dns_port=reserve_port(),
        authority_port=reserve_port(),
        enabled=False,
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_rest_controller(process, controller_port)
        result = {
            "doh": error_observation(
                request(controller_port, "GET", "/dns-query", authorized=False)
            ),
            "dns-flush": error_observation(
                request(controller_port, "POST", "/cache/dns/flush")
            ),
            "fakeip-flush": error_observation(
                request(controller_port, "POST", "/cache/fakeip/flush")
            ),
            "exit-code": stop(process),
        }
        return result
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    return {
        "enabled": exercise_enabled(binary, scratch / "enabled"),
        "disabled": exercise_disabled(binary, scratch / "disabled"),
    }


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f15-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4F15 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F15 DNS control differential passed")


if __name__ == "__main__":
    main()

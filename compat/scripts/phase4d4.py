#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4D4 DNS REST control."""

from __future__ import annotations

import http.client
import json
import pathlib
import socket
import subprocess
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port
from phase3 import wait_controller
from phase4 import build_binaries, launch, stop, wait_dns_ready
from phase4b import make_query, parse_query, parse_response, udp_query
from phase4d2 import LocalAuthority


FIXTURE = ROOT / "compat" / "fixtures" / "phase4" / "rest-cache.yaml.tmpl"
DISABLED_FIXTURE = (
    ROOT / "compat" / "fixtures" / "phase4" / "rest-disabled.yaml.tmpl"
)
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4d4-diff.json"
SECRET = "phase4d4-secret"


def authority_response(query: bytes, _transport: str) -> bytes:
    _name, record_type, question_end = parse_query(query)
    if record_type == 1:
        data = socket.inet_aton("192.0.2.44")
    elif record_type == 28:
        data = socket.inet_pton(socket.AF_INET6, "2001:db8::44")
    elif record_type == 5:
        labels = ["alias", "phase4", "test"]
        data = b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\0"
    else:
        data = b""
    answer = b""
    count = 0
    if data:
        answer = (
            b"\xc0\x0c"
            + record_type.to_bytes(2, "big")
            + b"\x00\x01"
            + (30).to_bytes(4, "big")
            + len(data).to_bytes(2, "big")
            + data
        )
        count = 1
    return (
        query[:2]
        + b"\x81\x80\x00\x01"
        + count.to_bytes(2, "big")
        + b"\x00\x00\x00\x00"
        + query[12:question_end]
        + answer
    )


def request(
    port: int,
    method: str,
    path: str,
    *,
    authorized: bool = True,
) -> dict[str, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    headers = {"Authorization": f"Bearer {SECRET}"} if authorized else {}
    connection.request(method, path, headers=headers)
    response = connection.getresponse()
    body = response.read()
    observation: dict[str, Any] = {
        "status": response.status,
        "content-type": response.getheader("Content-Type"),
        "body-empty": body == b"",
    }
    if body:
        observation["json"] = json.loads(body)
    connection.close()
    return observation


def wait_rest_controller(process: subprocess.Popen[bytes], port: int) -> None:
    # Keep request timeouts strict while allowing a contended candidate two
    # scheduling windows to publish its controller listener.
    deadline = time.monotonic() + (2 * IO_DEADLINE) + 1
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"candidate exited during controller startup: {process.returncode}")
        try:
            observation = request(port, "GET", "/version", authorized=False)
            if observation["status"] == 401:
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("controller did not become ready")


def normalize_cached_ttl(observation: dict[str, Any]) -> None:
    ttl = observation["json"]["Answer"][0]["TTL"]
    if not 0 < ttl <= 30:
        raise AssertionError(f"cached REST TTL is not positive and bounded: {ttl}")
    observation["json"]["Answer"][0]["TTL"] = "positive-bounded"


def render_config(
    path: pathlib.Path,
    mixed_port: int,
    controller_port: int,
    dns_port: int,
    upstream_port: int,
) -> None:
    path.write_text(
        FIXTURE.read_text()
        .replace("${MIXED_PORT}", str(mixed_port))
        .replace("${CONTROLLER_PORT}", str(controller_port))
        .replace("${DNS_PORT}", str(dns_port))
        .replace("${UPSTREAM_PORT}", str(upstream_port))
    )


def exercise_enabled(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = LocalAuthority("192.0.2.44")

    def tracked_response(query: bytes, transport: str) -> bytes:
        name, record_type, _question_end = parse_query(query)
        with authority.state.lock:
            authority.state.questions.append([transport, name, str(record_type)])
        return authority_response(query, transport)

    authority.state.respond = tracked_response  # type: ignore[method-assign]
    mixed_port, controller_port, dns_port = reserve_port(), reserve_port(), reserve_port()
    config = scratch / "enabled.yaml"
    render_config(config, mixed_port, controller_port, dns_port, authority.port)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_rest_controller(process, controller_port)
        wait_dns_ready(process, dns_port)
        time.sleep(0.1)
        observations = {
            "unauthorized-query": request(
                controller_port,
                "GET",
                "/dns/query?name=rest.phase4.test",
                authorized=False,
            ),
            "invalid-type": request(
                controller_port,
                "GET",
                "/dns/query?name=rest.phase4.test&type=BOGUS",
            ),
            "a-first": request(
                controller_port, "GET", "/dns/query?name=rest.phase4.test"
            ),
            "a-cached": request(
                controller_port, "GET", "/dns/query?name=rest.phase4.test&type=A"
            ),
            "aaaa": request(
                controller_port, "GET", "/dns/query?name=v6.phase4.test&type=AAAA"
            ),
            "cname": request(
                controller_port,
                "GET",
                "/dns/query?name=cname.phase4.test&type=CNAME",
            ),
            "unauthorized-flush": request(
                controller_port,
                "POST",
                "/cache/dns/flush",
                authorized=False,
            ),
        }
        normalize_cached_ttl(observations["a-cached"])
        local_cached = parse_response(
            udp_query(dns_port, make_query("rest.phase4.test", 1, 0x7444)),
            0x7444,
        )
        local_ttl = local_cached["records"][0]["ttl"]
        if not 0 < local_ttl <= 30:
            raise AssertionError(f"shared local DNS TTL is not positive: {local_ttl}")
        local_cached["records"][0]["ttl"] = "positive-bounded"
        observations["local-dns-shared-cache"] = local_cached
        observations["flush"] = request(
            controller_port, "POST", "/cache/dns/flush"
        )
        # The Go oracle dispatches ClearCache in a goroutine. Compare the
        # documented eventual side effect after its bounded local completion.
        time.sleep(0.1)
        observations["a-after-flush"] = request(
            controller_port, "GET", "/dns/query?name=rest.phase4.test"
        )
        normalize_cached_ttl(observations["a-first"])
        normalize_cached_ttl(observations["aaaa"])
        normalize_cached_ttl(observations["cname"])
        normalize_cached_ttl(observations["a-after-flush"])
        observations["authority"] = authority.state.snapshot()
        observations["exit-code"] = stop(process)
        return observations
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        authority.close()


def exercise_disabled(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    controller_port = reserve_port()
    config = scratch / "disabled.yaml"
    config.write_text(
        DISABLED_FIXTURE.read_text()
        .replace("${MIXED_PORT}", str(reserve_port()))
        .replace("${CONTROLLER_PORT}", str(controller_port))
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_rest_controller(process, controller_port)
        observations = {
            "query": request(
                controller_port, "GET", "/dns/query?name=disabled.phase4.test"
            ),
            "flush": request(controller_port, "POST", "/cache/dns/flush"),
        }
        time.sleep(0.1)
        observations["exit-code"] = stop(process)
        return observations
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
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4d4-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations: dict[str, Any] = {}
        for implementation, binary in binaries.items():
            observations[implementation] = run_candidate(
                binary, root / implementation
            )
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(
                json.dumps(observations, indent=2, sort_keys=True)
            )
            raise SystemExit(f"Phase 4D4 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4D4 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

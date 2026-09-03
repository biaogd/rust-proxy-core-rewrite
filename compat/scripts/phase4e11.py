#!/usr/bin/env python3
"""Local Go/Rust differential suite for Phase 4E11 DoT lifecycle behavior."""

from __future__ import annotations

import concurrent.futures
import json
import pathlib
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, recv_exact, reload_via_declared_controller, reserve_port
from phase4 import AuthorityState, build_binaries, dns_query, launch, observe_response
from phase4 import stop, wait_dns_ready
from phase4e2 import rejected_query
from phase4e5 import encrypted_udp_query
from phase4e2 import SERVER_CERTIFICATE, SERVER_KEY


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4e11-diff.json"
CONCURRENT_MISSES = 12


class LifecycleTLSAuthority(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, behavior: str) -> None:
        self.behavior = behavior
        self.state = AuthorityState()
        self.state.counts = {"tls": 0}
        self.connection_count = 0
        self.active_connections = 0
        self.lifecycle_lock = threading.Lock()
        self.barrier = threading.Barrier(CONCURRENT_MISSES)
        self.release = threading.Event()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        super().__init__(("127.0.0.1", 0), LifecycleTLSHandler)

    def get_request(self) -> tuple[socket.socket, Any]:
        stream, address = super().get_request()
        try:
            tls_stream = self.context.wrap_socket(stream, server_side=True)
        except Exception:
            stream.close()
            raise
        return tls_stream, address

    def begin_connection(self) -> int:
        with self.lifecycle_lock:
            self.connection_count += 1
            self.active_connections += 1
            return self.connection_count

    def end_connection(self) -> None:
        with self.lifecycle_lock:
            self.active_connections -= 1

    def snapshot(self) -> dict[str, Any]:
        with self.lifecycle_lock:
            connections = self.connection_count
            active = self.active_connections
        return {
            "connections": connections,
            "active": active,
            "queries": self.state.snapshot(),
        }

    def handle_error(self, request: socket.socket, client_address: Any) -> None:
        del request, client_address


class LifecycleTLSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: LifecycleTLSAuthority = self.server  # type: ignore[assignment]
        connection = server.begin_connection()
        first_query = True
        try:
            while True:
                try:
                    length = int.from_bytes(recv_exact(self.request, 2), "big")
                    query = recv_exact(self.request, length)
                except (EOFError, OSError):
                    return

                if server.behavior == "timeout":
                    server.state.answer(query, "tls")
                    server.release.wait((2 * IO_DEADLINE) + 5)
                    return
                if server.behavior == "fresh-close":
                    server.state.answer(query, "tls")
                    return
                if server.behavior == "stale-then-fresh-fail" and connection > 1:
                    server.state.answer(query, "tls")
                    return
                if server.behavior == "barrier" and first_query:
                    try:
                        server.barrier.wait(timeout=(2 * IO_DEADLINE) + 2)
                    except threading.BrokenBarrierError:
                        return

                response = server.state.answer(query, "tls")
                try:
                    self.request.sendall(len(response).to_bytes(2, "big") + response)
                except OSError:
                    return
                first_query = False
                if server.behavior == "stale-then-fresh-fail":
                    return
        finally:
            server.end_connection()


class RunningAuthority:
    def __init__(self, behavior: str) -> None:
        self.server = LifecycleTLSAuthority(behavior)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def close(self) -> None:
        self.server.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=IO_DEADLINE)


def render_config(
    path: pathlib.Path, *, mixed_port: int, dns_port: int, upstream_port: int
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  nameserver:
    - tls://127.0.0.1:{upstream_port}#skip-cert-verify=true
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
    wrong_scheme.write_text(valid.read_text().replace("tls://", "bogus://"))
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


def wait_authority(
    authority: LifecycleTLSAuthority,
    predicate: Any,
) -> dict[str, Any]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        snapshot = authority.snapshot()
        if predicate(snapshot):
            return snapshot
        time.sleep(0.02)
    raise TimeoutError(f"authority state did not converge: {authority.snapshot()}")


def start_case(
    binary: pathlib.Path, scratch: pathlib.Path, behavior: str
) -> tuple[RunningAuthority, int, pathlib.Path, Any, Any, subprocess.Popen[bytes]]:
    scratch.mkdir(parents=True, exist_ok=True)
    authority = RunningAuthority(behavior)
    mixed_port, dns_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    render_config(
        config,
        mixed_port=mixed_port,
        dns_port=dns_port,
        upstream_port=authority.port,
    )
    config.write_text(
        config.read_text()
        + f"external-controller: 127.0.0.1:{reserve_port()}\n"
    )
    process, stdout, stderr = launch(binary, config, scratch)
    wait_dns_ready(process, dns_port)
    time.sleep(0.1)
    return authority, dns_port, config, stdout, stderr, process


def finish_case(
    authority: RunningAuthority,
    stdout: Any,
    stderr: Any,
    process: subprocess.Popen[bytes],
) -> int:
    exit_code = stop(process)
    stdout.close()
    stderr.close()
    authority.close()
    return exit_code


def exercise_concurrency(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority, dns_port, _, stdout, stderr, process = start_case(
        binary, scratch, "barrier"
    )
    try:
        def query(index: int) -> dict[str, Any]:
            identifier = 0x8800 + index
            response = encrypted_udp_query(
                dns_port,
                dns_query(f"concurrent-{index}.phase4.test", identifier),
            )
            return observe_response(response, identifier)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=CONCURRENT_MISSES
        ) as executor:
            responses = list(executor.map(query, range(CONCURRENT_MISSES)))
        pooled = wait_authority(
            authority.server,
            lambda snapshot: snapshot["connections"] == CONCURRENT_MISSES
            and snapshot["active"] == 8,
        )
        identifier = 0x88F0
        follow_up = observe_response(
            encrypted_udp_query(
                dns_port, dns_query("after-concurrency.phase4.test", identifier)
            ),
            identifier,
        )
        reused = authority.server.snapshot()
        exit_code = finish_case(authority, stdout, stderr, process)
        return {
            "responses": responses,
            "pooled": pooled,
            "follow-up": follow_up,
            "reused": reused,
            "exit-code": exit_code,
        }
    finally:
        if process.poll() is None:
            finish_case(authority, stdout, stderr, process)


def exercise_timeout(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority, dns_port, _, stdout, stderr, process = start_case(
        binary, scratch, "timeout"
    )
    try:
        query = dns_query("timeout.phase4.test", 0x8910)
        started = time.monotonic()
        response = rejected_query(encrypted_udp_query, dns_port, query)
        elapsed = time.monotonic() - started
        observation = {
            "response": response,
            "duration": "five-seconds" if 4.5 <= elapsed <= 6.5 else "outside-window",
            "authority": authority.server.snapshot(),
            "exit-code": finish_case(authority, stdout, stderr, process),
        }
        return observation
    finally:
        authority.server.release.set()
        if process.poll() is None:
            finish_case(authority, stdout, stderr, process)


def exercise_fresh_failure(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority, dns_port, _, stdout, stderr, process = start_case(
        binary, scratch, "fresh-close"
    )
    try:
        query = dns_query("fresh-failure.phase4.test", 0x8A10)
        response = rejected_query(encrypted_udp_query, dns_port, query)
        snapshot = wait_authority(
            authority.server,
            lambda current: current["active"] == 0 and current["queries"] == {"tls": 1},
        )
        return {
            "response": response,
            "authority": snapshot,
            "exit-code": finish_case(authority, stdout, stderr, process),
        }
    finally:
        if process.poll() is None:
            finish_case(authority, stdout, stderr, process)


def exercise_stale_then_fresh_failure(
    binary: pathlib.Path, scratch: pathlib.Path
) -> dict[str, Any]:
    authority, dns_port, _, stdout, stderr, process = start_case(
        binary, scratch, "stale-then-fresh-fail"
    )
    try:
        first_id = 0x8B10
        first = observe_response(
            encrypted_udp_query(
                dns_port, dns_query("stale-first.phase4.test", first_id)
            ),
            first_id,
        )
        wait_authority(authority.server, lambda current: current["active"] == 0)
        second_query = dns_query("stale-second.phase4.test", 0x8B20)
        second = rejected_query(encrypted_udp_query, dns_port, second_query)
        snapshot = wait_authority(
            authority.server,
            lambda current: current["active"] == 0 and current["queries"] == {"tls": 2},
        )
        return {
            "first": first,
            "second": second,
            "authority": snapshot,
            "exit-code": finish_case(authority, stdout, stderr, process),
        }
    finally:
        if process.poll() is None:
            finish_case(authority, stdout, stderr, process)


def exercise_reload_reset(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    authority, dns_port, config, stdout, stderr, process = start_case(
        binary, scratch, "persistent"
    )
    try:
        first_id = 0x8C10
        first = observe_response(
            encrypted_udp_query(
                dns_port, dns_query("before-reset.phase4.test", first_id)
            ),
            first_id,
        )
        before = wait_authority(
            authority.server,
            lambda current: current["connections"] == 1 and current["active"] == 1,
        )
        config.touch()
        reload_via_declared_controller(process, config)
        reset = wait_authority(authority.server, lambda current: current["active"] == 0)
        second_id = 0x8C20
        second = observe_response(
            encrypted_udp_query(
                dns_port, dns_query("after-reset.phase4.test", second_id)
            ),
            second_id,
        )
        after = wait_authority(
            authority.server,
            lambda current: current["connections"] == 2 and current["active"] == 1,
        )
        return {
            "first": first,
            "before": before,
            "reset": reset,
            "second": second,
            "after": after,
            "exit-code": finish_case(authority, stdout, stderr, process),
        }
    finally:
        if process.poll() is None:
            finish_case(authority, stdout, stderr, process)


def run_candidate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    config = validation(binary, scratch)
    if config != {"valid": 0, "wrong-scheme": 1}:
        return {"config": config, "runtime": "not-run"}
    return {
        "config": config,
        "runtime": {
            "concurrency": exercise_concurrency(binary, scratch / "concurrency"),
            "timeout": exercise_timeout(binary, scratch / "timeout"),
            "fresh-failure": exercise_fresh_failure(binary, scratch / "fresh-failure"),
            "stale-then-fresh-failure": exercise_stale_then_fresh_failure(
                binary, scratch / "stale-then-fresh-failure"
            ),
            "reload-reset": exercise_reload_reset(binary, scratch / "reload-reset"),
        },
    }


def satisfies_phase_contract(observation: dict[str, Any]) -> bool:
    if observation["config"] != {"valid": 0, "wrong-scheme": 1}:
        return False
    runtime = observation["runtime"]
    concurrency = runtime["concurrency"]
    if (
        len(concurrency["responses"]) != CONCURRENT_MISSES
        or any(item.get("address") != "192.0.2.42" for item in concurrency["responses"])
        or concurrency["pooled"]
        != {
            "connections": CONCURRENT_MISSES,
            "active": 8,
            "queries": {"tls": CONCURRENT_MISSES},
        }
        or concurrency["follow-up"].get("address") != "192.0.2.42"
        or concurrency["reused"]
        != {
            "connections": CONCURRENT_MISSES,
            "active": 8,
            "queries": {"tls": CONCURRENT_MISSES + 1},
        }
        or concurrency["exit-code"] != 0
    ):
        return False
    timeout = runtime["timeout"]
    if (
        timeout["duration"] != "five-seconds"
        or timeout["response"].get("answers") != 0
        or timeout["authority"]["queries"] != {"tls": 1}
        or timeout["exit-code"] != 0
    ):
        return False
    fresh = runtime["fresh-failure"]
    if (
        fresh["response"].get("answers") != 0
        or fresh["authority"]
        != {"connections": 1, "active": 0, "queries": {"tls": 1}}
        or fresh["exit-code"] != 0
    ):
        return False
    stale = runtime["stale-then-fresh-failure"]
    if (
        stale["first"].get("address") != "192.0.2.42"
        or stale["second"].get("answers") != 0
        or stale["authority"]
        != {"connections": 2, "active": 0, "queries": {"tls": 2}}
        or stale["exit-code"] != 0
    ):
        return False
    reset = runtime["reload-reset"]
    return (
        reset["first"].get("address") == "192.0.2.42"
        and reset["before"] == {"connections": 1, "active": 1, "queries": {"tls": 1}}
        and reset["reset"] == {"connections": 1, "active": 0, "queries": {"tls": 1}}
        and reset["second"].get("address") == "192.0.2.42"
        and reset["after"] == {"connections": 2, "active": 1, "queries": {"tls": 2}}
        and reset["exit-code"] == 0
    )


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4e11-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            implementation: run_candidate(binary, root / implementation)
            for implementation, binary in binaries.items()
        }
        if observations["go"] != observations["rust"] or not satisfies_phase_contract(
            observations["go"]
        ):
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 4E11 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4E11 Go/Rust differential suite passed")


if __name__ == "__main__":
    main()

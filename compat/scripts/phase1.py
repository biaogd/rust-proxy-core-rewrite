#!/usr/bin/env python3
"""Local black-box differential suite for the Phase 1 vertical slice."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import queue
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "compat" / "fixtures" / "config"
RUST_ROOT = ROOT / "rust"
BASELINE = "c0e43ebecf3be9b223f1015c1fc38689bb073467"
STARTUP_DEADLINE = 10.0
IO_DEADLINE = 5.0
FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase1-diff.json"

MIGRATION_PATH_PREFIXES = ("compat/", "docs/rust-rewrite/", "rust/")
MIGRATION_PATHS = {
    ".github/workflows/rust-rewrite.yml",
    ".gitignore",
    "AGENTS.md",
    "README.md",
    "dns/phase4f5_contract_test.go",
    "dns/phase4f6_contract_test.go",
}


def assert_go_oracle_baseline() -> None:
    """Prove committed product sources still match the pinned Go oracle."""
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", BASELINE, "HEAD"],
        cwd=ROOT,
        check=True,
    )
    changed = subprocess.check_output(
        ["git", "diff", "--name-only", BASELINE, "--"], cwd=ROOT, text=True
    ).splitlines()
    unexpected = [
        path
        for path in changed
        if path not in MIGRATION_PATHS
        and not any(path.startswith(prefix) for prefix in MIGRATION_PATH_PREFIXES)
    ]
    if unexpected:
        formatted = "\n  ".join(unexpected)
        raise RuntimeError(
            f"Go oracle differs from baseline {BASELINE}:\n  {formatted}"
        )


def wait_for_linux_signal_handlers(process: subprocess.Popen[Any]) -> bool:
    """Wait until Linux reports that SIGHUP and SIGTERM are caught.

    Listener readiness can precede product signal-handler installation. The
    Linux caught-signal mask supplies a deterministic barrier without sleeps or
    repeated signals. Callers on other platforms receive ``False`` and must use
    a capability-specific observable barrier.
    """
    status = pathlib.Path(f"/proc/{process.pid}/status")
    if not status.exists():
        return False
    expected = (1 << (signal.SIGHUP - 1)) | (1 << (signal.SIGTERM - 1))
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("candidate exited before signal handlers were installed")
        try:
            caught = next(
                line.split(":", 1)[1].strip()
                for line in status.read_text().splitlines()
                if line.startswith("SigCgt:")
            )
        except (OSError, StopIteration):
            time.sleep(0.01)
            continue
        if int(caught, 16) & expected == expected:
            return True
        time.sleep(0.01)
    raise AssertionError("candidate signal handlers did not become observable")


def run_checked(command: list[str], *, cwd: pathlib.Path) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def cargo_target_path(environment: str, name: str) -> pathlib.Path:
    """Resolve a test target without falling back inside the repository."""
    override = os.environ.get(environment)
    if override:
        return pathlib.Path(override)
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--format-version=1", "--no-deps"],
            cwd=RUST_ROOT,
            text=True,
        )
    )
    return pathlib.Path(metadata["target_directory"]) / "compat" / name


def build_binaries(output: pathlib.Path) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()

    go_override = os.environ.get("PHASE1_GO_BINARY")
    go_binary = pathlib.Path(go_override) if go_override else output / "go-oracle"
    if not go_override:
        run_checked(["go", "build", "-trimpath", "-o", str(go_binary), "."], cwd=ROOT)
    rust_target = cargo_target_path("PHASE1_CARGO_TARGET", "rust-target")
    rust_override = os.environ.get("PHASE1_RUST_BINARY")
    rust_binary = (
        pathlib.Path(rust_override)
        if rust_override
        else rust_target / "debug" / "rewrite-core"
    )
    if not rust_override:
        run_checked(
            ["cargo", "build", "--workspace", "--target-dir", str(rust_target)],
            cwd=RUST_ROOT,
        )
    for name, binary in (("Go", go_binary), ("Rust", rust_binary)):
        if not binary.is_file():
            raise RuntimeError(f"{name} binary does not exist: {binary}")
    return {"go": go_binary, "rust": rust_binary}


def classify_config_error(output: str) -> str | None:
    lowered = output.lower()
    if "invalid mode" in lowered:
        return "invalid-mode"
    if "format invalid" in lowered or "rules[0]" in lowered:
        return "invalid-rule"
    if "yaml" in lowered or "unmarshal" in lowered or "cannot decode" in lowered:
        return "yaml"
    return None


def config_observations(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    cases = {
        "valid": (FIXTURES / "phase1-minimal.yaml.tmpl", True),
        "malformed-yaml": (FIXTURES / "phase1-malformed.yaml", False),
        "invalid-mode": (FIXTURES / "phase1-invalid-mode.yaml", False),
        "malformed-match": (FIXTURES / "phase1-malformed-match.yaml", False),
        "invalid-port-type": (FIXTURES / "phase1-invalid-port-type.yaml", False),
        # The Go oracle validates the integer type in -t mode but not bind range.
        "large-port": (FIXTURES / "phase1-large-port.yaml", True),
    }
    observations: dict[str, Any] = {}
    for name, (fixture, expected_acceptance) in cases.items():
        config = scratch / f"{name}.yaml"
        source = fixture.read_text().replace("${MIXED_PORT}", "7890")
        config.write_text(source)
        result = subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            text=True,
            capture_output=True,
            timeout=IO_DEADLINE,
            env={**os.environ, "HOME": str(scratch)},
        )
        accepted = result.returncode == 0
        if accepted != expected_acceptance:
            raise AssertionError(
                f"{binary.name} unexpected acceptance for {name}: "
                f"rc={result.returncode}\n{result.stdout}\n{result.stderr}"
            )
        observations[name] = {
            "accepted": accepted,
            "error-class": None
            if accepted
            else classify_config_error(result.stdout + result.stderr),
        }
    return observations


class ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ThreadingServerV6(ThreadingServer):
    address_family = socket.AF_INET6


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class HalfCloseHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        received = bytearray()
        while True:
            data = self.request.recv(65536)
            if not data:
                break
            received.extend(data)
        self.request.sendall(b"after:" + received)


class CaptureHttpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data.extend(chunk)
        head, body = bytes(data).split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            headers[name.lower()] = value.strip()
        length = int(headers.get("content-length", "0"))
        while len(body) < length:
            body += self.request.recv(length - len(body))
        self.server.captures.put(  # type: ignore[attr-defined]
            {
                "method": method,
                "target": target,
                "body": body[:length].decode("ascii"),
                "x-phase": headers.get("x-phase"),
                "host": headers.get("host"),
                "proxy-authorization": headers.get("proxy-authorization"),
            }
        )
        response = b"phase-one-origin"
        self.request.sendall(
            b"HTTP/1.1 200 OK\r\n"
            + f"Content-Length: {len(response)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + response
        )


@dataclass
class RunningServer:
    server: ThreadingServer
    thread: threading.Thread

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=IO_DEADLINE)


def start_server(
    handler: type[socketserver.BaseRequestHandler], *, ipv6: bool = False
) -> RunningServer:
    server_type = ThreadingServerV6 if ipv6 else ThreadingServer
    host = "::1" if ipv6 else "127.0.0.1"
    server = server_type((host, 0), handler)
    if handler is CaptureHttpHandler:
        server.captures = queue.Queue()  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return RunningServer(server, thread)


def reserve_port() -> int:
    with socket.socket() as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def recv_exact(stream: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise EOFError(f"wanted {length} bytes, received {len(result)}")
        result.extend(chunk)
    return bytes(result)


def recv_until(stream: socket.socket, marker: bytes) -> bytes:
    result = bytearray()
    while marker not in result:
        chunk = stream.recv(4096)
        if not chunk:
            raise EOFError(f"connection closed before {marker!r}")
        result.extend(chunk)
    return bytes(result)


def recv_all(stream: socket.socket) -> bytes:
    result = bytearray()
    while True:
        chunk = stream.recv(4096)
        if not chunk:
            return bytes(result)
        result.extend(chunk)


def connect_proxy(port: int) -> socket.socket:
    stream = socket.create_connection(("127.0.0.1", port), timeout=IO_DEADLINE)
    stream.settimeout(IO_DEADLINE)
    return stream


def wait_ready(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + STARTUP_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during startup with {process.returncode}")
        try:
            with connect_proxy(port):
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("proxy did not open mixed-port")


def connect_tunnel(proxy_port: int, host: str, port: int) -> socket.socket:
    stream = connect_proxy(proxy_port)
    stream.sendall(
        f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
    )
    response = recv_until(stream, b"\r\n\r\n")
    if b" 200 " not in response.split(b"\r\n", 1)[0]:
        raise AssertionError(f"CONNECT failed: {response!r}")
    return stream


def wait_route_ready(
    process: subprocess.Popen[bytes], proxy_port: int, echo_port: int
) -> None:
    """Wait for an observable end-to-end DIRECT route after the listener binds.

    The Go listener can accept a readiness TCP probe before the initial provider
    startup work has settled.  A disposable CONNECT/echo exchange is the
    capability barrier needed by the network cases below; the measured requests
    are still issued exactly once after this returns.
    """
    deadline = time.monotonic() + STARTUP_DEADLINE
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"proxy exited during route readiness with {process.returncode}"
            )
        try:
            with connect_tunnel(proxy_port, "127.0.0.1", echo_port) as stream:
                stream.sendall(b"ready")
                if recv_exact(stream, 5) == b"ready":
                    return
        except (OSError, EOFError, AssertionError) as error:
            last_error = error
        time.sleep(0.02)
    raise TimeoutError(f"proxy DIRECT route did not become ready: {last_error}")


def socks_connect(proxy_port: int, atyp: int, address: bytes, port: int) -> socket.socket:
    stream = connect_proxy(proxy_port)
    stream.sendall(b"\x05\x01\x00")
    if recv_exact(stream, 2) != b"\x05\x00":
        raise AssertionError("SOCKS5 no-auth negotiation failed")
    stream.sendall(b"\x05\x01\x00" + bytes([atyp]) + address + port.to_bytes(2, "big"))
    head = recv_exact(stream, 4)
    if head[:2] != b"\x05\x00":
        raise AssertionError(f"SOCKS5 CONNECT failed: {head!r}")
    lengths = {1: 4, 4: 16}
    if head[3] == 3:
        bound_length = recv_exact(stream, 1)[0]
    else:
        bound_length = lengths[head[3]]
    recv_exact(stream, bound_length + 2)
    return stream


def exercise_proxy(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    half = start_server(HalfCloseHandler)
    origin = start_server(CaptureHttpHandler)
    ipv6_echo: RunningServer | None = None
    try:
        try:
            ipv6_echo = start_server(EchoHandler, ipv6=True)
        except OSError:
            ipv6_echo = None

        proxy_port = reserve_port()
        config = scratch / "config.yaml"
        template = (FIXTURES / "phase1-minimal.yaml.tmpl").read_text()
        config.write_text(template.replace("${MIXED_PORT}", str(proxy_port)))
        stdout = (scratch / "stdout.log").open("wb")
        stderr = (scratch / "stderr.log").open("wb")
        process = subprocess.Popen(
            [str(binary), "-f", str(config)],
            cwd=scratch,
            env={**os.environ, "HOME": str(scratch)},
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            wait_ready(process, proxy_port)
            wait_route_ready(process, proxy_port, echo.port)
            observation: dict[str, Any] = {"startup": "ready"}

            # Fragment the absolute-form request, including a body and a proxy-only header.
            with connect_proxy(proxy_port) as stream:
                request = (
                    f"POST http://127.0.0.1:{origin.port}/alpha?x=1 HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{origin.port}\r\n"
                    "Content-Length: 7\r\n"
                    "X-Phase: one\r\n"
                    "Proxy-Authorization: Basic dGVzdA==\r\n"
                    "Connection: close\r\n\r\n"
                    "payload"
                ).encode()
                for boundary in (1, 7, 31, len(request)):
                    stream.sendall(request[:boundary])
                    request = request[boundary:]
                    time.sleep(0.01)
                    if not request:
                        break
                response = recv_all(stream)
            captured = origin.server.captures.get(timeout=IO_DEADLINE)  # type: ignore[attr-defined]
            captured["host"] = captured["host"].replace(str(origin.port), "<ORIGIN_PORT>")
            observation["http-absolute-fragmented"] = {
                "origin": captured,
                "status": response.split(b"\r\n", 1)[0].decode(),
                "body-present": b"phase-one-origin" in response,
            }

            payload = b"\x00phase-one\xff\x10"
            with connect_tunnel(proxy_port, "127.0.0.1", echo.port) as stream:
                stream.sendall(payload)
                observation["http-connect"] = recv_exact(stream, len(payload)).hex()

            with connect_tunnel(proxy_port, "127.0.0.1", half.port) as stream:
                stream.sendall(b"half-close")
                stream.shutdown(socket.SHUT_WR)
                observation["remote-after-client-half-close"] = recv_all(stream).decode()

            with socks_connect(
                proxy_port, 1, socket.inet_aton("127.0.0.1"), echo.port
            ) as stream:
                stream.sendall(b"ipv4")
                observation["socks-ipv4"] = recv_exact(stream, 4).decode()

            domain = b"localhost"
            with socks_connect(
                proxy_port, 3, bytes([len(domain)]) + domain, echo.port
            ) as stream:
                stream.sendall(b"domain")
                observation["socks-domain"] = recv_exact(stream, 6).decode()

            if ipv6_echo is None:
                observation["socks-ipv6-with-ipv6-disabled"] = "unavailable"
            else:
                with socks_connect(
                    proxy_port, 4, socket.inet_pton(socket.AF_INET6, "::1"), ipv6_echo.port
                ) as stream:
                    try:
                        disabled_closed = stream.recv(1) == b""
                    except (ConnectionResetError, BrokenPipeError):
                        disabled_closed = True
                    observation["socks-ipv6-with-ipv6-disabled"] = (
                        "closed" if disabled_closed else "open"
                    )

            with connect_proxy(proxy_port) as stream:
                stream.sendall(b"\x05\x01\x02")
                observation["unsupported-auth-reply"] = recv_exact(stream, 2).hex()

            failed_port = reserve_port()
            with socks_connect(
                proxy_port, 1, socket.inet_aton("127.0.0.1"), failed_port
            ) as stream:
                try:
                    closed = stream.recv(1) == b""
                except (ConnectionResetError, BrokenPipeError):
                    closed = True
                observation["direct-failure"] = "closed" if closed else "open"

            # An early disconnect must not bring down the listener.
            connect_proxy(proxy_port).close()
            with connect_tunnel(proxy_port, "127.0.0.1", echo.port) as idle:
                started = time.monotonic()
                os.killpg(process.pid, signal.SIGTERM)
                return_code = process.wait(timeout=IO_DEADLINE)
                duration = time.monotonic() - started
                try:
                    idle_closed = idle.recv(1) == b""
                except (ConnectionResetError, BrokenPipeError):
                    idle_closed = True
                observation["shutdown"] = {
                    "exit-code": return_code,
                    "idle-connection": "closed" if idle_closed else "open",
                    "duration-class": "bounded" if duration < IO_DEADLINE else "timeout",
                }
            return observation
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=IO_DEADLINE)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=IO_DEADLINE)
            stdout.close()
            stderr.close()
    finally:
        echo.close()
        half.close()
        origin.close()
        if ipv6_echo is not None:
            ipv6_echo.close()


def collect_debug_files(root: pathlib.Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in {".yaml", ".log"}:
            files[str(path.relative_to(root))] = path.read_text(errors="replace")
    return files


def write_failure(payload: dict[str, Any]) -> pathlib.Path:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    FAILURE_ARTIFACT.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return FAILURE_ARTIFACT


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="phase1-compat-") as temporary:
        temporary_root = pathlib.Path(temporary)
        binaries = build_binaries(temporary_root)

        observations: dict[str, dict[str, Any]] = {}
        try:
            for implementation, binary in binaries.items():
                run_root = temporary_root / f"run-{implementation}"
                config_root = run_root / "config"
                network_root = run_root / "network"
                config_root.mkdir(parents=True)
                network_root.mkdir()
                observations[implementation] = {
                    "config": config_observations(binary, config_root),
                    "network": exercise_proxy(binary, network_root),
                }
        except Exception as error:
            artifact = write_failure(
                {
                    "error": f"{type(error).__name__}: {error}",
                    "observations": observations,
                    "debug-files": collect_debug_files(temporary_root),
                }
            )
            print(f"Phase 1 differential run failed: {artifact}", file=sys.stderr)
            raise

        if observations["go"] != observations["rust"]:
            artifact = write_failure(
                {
                    "observations": observations,
                    "debug-files": collect_debug_files(temporary_root),
                }
            )
            print(f"Phase 1 differential mismatch: {artifact}", file=sys.stderr)
            print(json.dumps(observations, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        FAILURE_ARTIFACT.unlink(missing_ok=True)
        print("Phase 1 Go/Rust differential suite passed")
        print(json.dumps(observations["rust"], indent=2, sort_keys=True))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

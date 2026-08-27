#!/usr/bin/env python3
"""Go/Rust differential for initial plaintext-HTTP proxy-provider loading."""

from __future__ import annotations

import http.server
import json
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_selector import route
from phase5d_proxies import normalize, request
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-http-provider-diff.json"


class ProviderHandler(http.server.BaseHTTPRequestHandler):
    server: "ProviderServer"

    def do_GET(self) -> None:
        self.server.observations.append(
            {"method": self.command, "path": self.path, "host-present": bool(self.headers["Host"])}
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/yaml")
        self.send_header("Content-Length", str(len(self.server.payload)))
        self.end_headers()
        self.wfile.write(self.server.payload)

    def log_message(self, format: str, *args: Any) -> None:
        pass


class ProviderServer(http.server.ThreadingHTTPServer):
    def __init__(self, payload: bytes) -> None:
        super().__init__(("127.0.0.1", 0), ProviderHandler)
        self.payload = payload
        self.observations: list[dict[str, Any]] = []
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=IO_DEADLINE)


def normalize_provider(value: Any) -> Any:
    value = normalize(value)
    if isinstance(value, dict):
        return {
            key: (
                "set"
                if key == "updatedAt" and item != "0001-01-01T00:00:00Z"
                else normalize_provider(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [normalize_provider(item) for item in value]
    return value


def json_response(result: tuple[int, bytes]) -> tuple[int, Any]:
    status, body = result
    return status, normalize_provider(json.loads(body))


def wait_provider(process: Any, controller_port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during provider startup: {process.returncode}")
        try:
            status, body = request(
                controller_port,
                "GET",
                "/providers/proxies/remote-http",
            )
            if status == 200 and [
                proxy["name"] for proxy in json.loads(body).get("proxies", [])
            ] == ["provider-http"]:
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError("HTTP proxy provider did not become ready")


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    upstream = ConnectProxyServer()
    payload = f"""proxies:
  - name: provider-http
    type: http
    server: 127.0.0.1
    port: {upstream.port}
    username: proxy-user
    password: proxy-pass
""".encode()
    provider = ProviderServer(payload)
    mixed_port, controller_port = reserve_port(), reserve_port()
    cache = scratch / ".config" / "mihomo" / "providers" / "remote.yaml"
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
proxy-providers:
  remote-http:
    type: http
    url: http://127.0.0.1:{provider.port}/provider.yaml?phase=5c2c
    path: {cache}
proxy-groups:
  - name: provider-group
    type: select
    proxies: [REJECT]
    use: [remote-http]
rules:
  - DST-PORT,{provider.port},DIRECT
  - MATCH,provider-group
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_provider(process, controller_port)
        selected = request(
            controller_port,
            "PUT",
            "/proxies/provider-group",
            {"name": "provider-http"},
        )
        if selected[0] != 204:
            raise AssertionError(selected)
        if route(mixed_port, echo.port) != "proxy":
            raise AssertionError("HTTP-provider member did not carry TCP")
        return {
            "request": provider.observations,
            "cache-created": cache.read_bytes() == payload,
            "provider-list": json_response(
                request(controller_port, "GET", "/providers/proxies")
            ),
            "provider-detail": json_response(
                request(controller_port, "GET", "/providers/proxies/remote-http")
            ),
            "provider-member": json_response(
                request(
                    controller_port,
                    "GET",
                    "/providers/proxies/remote-http/provider-http",
                )
            ),
            "group": json_response(
                request(controller_port, "GET", "/group/provider-group")
            ),
            "selected": (selected[0], selected[1] == b""),
            "route": route(mixed_port, echo.port),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        provider.close()
        upstream.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-http-provider-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CHTTPPROVIDER_CARGO_TARGET",
            "phase5c-http-provider",
        )
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "error": f"{type(error).__name__}: {error}",
                        "observations": observations,
                        "debug": debug_files(root),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            raise
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5C initial HTTP proxy-provider differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

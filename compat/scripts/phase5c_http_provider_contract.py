#!/usr/bin/env python3
"""Go/Rust differential for HTTP provider headers, ETag and size bounds."""

from __future__ import annotations

import http.server
import json
import tempfile
import threading
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5c_http_provider_refresh import provider_names, select, wait_names
from phase5c_selector import route
from phase5d_proxies import request
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-http-provider-contract-diff.json"


def provider_payload(name: str, port: int) -> bytes:
    return f"""proxies:
  - name: {name}
    type: http
    server: 127.0.0.1
    port: {port}
    username: proxy-user
    password: proxy-pass
""".encode()


class ConditionalHandler(http.server.BaseHTTPRequestHandler):
    server: "ConditionalServer"

    def do_GET(self) -> None:
        with self.server.lock:
            payload = self.server.payload
            etag = self.server.etag
        conditional = self.headers.get("If-None-Match")
        self.server.observations.append(
            {
                "custom": self.headers.get_all("X-Phase") or [],
                "conditional": conditional,
            }
        )
        if conditional == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/yaml")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        pass


class ConditionalServer(http.server.ThreadingHTTPServer):
    def __init__(self, payload: bytes, etag: str) -> None:
        super().__init__(("127.0.0.1", 0), ConditionalHandler)
        self.payload = payload
        self.etag = etag
        self.lock = threading.Lock()
        self.observations: list[dict[str, Any]] = []
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def respond(self, payload: bytes, etag: str) -> None:
        with self.lock:
            self.payload = payload
            self.etag = etag

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=IO_DEADLINE)


def write_config(
    path: Path,
    mixed_port: int,
    controller_port: int,
    provider_port: int,
    cache: Path,
    etag_support: bool,
) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: info
ipv6: false
etag-support: {str(etag_support).lower()}
proxy-providers:
  remote-http:
    type: http
    url: http://127.0.0.1:{provider_port}/provider.yaml?phase=5c2e
    path: {cache}
    interval: 600
    size-limit: 512
    header:
      X-Phase: [first, second]
proxy-groups:
  - name: provider-group
    type: select
    proxies: [REJECT]
    use: [remote-http]
rules:
  - DST-PORT,{provider_port},DIRECT
  - MATCH,provider-group
"""
    )


def update(controller_port: int) -> tuple[int, bool]:
    status, body = request(controller_port, "PUT", "/providers/proxies/remote-http")
    return status, body == b""


def enabled_contract(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    first, second = ConnectProxyServer(), ConnectProxyServer()
    first_payload = provider_payload("provider-one", first.port)
    second_payload = provider_payload("provider-two", second.port)
    provider = ConditionalServer(first_payload, '"v1"')
    mixed_port, controller_port = reserve_port(), reserve_port()
    cache = scratch / ".config" / "mihomo" / "providers" / "contract.yaml"
    config = scratch / "config.yaml"
    write_config(config, mixed_port, controller_port, provider.port, cache, True)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_names(process, controller_port, ["provider-one"])
        initial_request = provider.observations[-1]

        not_modified = update(controller_port)
        unchanged_request = provider.observations[-1]
        unchanged = (
            provider_names(controller_port) == ["provider-one"]
            and cache.read_bytes() == first_payload
        )

        provider.respond(second_payload, '"v2"')
        modified = update(controller_port)
        wait_names(process, controller_port, ["provider-two"])
        modified_request = provider.observations[-1]
        selected = select(controller_port, "provider-two")
        routed = route(mixed_port, echo.port)

        provider.respond(b"x" * 1024, '"v3"')
        oversized = request(controller_port, "PUT", "/providers/proxies/remote-http")
        oversized_json = json.loads(oversized[1])
        return {
            "initial-headers": initial_request["custom"],
            "initial-unconditional": initial_request["conditional"] is None,
            "not-modified": not_modified,
            "conditional-v1": unchanged_request["conditional"] == '"v1"',
            "unchanged": unchanged,
            "modified": modified,
            "modified-sent-v1": modified_request["conditional"] == '"v1"',
            "cache-updated": cache.read_bytes() == second_payload,
            "selected": selected,
            "route": routed,
            "used-second": bool(second.observations),
            "oversized": {
                "status": oversized[0],
                "message-is-string": isinstance(oversized_json.get("message"), str),
                "sent-v2": provider.observations[-1]["conditional"] == '"v2"',
            },
            "oversize-rollback": (
                provider_names(controller_port) == ["provider-two"]
                and cache.read_bytes() == second_payload
                and route(mixed_port, echo.port) == "proxy"
            ),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        provider.close()
        first.close()
        second.close()
        echo.close()


def disabled_contract(binary: Path, scratch: Path) -> dict[str, Any]:
    upstream = ConnectProxyServer()
    payload = provider_payload("provider-one", upstream.port)
    provider = ConditionalServer(payload, '"disabled"')
    mixed_port, controller_port = reserve_port(), reserve_port()
    cache = scratch / ".config" / "mihomo" / "providers" / "disabled.yaml"
    config = scratch / "config.yaml"
    write_config(config, mixed_port, controller_port, provider.port, cache, False)
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_names(process, controller_port, ["provider-one"])
        refreshed = update(controller_port)
        return {
            "refresh": refreshed,
            "second-request-unconditional": provider.observations[-1]["conditional"] is None,
            "headers-retained": provider.observations[-1]["custom"] == ["first", "second"],
            "cache-retained": cache.read_bytes() == payload,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        provider.close()
        upstream.close()


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    enabled, disabled = scratch / "enabled", scratch / "disabled"
    enabled.mkdir()
    disabled.mkdir()
    return {
        "enabled": enabled_contract(binary, enabled),
        "disabled": disabled_contract(binary, disabled),
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-http-provider-contract-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CHTTPPROVIDERCONTRACT_CARGO_TARGET",
            "phase5c-http-provider-contract",
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
    print("Phase 5C HTTP-provider request contract differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

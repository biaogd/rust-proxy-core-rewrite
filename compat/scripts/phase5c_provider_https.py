#!/usr/bin/env python3
"""Go/Rust differential for trusted HTTPS proxy and rule providers."""

from __future__ import annotations

import json
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files, route
from phase5d_proxies import request
from phase5d_streams import wait_controller
from phase6b_http import ConnectProxyServer


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5c-provider-https-diff.json"


class HttpsProviderHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        server = self.server
        with server.lock:
            server.requests.append(self.path)
            payload = (
                server.proxy_payload
                if self.path.startswith("/proxies")
                else server.rule_payload
            )
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class HttpsProviderServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, proxy_payload: bytes, rule_payload: bytes) -> None:
        super().__init__(("127.0.0.1", 0), HttpsProviderHandler)
        self.proxy_payload = proxy_payload
        self.rule_payload = rule_payload
        self.requests: list[str] = []
        self.lock = threading.Lock()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def set_payloads(self, proxy_payload: bytes, rule_payload: bytes) -> None:
        with self.lock:
            self.proxy_payload = proxy_payload
            self.rule_payload = rule_payload

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)


def proxy_yaml(name: str, port: int) -> bytes:
    return f"""proxies:
  - name: {name}
    type: http
    server: 127.0.0.1
    port: {port}
    username: proxy-user
    password: proxy-pass
""".encode()


def wait_provider(controller: int, member: str) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        try:
            status, body = request(controller, "GET", "/providers/proxies/secure-proxies")
            if status == 200 and [item["name"] for item in json.loads(body)["proxies"]] == [member]:
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError(f"HTTPS proxy provider did not become {member}")


def wait_route(process: Any, mixed: int, host: str, port: int, expected: str) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited during HTTPS provider test: {process.returncode}")
        try:
            if route(mixed, host, port) == expected:
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise TimeoutError(f"{host} did not become {expected}")


def exercise(binary: Path, scratch: Path) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    first, second = ConnectProxyServer(), ConnectProxyServer()
    provider = HttpsProviderServer(proxy_yaml("secure-one", first.port), b"secure-block.test\n")
    mixed, controller = reserve_port(), reserve_port()
    root_pem = "\n".join(
        f"      {line}" for line in ROOT_CERTIFICATE.read_text().splitlines()
    )
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
mode: rule
log-level: info
ipv6: false
tls:
  custom-certifactes:
    - |-
{root_pem}
hosts:
  dot.phase4.test: 127.0.0.1
  secure-block.test: 127.0.0.1
  secure-next.test: 127.0.0.1
proxy-providers:
  secure-proxies:
    type: http
    url: https://dot.phase4.test:{provider.port}/proxies.yaml
    path: providers/secure.yaml
    interval: 600
rule-providers:
  secure-rules:
    type: http
    behavior: domain
    format: text
    url: https://dot.phase4.test:{provider.port}/rules.txt
    path: rules/secure.txt
    interval: 600
proxy-groups:
  - name: secure-group
    type: select
    use: [secure-proxies]
    default-selected: secure-one
rules:
  - DOMAIN,dot.phase4.test,DIRECT
  - RULE-SET,secure-rules,REJECT
  - MATCH,secure-group
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed)
        wait_controller(process, controller)
        wait_provider(controller, "secure-one")
        wait_route(process, mixed, "secure-block.test", echo.port, "reject")
        first.observations.clear()
        wait_route(process, mixed, "127.0.0.1", echo.port, "direct")
        initial = {
            "blocked": route(mixed, "secure-block.test", echo.port),
            "proxy-route": route(mixed, "127.0.0.1", echo.port),
            "via-first": bool(first.observations),
            "requests": sorted(path.split("?")[0] for path in provider.requests),
        }

        provider.set_payloads(proxy_yaml("secure-two", second.port), b"secure-next.test\n")
        proxy_update = request(controller, "PUT", "/providers/proxies/secure-proxies")
        rule_update = request(controller, "PUT", "/providers/rules/secure-rules")
        wait_provider(controller, "secure-two")
        wait_route(process, mixed, "secure-next.test", echo.port, "reject")
        second.observations.clear()
        wait_route(process, mixed, "127.0.0.1", echo.port, "direct")
        return {
            "initial": initial,
            "proxy-update": (proxy_update[0], proxy_update[1] == b""),
            "rule-update": (rule_update[0], rule_update[1] == b""),
            "new-rule": route(mixed, "secure-next.test", echo.port),
            "via-second": bool(second.observations),
            "proxy-cache": (scratch / ".config" / "mihomo" / "providers" / "secure.yaml").read_bytes()
            == proxy_yaml("secure-two", second.port),
            "rule-cache": (scratch / ".config" / "mihomo" / "rules" / "secure.txt").read_bytes()
            == b"secure-next.test\n",
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        provider.close()
        first.close()
        second.close()
        echo.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5c-provider-https-") as temporary:
        root = Path(temporary)
        binaries = build_binaries(
            root,
            "PHASE5CPROVIDERHTTPS_CARGO_TARGET",
            "phase5c-provider-https",
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
    print("Phase 5C HTTPS proxy/rule-provider differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

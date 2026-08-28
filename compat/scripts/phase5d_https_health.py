#!/usr/bin/env python3
"""HTTPS controller delay/health-check differential with a custom root."""

from __future__ import annotations

import json
import pathlib
import ssl
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase5b1a import build_binaries, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat/artifacts/phase5d-https-health-diff.json"


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(204)
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


class HttpsHealthServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(SERVER_CERTIFICATE, SERVER_KEY)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=IO_DEADLINE)


def exercise(binary: pathlib.Path, scratch: pathlib.Path, health: HttpsHealthServer) -> dict[str, Any]:
    mixed, controller = reserve_port(), reserve_port()
    root_pem = "\n".join(f"      {line}" for line in ROOT_CERTIFICATE.read_text().splitlines())
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
tls:
  custom-certifactes:
    - |-
{root_pem}
hosts:
  dot.phase4.test: 127.0.0.1
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed)
        wait_controller(process, controller)
        url = urllib.parse.quote(f"https://dot.phase4.test:{health.port}/health", safe="")
        success = request(
            controller,
            "GET",
            f"/proxies/DIRECT/delay?url={url}&timeout=2000&expected=204",
        )
        mismatch = request(
            controller,
            "GET",
            f"/proxies/DIRECT/delay?url={url}&timeout=2000&expected=200",
        )
        success_body = json.loads(success[1]) if success[1] else {}
        mismatch_body = json.loads(mismatch[1]) if mismatch[1] else {}
        return {
            "success-status": success[0],
            "positive-delay": success_body.get("delay", 0) > 0,
            "mismatch-status": mismatch[0],
            "mismatch-message": mismatch_body.get("message"),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-https-health-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5DHTTPSHEALTH_CARGO_TARGET", "phase5d-https-health")
        health = HttpsHealthServer()
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch, health)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(json.dumps({
                "error": f"{type(error).__name__}: {error}",
                "observations": observations,
                "debug": debug_files(root),
            }, indent=2, sort_keys=True))
            raise
        finally:
            health.close()
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps({"observations": observations}, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5D HTTPS health differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

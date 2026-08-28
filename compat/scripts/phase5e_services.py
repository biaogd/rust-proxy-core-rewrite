#!/usr/bin/env python3
"""Phase 5E external-UI and geodata service differential."""

from __future__ import annotations

import io
import json
import pathlib
import tempfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase4f8 import geosite
from phase5b1a import build_binaries, debug_files
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat/artifacts/phase5e-services-diff.json"


def ui_archive(value: str) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("dashboard/index.html", value)
        archive.writestr("dashboard/assets/version.txt", value)
    return output.getvalue()


def geo_payload(value: str) -> bytes:
    return geosite("CN", [(2, "example.cn")]) + geosite(
        "PHASE5E", [(2, value)]
    )


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        self.ui = ui_archive("automatic")
        self.geo = geo_payload("initial.phase5e.test")

        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                payload = fixture.ui if self.path == "/ui.zip" else fixture.geo
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        super().__init__(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=IO_DEADLINE)


def wait_file(path: pathlib.Path, expected: str) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if path.is_file() and path.read_text() == expected:
            return
        time.sleep(0.02)
    raise TimeoutError(f"file did not become {expected!r}: {path}")


def exercise(
    binary: pathlib.Path, scratch: pathlib.Path, fixture: FixtureServer
) -> dict[str, Any]:
    mixed, controller = reserve_port(), reserve_port()
    profile = scratch / ".config/mihomo"
    profile.mkdir(parents=True)
    service_home = profile
    initial_geo = geo_payload("old.phase5e.test")
    (service_home / "GeoSite.dat").write_bytes(initial_geo)
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
external-ui: ui
external-ui-url: http://127.0.0.1:{fixture.port}/ui.zip
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
geodata-mode: true
geox-url:
  geosite: http://127.0.0.1:{fixture.port}/GeoSite.dat
dns:
  enable: true
  listen: 127.0.0.1:{reserve_port()}
  nameserver: [rcode://success]
  nameserver-policy:
    'geosite:PHASE5E': rcode://success
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed)
        wait_controller(process, controller)
        index = service_home / "ui/index.html"
        wait_file(index, "automatic")

        fixture.ui = ui_archive("manual")
        ui_success = request(controller, "POST", "/upgrade/ui")
        wait_file(index, "manual")

        fixture.ui = b"not-an-archive"
        ui_failure = request(controller, "POST", "/upgrade/ui")
        ui_rollback = index.read_text()

        next_geo = geo_payload("updated.phase5e.test")
        fixture.geo = next_geo
        geo_success = request(controller, "POST", "/configs/geo")
        geo_replaced = (service_home / "GeoSite.dat").read_bytes() == next_geo

        fixture.geo = b"invalid-geodata"
        geo_failure = request(controller, "POST", "/upgrade/geo")
        geo_rollback = (service_home / "GeoSite.dat").read_bytes() == next_geo
        return {
            "auto-ui": "automatic",
            "manual-ui-status": ui_success[0],
            "manual-ui-body": ui_success[1].decode(),
            "invalid-ui-status": ui_failure[0],
            "invalid-ui-rollback": ui_rollback,
            "geo-status": geo_success[0],
            "geo-replaced": geo_replaced,
            "invalid-geo-status": geo_failure[0],
            "invalid-geo-rollback": geo_rollback,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5e-services-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE5ESERVICES_CARGO_TARGET", "phase5e-services")
        fixture = FixtureServer()
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                fixture.ui = ui_archive("automatic")
                fixture.geo = geo_payload("initial.phase5e.test")
                observations[name] = exercise(binary, scratch, fixture)
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
        finally:
            fixture.close()
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5E UI/geodata service differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

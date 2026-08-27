#!/usr/bin/env python3
"""Go/Rust differential for built-in proxy and GLOBAL selector control."""

from __future__ import annotations

import http.client
import json
import pathlib
import re
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5d_streams import SECRET, wait_controller


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5d-proxies-diff.json"
UUID_V4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


class HealthHandler(BaseHTTPRequestHandler):
    def do_HEAD(self) -> None:
        time.sleep(0.04)
        self.send_response(204)
        self.end_headers()

    def log_message(self, _format: str, *args: Any) -> None:
        del args


def start_health_server() -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def request(
    port: int, method: str, path: str, value: dict[str, Any] | None = None
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    headers = {"Authorization": f"Bearer {SECRET}"}
    body = None
    if value is not None:
        body = json.dumps(value).encode()
        headers["Content-Type"] = "application/json"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    try:
        return response.status, response.read()
    finally:
        response.close()
        connection.close()


def raw_request(port: int, method: str, path: str, body: bytes) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    connection.request(
        method,
        path,
        body=body,
        headers={
            "Authorization": f"Bearer {SECRET}",
            "Content-Type": "application/json",
        },
    )
    response = connection.getresponse()
    try:
        return response.status, response.read()
    finally:
        response.close()
        connection.close()


def json_body(result: tuple[int, bytes]) -> tuple[int, Any]:
    status, body = result
    return status, normalize(json.loads(body))


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, str) and UUID_V4.fullmatch(value):
        return "uuid-v4"
    return value


def empty(result: tuple[int, bytes]) -> dict[str, Any]:
    status, body = result
    return {"status": status, "empty-body": body == b""}


def error(result: tuple[int, bytes]) -> dict[str, Any]:
    status, body = result
    return {"status": status, "message": json.loads(body)["message"]}


def delay_response(result: tuple[int, bytes]) -> dict[str, Any]:
    status, body = result
    value = json.loads(body)
    return {
        "status": status,
        "positive-delay": isinstance(value.get("delay"), int) and value["delay"] > 0,
    }


def group_delay_response(result: tuple[int, bytes]) -> dict[str, Any]:
    status, body = result
    value = json.loads(body)
    return {
        "status": status,
        "keys": sorted(value),
        "positive-direct": isinstance(value.get("DIRECT"), int) and value["DIRECT"] > 0,
    }


def health(result: tuple[int, bytes], url: str) -> dict[str, Any]:
    status, body = result
    value = json.loads(body)
    history = value["history"]
    extra = value["extra"].get(url)
    return {
        "status": status,
        "alive": value["alive"],
        "history-count": len(history),
        "history-positive": all(item["delay"] > 0 and item["time"] for item in history),
        "url-alive": extra["alive"] if extra else None,
        "url-history-count": len(extra["history"]) if extra else 0,
    }


def exercise(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    health_server = start_health_server()
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    health_url = f"http://127.0.0.1:{health_server.server_port}/generate_204"
    delay_query = urllib.parse.urlencode(
        {"url": health_url, "timeout": "1000", "expected": "204"}
    )
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        listing = json_body(request(controller_port, "GET", "/proxies"))
        group_listing = json_body(request(controller_port, "GET", "/group"))
        direct = json_body(request(controller_port, "GET", "/proxies/DIRECT"))
        global_before = json_body(request(controller_port, "GET", "/group/GLOBAL"))
        missing = error(request(controller_port, "GET", "/proxies/not-present"))
        non_group = error(request(controller_port, "GET", "/group/DIRECT"))

        direct_put = error(
            request(controller_port, "PUT", "/proxies/DIRECT", {"name": "REJECT"})
        )
        malformed = error(raw_request(controller_port, "PUT", "/proxies/GLOBAL", b"{"))
        bad_choice = error(
            request(controller_port, "PUT", "/proxies/GLOBAL", {"name": "missing"})
        )
        select_reject = empty(
            request(controller_port, "PUT", "/proxies/GLOBAL", {"name": "REJECT"})
        )
        global_after = json_body(request(controller_port, "GET", "/proxies/GLOBAL"))
        delete_selector = error(request(controller_port, "DELETE", "/proxies/GLOBAL"))
        restore = empty(
            request(controller_port, "PUT", "/proxies/GLOBAL", {"name": "DIRECT"})
        )
        invalid_timeout = error(
            request(
                controller_port,
                "GET",
                f"/proxies/DIRECT/delay?url={urllib.parse.quote(health_url)}",
            )
        )
        invalid_expected = error(
            request(
                controller_port,
                "GET",
                f"/proxies/DIRECT/delay?url={urllib.parse.quote(health_url)}&timeout=1000&expected=nope",
            )
        )
        direct_delay = delay_response(
            request(controller_port, "GET", f"/proxies/DIRECT/delay?{delay_query}")
        )
        direct_health = health(
            request(controller_port, "GET", "/proxies/DIRECT"), health_url
        )
        group_delay = group_delay_response(
            request(controller_port, "GET", f"/group/GLOBAL/delay?{delay_query}")
        )
        direct_after_group = health(
            request(controller_port, "GET", "/proxies/DIRECT"), health_url
        )

        return {
            "list": listing,
            "group-list": group_listing,
            "direct": direct,
            "global-before": global_before,
            "missing": missing,
            "non-group": non_group,
            "put-non-selector": direct_put,
            "malformed-selection": malformed,
            "unknown-selection": bad_choice,
            "select-reject": select_reject,
            "global-after": global_after,
            "delete-selector": delete_selector,
            "restore": restore,
            "invalid-delay-timeout": invalid_timeout,
            "invalid-delay-expected": invalid_expected,
            "direct-delay": direct_delay,
            "direct-health": direct_health,
            "group-delay": group_delay,
            "direct-after-group": direct_after_group,
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        health_server.shutdown()
        health_server.server_close()


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5d-proxies-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE5DPROXIES_CARGO_TARGET", "phase5d-proxies"
        )
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch)
        except Exception as exc:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(
                json.dumps(
                    {
                        "error": f"{type(exc).__name__}: {exc}",
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
        FAILURE_ARTIFACT.write_text(
            json.dumps({"observations": observations}, indent=2, sort_keys=True)
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5D built-in proxies and GLOBAL selector differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

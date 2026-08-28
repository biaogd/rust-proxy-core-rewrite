#!/usr/bin/env python3
"""Go/Rust differential for Phase 5E4 general geodata-mode rules."""

from __future__ import annotations

import http.client
import json
import pathlib
import socket
import tempfile
from typing import Any

from phase1 import EchoHandler, IO_DEADLINE, ROOT, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase4f8 import geosite
from phase4f9 import field_bytes, varint
from phase5b1a import build_binaries, debug_files, route, wait_route
from phase5d_proxies import request
from phase5d_streams import SECRET, wait_controller
from phase5e_services import FixtureServer, geo_payload


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5e-geo-rules-diff.json"


def geoip(name: str, address: str, prefix: int) -> bytes:
    packed = socket.inet_pton(socket.AF_INET, address)
    network = field_bytes(1, packed) + varint(2 << 3) + varint(prefix)
    entry = field_bytes(1, name.encode()) + field_bytes(2, network)
    return field_bytes(1, entry)


def write_geodata(home: pathlib.Path) -> None:
    home.mkdir(parents=True)
    (home / "GeoSite.dat").write_bytes(
        geosite("CN", [(2, "example.cn")])
        + geosite("PHASE5E", [(2, "geo.phase5e.test")])
    )
    (home / "GeoIP.dat").write_bytes(
        geoip("CN", "203.0.113.0", 24)
        + geoip("PHASE5EIP", "127.0.0.0", 8)
        + geoip("PHASE5ESOURCE", "127.0.0.1", 32)
    )


def snapshot(controller_port: int) -> list[dict[str, Any]]:
    connection = http.client.HTTPConnection(
        "127.0.0.1", controller_port, timeout=IO_DEADLINE
    )
    connection.request(
        "GET", "/rules", headers={"Authorization": f"Bearer {SECRET}"}
    )
    response = connection.getresponse()
    try:
        if response.status != 200:
            raise AssertionError((response.status, response.read()))
        return [
            {
                "type": rule["type"],
                "payload": rule["payload"],
                "proxy": rule["proxy"],
                "size": rule["size"],
            }
            for rule in json.loads(response.read())["rules"]
        ]
    finally:
        response.close()
        connection.close()


def exercise_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    rule: str,
    host: str,
    fallback_host: str | None,
    fixture: FixtureServer,
) -> dict[str, Any]:
    echo = start_server(EchoHandler)
    mixed_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
geodata-mode: true
geo-auto-update: false
geox-url:
  geosite: http://127.0.0.1:{fixture.port}/GeoSite.dat
hosts:
  deep.geo.phase5e.test: 127.0.0.1
rules:
  - DST-PORT,{fixture.port},DIRECT
  - {rule}
  - MATCH,REJECT
"""
    )
    write_geodata(scratch / ".config" / "mihomo")
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        wait_route(process, mixed_port, host, echo.port, "direct")
        result = {
            "matching": route(mixed_port, host, echo.port),
            "rules": snapshot(controller_port),
        }
        if fallback_host is not None:
            result["fallback"] = route(mixed_port, fallback_host, echo.port)
        if rule.startswith("GEOSITE,"):
            updated = geo_payload("updated.geo.phase5e.test")
            fixture.geo = updated
            update_status, update_body = request(controller_port, "POST", "/configs/geo")
            result["update"] = {
                "status": update_status,
                "body": update_body.decode(),
                "replaced": (
                    scratch / ".config" / "mihomo" / "GeoSite.dat"
                ).read_bytes()
                == updated,
            }
        return result
    finally:
        stop(process)
        stdout.close()
        stderr.close()
        echo.close()


def exercise(
    binary: pathlib.Path, scratch: pathlib.Path, fixture: FixtureServer
) -> dict[str, Any]:
    cases = {
        "geosite": (
            "GEOSITE,PHASE5E,DIRECT",
            "deep.geo.phase5e.test",
            "127.0.0.1",
        ),
        "geoip": (
            "GEOIP,PHASE5EIP,DIRECT,no-resolve",
            "127.0.0.1",
            "192.0.2.1",
        ),
        "src-geoip": (
            "SRC-GEOIP,PHASE5ESOURCE,DIRECT",
            "127.0.0.1",
            None,
        ),
    }
    observations: dict[str, Any] = {}
    for name, (rule, host, fallback_host) in cases.items():
        case_root = scratch / name
        case_root.mkdir(parents=True)
        observations[name] = exercise_case(
            binary, case_root, rule, host, fallback_host, fixture
        )
    return observations


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5e-geo-rules-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(
            root, "PHASE5EGEORULES_CARGO_TARGET", "phase5e-geo-rules"
        )
        fixture = FixtureServer()
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
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
        FAILURE_ARTIFACT.write_text(
            json.dumps({"observations": observations}, indent=2, sort_keys=True)
        )
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5E4 general Geo rule differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

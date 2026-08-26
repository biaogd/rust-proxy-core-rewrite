#!/usr/bin/env python3
"""Go/Rust differential and interchange gate for Phase 4F14 fake-IP."""

from __future__ import annotations

import http.client
import json
import os
import pathlib
import signal
import socket
import socketserver
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_for_linux_signal_handlers
from phase4 import build_binaries, launch, stop, wait_dns_ready
from phase4b import local_interface_ip, make_query, udp_query
from phase4c import AuthorityHandler, AuthorityServer, AuthorityState, fake_address
from phase4f13 import FixtureServers, MappingAuthorityState, socks5_connect, wait_tcp_echo, wait_udp_echo
from phase4f8 import write_geosite


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase4f14-diff.json"
REAL_ADDRESS = "192.0.2.114"


def config_text(
    *,
    dns_port: int,
    mixed_port: int,
    upstream_port: int,
    ipv4_range: str = "198.20.0.1/16",
    filter_mode: str = "blacklist",
    filters: list[str] | None = None,
    controller_port: int = 0,
    store: bool = False,
    provider: bool = False,
) -> str:
    filters = filters or ["never-match.phase4f14.test"]
    controller = f"external-controller: 127.0.0.1:{controller_port}\n" if controller_port else ""
    provider_section = """rule-providers:
  domains:
    type: inline
    behavior: domain
    payload:
      - '+.provider.phase4f14.test'
"""
    if not provider:
        provider_section = ""
    rendered_filters = "\n".join(f"    - '{entry}'" for entry in filters)
    return f"""mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: true
{controller}{provider_section}profile:
  store-fake-ip: {str(store).lower()}
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: true
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: fake-ip
  fake-ip-range: {ipv4_range}
  fake-ip-range6: fd00:198:20::1/120
  fake-ip-filter-mode: {filter_mode}
  fake-ip-filter:
{rendered_filters}
  fake-ip-ttl: 7
  nameserver:
    - udp://127.0.0.1:{upstream_port}
rules:
  - MATCH,DIRECT
"""


def install_geosite(scratch: pathlib.Path) -> None:
    write_geosite(scratch / "GeoSite.dat")
    go_home = scratch / ".config" / "mihomo"
    go_home.mkdir(parents=True, exist_ok=True)
    write_geosite(go_home / "GeoSite.dat")


def query_data(port: int, name: str, identifier: int) -> str:
    return query_type_data(port, name, 1, identifier)


def query_type_data(port: int, name: str, record_type: int, identifier: int) -> str:
    response = fake_address(port, name, record_type, identifier)
    records = response["records"]
    if not records:
        return "no-answer"
    return str(records[0]["data"])


def run_filter_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authority_port: int,
    mode: str,
    filters: list[str],
    names: list[str],
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    install_geosite(scratch)
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        config_text(
            dns_port=dns_port,
            mixed_port=reserve_port(),
            upstream_port=authority_port,
            filter_mode=mode,
            filters=filters,
            provider=True,
        )
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        try:
            wait_dns_ready(process, dns_port)
        except RuntimeError as error:
            stderr.flush()
            raise RuntimeError(f"{error}: {(scratch / 'stderr.log').read_text()}") from error
        results = {
            name: query_data(dns_port, name, 0x7100 + index)
            for index, name in enumerate(names)
        }
        results["exit-code"] = stop(process)
        return results
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def wait_for_real(
    port: int, name: str, *, reload_process: Any | None = None
) -> str:
    deadline = time.monotonic() + IO_DEADLINE
    identifier = 0x7200
    reload_sent = False
    while time.monotonic() < deadline:
        if reload_process is not None and not reload_sent:
            if reload_process.poll() is not None:
                raise AssertionError("candidate exited before fake-IP reload became observable")
            os.kill(reload_process.pid, signal.SIGHUP)
            reload_sent = True
        try:
            data = query_data(port, name, identifier)
            if data == REAL_ADDRESS:
                return data
        except (OSError, TimeoutError):
            pass
        identifier = (identifier + 1) & 0xFFFF
        time.sleep(0.02)
    raise AssertionError("fake-IP reload did not become observable")


def run_reload_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authority_port: int,
    *,
    persistent: bool = False,
    saved_state: bool = False,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    dns_port, mixed_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    if saved_state:
        seed_port = reserve_port()
        config.write_text(
            config_text(
                dns_port=seed_port,
                mixed_port=reserve_port(),
                upstream_port=authority_port,
                store=True,
            )
        )
        seed_process, seed_stdout, seed_stderr = launch(binary, config, scratch)
        try:
            wait_dns_ready(seed_process, seed_port)
            query_data(seed_port, "seed.range.phase4f14.test", 0x7205)
            stop(seed_process)
        finally:
            if seed_process.poll() is None:
                stop(seed_process)
            seed_stdout.close()
            seed_stderr.close()
    config.write_text(
        config_text(
            dns_port=dns_port,
            mixed_port=mixed_port,
            upstream_port=authority_port,
            store=persistent,
        )
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        try:
            wait_dns_ready(process, dns_port)
        except RuntimeError as error:
            stderr.flush()
            raise RuntimeError(f"{error}: {(scratch / 'stderr.log').read_text()}") from error
        old = query_data(dns_port, "old.range.phase4f14.test", 0x7210)
        config.write_text(
            config_text(
                dns_port=dns_port,
                mixed_port=mixed_port,
                upstream_port=authority_port,
                ipv4_range="198.21.7.1/24",
                filters=["reload-ready.phase4f14.test"],
                store=persistent,
            )
        )
        try:
            ready = wait_for_real(
                dns_port,
                "reload-ready.phase4f14.test",
                reload_process=process,
            )
        except AssertionError as error:
            stdout.flush()
            stderr.flush()
            raise AssertionError(
                f"{error}; binary={binary}; stdout={(scratch / 'stdout.log').read_text()}; "
                f"stderr={(scratch / 'stderr.log').read_text()}"
            ) from error
        old_after = query_data(dns_port, "old.range.phase4f14.test", 0x7211)
        fresh = query_data(dns_port, "fresh.range.phase4f14.test", 0x7212)
        return {
            "old": old,
            "ready": ready,
            "old-after": old_after,
            "fresh": fresh,
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def controller_request(port: int, path: str) -> tuple[int, bool]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=IO_DEADLINE)
    connection.request("POST", path)
    response = connection.getresponse()
    body = response.read()
    connection.close()
    return response.status, body == b""


def wait_controller(process: Any, port: int) -> None:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("candidate exited during controller startup")
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
            connection.request("GET", "/version")
            response = connection.getresponse()
            response.read()
            connection.close()
            if response.status == 200:
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("controller did not become ready")


def run_flush_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authority_port: int,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    dns_port, controller_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        config_text(
            dns_port=dns_port,
            mixed_port=reserve_port(),
            upstream_port=authority_port,
            controller_port=controller_port,
            store=True,
        )
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        wait_controller(process, controller_port)
        first = query_data(dns_port, "flush-one.phase4f14.test", 0x7300)
        second = query_data(dns_port, "flush-two.phase4f14.test", 0x7301)
        status, empty = controller_request(controller_port, "/cache/fakeip/flush")
        after = query_data(dns_port, "flush-one.phase4f14.test", 0x7302)
        first_exit = stop(process)
        stdout.close()
        stderr.close()
        restart_port = reserve_port()
        config.write_text(
            config_text(
                dns_port=restart_port,
                mixed_port=reserve_port(),
                upstream_port=authority_port,
                store=True,
            )
        )
        process, stdout, stderr = launch(binary, config, scratch)
        wait_dns_ready(process, restart_port)
        restarted = query_data(restart_port, "flush-three.phase4f14.test", 0x7303)
        return {
            "first": first,
            "second": second,
            "status": status,
            "body-empty": empty,
            "after": after,
            "first-exit-code": first_exit,
            "restarted": restarted,
            "restart-exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def run_reverse_case(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    address = local_interface_ip()
    if address is None:
        return {"available": False}
    scratch.mkdir(parents=True, exist_ok=True)
    servers = FixtureServers(MappingAuthorityState(address))
    dns_port, mixed_port = reserve_port(), reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        config_text(
            dns_port=dns_port,
            mixed_port=mixed_port,
            upstream_port=servers.authority.server_address[1],
        )
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        fake = query_data(dns_port, "reverse.phase4f14.test", 0x7350)
        tcp = wait_tcp_echo(
            socks5_connect,
            mixed_port,
            fake,
            int(servers.tcp_echo.server_address[1]),
            "fake-tcp",
        )
        try:
            udp = wait_udp_echo(
                mixed_port,
                fake,
                int(servers.udp_echo.server_address[1]),
                "fake-udp",
            )
        except TimeoutError as error:
            stdout.flush()
            stderr.flush()
            raise TimeoutError(
                f"{error}; binary={binary}; stdout={(scratch / 'stdout.log').read_text()}; "
                f"stderr={(scratch / 'stderr.log').read_text()}"
            ) from error
        return {
            "available": True,
            "fake": fake,
            "tcp": tcp,
            "udp": udp,
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()
        servers.close()


def run_corruption_case(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authority_port: int,
) -> dict[str, Any]:
    home = scratch / ".config" / "mihomo"
    home.mkdir(parents=True, exist_ok=True)
    (home / "cache.db").write_bytes(b"not-a-bbolt-database")
    dns_port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        config_text(
            dns_port=dns_port,
            mixed_port=reserve_port(),
            upstream_port=authority_port,
            store=True,
        )
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        return {
            "address": query_data(dns_port, "corrupt.phase4f14.test", 0x7360),
            "exit-code": stop(process),
        }
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def run_candidate(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authority_port: int,
) -> dict[str, Any]:
    legacy_filters = [
        "*.legacy.phase4f14.test",
        "+.suffix.phase4f14.test",
        "rule-set:domains",
        "geosite:PHASE4F8",
    ]
    legacy_names = [
        "one.legacy.phase4f14.test",
        "deep.suffix.phase4f14.test",
        "deep.provider.phase4f14.test",
        "x.plain-token.test",
        "unmatched.phase4f14.test",
    ]
    rule_filters = [
        "DOMAIN,exact.phase4f14.test,real-ip,no-resolve",
        "DOMAIN-SUFFIX,suffix-rule.phase4f14.test,real-ip",
        "DOMAIN-KEYWORD,keyword-rule,real-ip",
        r"DOMAIN-REGEX,^regex\.[a-z]+\.phase4f14\.test$,real-ip",
        "DOMAIN-WILDCARD,*.wild.phase4f14.test,real-ip",
        "RULE-SET,domains,real-ip",
        "GEOSITE,PHASE4F8,real-ip",
        "MATCH,fake-ip",
    ]
    rule_names = [
        "exact.phase4f14.test",
        "deep.suffix-rule.phase4f14.test",
        "has-keyword-rule-here.test",
        "regex.name.phase4f14.test",
        "one.wild.phase4f14.test",
        "deep.provider.phase4f14.test",
        "x.plain-token.test",
        "fallback-fake.phase4f14.test",
    ]
    return {
        "legacy-blacklist": run_filter_case(
            binary, scratch / "legacy", authority_port, "blacklist", legacy_filters, legacy_names
        ),
        "ordered-rule": run_filter_case(
            binary, scratch / "rule", authority_port, "rule", rule_filters, rule_names
        ),
        "reload-range": run_reload_case(binary, scratch / "reload", authority_port),
        "persistent-live-range": run_reload_case(
            binary, scratch / "persistent-reload", authority_port, persistent=True
        ),
        "persistent-saved-range-reset": run_reload_case(
            binary,
            scratch / "persistent-saved-reload",
            authority_port,
            persistent=True,
            saved_state=True,
        ),
        "flush": run_flush_case(binary, scratch / "flush", authority_port),
        "reverse": run_reverse_case(binary, scratch / "reverse"),
        "corruption": run_corruption_case(binary, scratch / "corruption", authority_port),
    }


def interchange_generation(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    authority_port: int,
    queries: list[tuple[str, int]],
) -> tuple[dict[str, str], int]:
    dns_port, mixed_port = reserve_port(), reserve_port()
    config = scratch / "interchange.yaml"
    config.write_text(
        config_text(
            dns_port=dns_port,
            mixed_port=mixed_port,
            upstream_port=authority_port,
            store=True,
        )
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_dns_ready(process, dns_port)
        addresses = {
            f"{name}/{record_type}": query_type_data(
                dns_port, name, record_type, 0x7400 + index
            )
            for index, (name, record_type) in enumerate(queries)
        }
        # Listener readiness can precede Go's signal.Notify calls. On Linux,
        # wait for the caught-signal mask directly before SIGTERM persists the
        # allocation offset. Never use SIGHUP as this barrier: the oracle only
        # stores the persistent offset during shutdown, so constructing a new
        # pool before then correctly treats mappings-without-offset as stale
        # and flushes the very interchange state this fixture must observe.
        if not wait_for_linux_signal_handlers(process):
            time.sleep(0.05)
            if process.poll() is not None:
                raise AssertionError("candidate exited before interchange shutdown")
        return addresses, stop(process)
    finally:
        if process.poll() is None:
            stop(process)
        stdout.close()
        stderr.close()


def run_interchange(
    binaries: dict[str, pathlib.Path],
    scratch: pathlib.Path,
    authority_port: int,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    one = "go-to-rust.phase4f14.test"
    two = "rust-to-go.phase4f14.test"
    three = "next.phase4f14.test"
    six_one = "go-to-rust-v6.phase4f14.test"
    six_two = "rust-to-go-v6.phase4f14.test"
    six_three = "next-v6.phase4f14.test"
    go_first, go_exit = interchange_generation(
        binaries["go"],
        scratch,
        authority_port,
        [
            ("prefill-one.phase4f14.test", 1),
            ("prefill-two.phase4f14.test", 1),
            (one, 1),
            (six_one, 28),
        ],
    )
    rust_middle, rust_exit = interchange_generation(
        binaries["rust"],
        scratch,
        authority_port,
        [(one, 1), (six_one, 28), (two, 1), (six_two, 28)],
    )
    go_last, last_exit = interchange_generation(
        binaries["go"],
        scratch,
        authority_port,
        [(two, 1), (six_two, 28), (three, 1), (six_three, 28)],
    )
    result = {
        "go-first": go_first,
        "rust-middle": rust_middle,
        "go-last": go_last,
        "exit-codes": [go_exit, rust_exit, last_exit],
    }
    if (
        go_first[f"{one}/1"] != rust_middle[f"{one}/1"]
        or go_first[f"{six_one}/28"] != rust_middle[f"{six_one}/28"]
        or rust_middle[f"{two}/1"] != go_last[f"{two}/1"]
        or rust_middle[f"{six_two}/28"] != go_last[f"{six_two}/28"]
    ):
        FAILURE_ARTIFACT.write_text(
            json.dumps({"interchange": result}, indent=2, sort_keys=True)
        )
        raise AssertionError(
            f"Go/Rust bbolt fake-IP mappings were not interchangeable; "
            f"see {FAILURE_ARTIFACT}"
        )
    return result


def main() -> None:
    os.environ["SKIP_SYSTEM_IPV6_CHECK"] = "1"
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase4f14-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        authority_state = AuthorityState(REAL_ADDRESS)
        authority: socketserver.ThreadingUDPServer = AuthorityServer(
            ("127.0.0.1", 0), AuthorityHandler
        )
        authority.state = authority_state  # type: ignore[attr-defined]
        thread = threading.Thread(target=authority.serve_forever, daemon=True)
        thread.start()
        try:
            observations = {
                name: run_candidate(binary, root / name, authority.server_address[1])
                for name, binary in binaries.items()
            }
            observations["interchange"] = run_interchange(
                binaries, root / "interchange", authority.server_address[1]
            )
            if observations["go"] != observations["rust"]:
                FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
                raise SystemExit(f"Phase 4F14 mismatch; see {FAILURE_ARTIFACT}")
        finally:
            authority.shutdown()
            authority.server_close()
            thread.join(timeout=IO_DEADLINE)
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 4F14 fake-IP differential and interchange passed")


if __name__ == "__main__":
    main()

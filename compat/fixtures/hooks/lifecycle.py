#!/usr/bin/env python3
"""Probe lifecycle resource ordering from a Mihomo shell hook."""

from __future__ import annotations

import pathlib
import socket
import sys
import time


RESOURCE_DEADLINE = 10.0


def probe_tcp(port: int) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=1):
        pass


def wait_tcp(port: int) -> None:
    deadline = time.monotonic() + RESOURCE_DEADLINE
    while time.monotonic() < deadline:
        try:
            probe_tcp(port)
            return
        except OSError:
            time.sleep(0.02)
    raise OSError(f"TCP port {port} did not become ready during post-up")


def bind_udp(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))


def udp_is_occupied(port: int) -> bool:
    try:
        bind_udp(port)
    except OSError:
        return True
    return False


def tcp_is_live(port: int) -> bool:
    try:
        probe_tcp(port)
    except OSError:
        return False
    return True


def record_state(path: pathlib.Path, resource: str, live: bool) -> None:
    state = "live" if live else "released"
    record_observation(path, f"down:{resource}-{state}")


def record_observation(path: pathlib.Path, observation: str) -> None:
    with path.open("a") as record:
        record.write(f"{observation}\n")


def main() -> None:
    action, record_name, mixed, controller, dns = sys.argv[1:]
    ports = [int(mixed), int(controller), int(dns)]
    record = pathlib.Path(record_name)
    if action == "up":
        for port in ports:
            wait_tcp(port)
        record_observation(record, "up:resources-ready")
    elif action == "down":
        record_observation(record, "down:started")
        record_state(record, "mixed-tcp", tcp_is_live(ports[0]))
        record_state(record, "mixed-udp", udp_is_occupied(ports[0]))
        record_state(record, "controller", tcp_is_live(ports[1]))
        record_state(record, "dns-tcp", tcp_is_live(ports[2]))
        record_state(record, "dns-udp", udp_is_occupied(ports[2]))
    else:
        raise ValueError(f"unknown lifecycle action: {action}")


if __name__ == "__main__":
    main()

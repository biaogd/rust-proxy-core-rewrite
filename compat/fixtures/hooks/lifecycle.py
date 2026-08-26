#!/usr/bin/env python3
"""Probe lifecycle resource ordering from a Mihomo shell hook."""

from __future__ import annotations

import pathlib
import socket
import sys


def probe_tcp(port: int) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=1):
        pass


def bind_udp(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))


def require_udp_occupied(port: int) -> None:
    try:
        bind_udp(port)
    except OSError:
        return
    raise OSError(f"UDP port {port} was released before post-down")


def record_observation(path: pathlib.Path, observation: str) -> None:
    with path.open("a") as record:
        record.write(f"{observation}\n")


def main() -> None:
    action, record_name, mixed, controller, dns = sys.argv[1:]
    ports = [int(mixed), int(controller), int(dns)]
    record = pathlib.Path(record_name)
    if action == "up":
        for port in ports:
            probe_tcp(port)
        record_observation(record, "up:resources-ready")
    elif action == "down":
        probe_tcp(ports[0])
        record_observation(record, "down:mixed-tcp-live")
        require_udp_occupied(ports[0])
        record_observation(record, "down:mixed-udp-live")
        probe_tcp(ports[1])
        record_observation(record, "down:controller-live")
        probe_tcp(ports[2])
        record_observation(record, "down:dns-tcp-live")
        require_udp_occupied(ports[2])
        record_observation(record, "down:dns-udp-live")
    else:
        raise ValueError(f"unknown lifecycle action: {action}")


if __name__ == "__main__":
    main()

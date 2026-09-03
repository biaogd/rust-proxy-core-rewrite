#!/usr/bin/env python3
"""Go/Rust differential for Phase 6E-H VLESS REALITY over native TCP."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_tcp import (
    LARGE_PAYLOAD,
    STANDARD_UUID,
    config_validation,
    exchange,
    rejected_exchange,
)


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6e-vless-reality-diff.json"

REALITY_PUBLIC_KEY = "Cu7X8PtrU22DHCW46oyZfgEEFLoWMxJYWhHOpBIokhc"
REALITY_SHORT_ID = "10f897e26c4b9478"
REALITY_SERVER_NAME = "itunes.apple.com"


def build_authority(output: pathlib.Path) -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    binary = output / f"vless-reality-authority{suffix}"
    subprocess.run(
        [
            "go",
            "build",
            "-trimpath",
            "-o",
            str(binary),
            "./compat/helpers/vless_reality_authority",
        ],
        cwd=ROOT,
        check=True,
    )
    return binary


def start_authority(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    port: int,
    *,
    log_name: str,
    transport: str = "tcp",
    expected_http_host: str = "",
    expected_http_path: str = "/",
) -> tuple[Any, Any, Any, pathlib.Path]:
    stdout_path = scratch / f"{log_name}-stdout.log"
    stdout = stdout_path.open("wb")
    stderr = (scratch / f"{log_name}-stderr.log").open("wb")
    command = [
        str(binary),
        "-listen",
        f"127.0.0.1:{port}",
        "-uuid",
        STANDARD_UUID,
        "-transport",
        transport,
        "-expected-http-host",
        expected_http_host,
        "-expected-http-path",
        expected_http_path,
    ]
    process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
    output = scratch / f"{log_name}-output.log"
    return process, stdout, stderr, output


def reality_record(name: str, authority_port: int, *, support_mlkem: bool = False) -> str:
    mlkem = "      support-x25519mlkem768: true\n" if support_mlkem else ""
    return f"""  - name: {name}
    type: vless
    server: 127.0.0.1
    port: {authority_port}
    uuid: {STANDARD_UUID}
    encryption: none
    network: tcp
    tls: true
    client-fingerprint: chrome
    servername: {REALITY_SERVER_NAME}
    reality-opts:
      public-key: {REALITY_PUBLIC_KEY}
      short-id: {REALITY_SHORT_ID}
{mlkem}
"""


def is_grease(value: int) -> bool:
    return value & 0x0F0F == 0x0A0A


def hex_u16(value: int) -> str:
    return f"0x{0x0A0A if is_grease(value) else value:04x}"


def parse_vector_u16(body: bytes) -> list[str]:
    size = int.from_bytes(body[:2], "big")
    return [hex_u16(int.from_bytes(body[offset : offset + 2], "big")) for offset in range(2, 2 + size, 2)]


def parse_protocols(body: bytes) -> list[str]:
    size = int.from_bytes(body[:2], "big")
    protocols: list[str] = []
    offset = 2
    while offset < 2 + size:
        length = body[offset]
        offset += 1
        protocols.append(body[offset : offset + length].decode("ascii"))
        offset += length
    return protocols


def parse_u8_sized_u16_vector(body: bytes) -> list[str]:
    size = body[0]
    return [
        hex_u16(int.from_bytes(body[offset : offset + 2], "big"))
        for offset in range(1, 1 + size, 2)
    ]


def parse_client_hello(record: bytes) -> dict[str, Any]:
    if len(record) < 9 or record[0] != 0x16 or record[5] != 0x01:
        raise ValueError("capture is not a TLS ClientHello")
    record_size = int.from_bytes(record[3:5], "big")
    handshake = record[5 : 5 + record_size]
    body_size = int.from_bytes(handshake[1:4], "big")
    body = handshake[4 : 4 + body_size]
    if len(body) != body_size:
        raise ValueError("truncated ClientHello")

    offset = 34
    session_id_length = body[offset]
    offset += 1 + session_id_length
    cipher_size = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    ciphers = [
        hex_u16(int.from_bytes(body[index : index + 2], "big"))
        for index in range(offset, offset + cipher_size, 2)
    ]
    offset += cipher_size
    compression_size = body[offset]
    offset += 1
    compression = list(body[offset : offset + compression_size])
    offset += compression_size
    extension_size = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    extension_end = offset + extension_size
    extensions: list[tuple[int, bytes]] = []
    while offset < extension_end:
        kind = int.from_bytes(body[offset : offset + 2], "big")
        length = int.from_bytes(body[offset + 2 : offset + 4], "big")
        offset += 4
        extensions.append((kind, body[offset : offset + length]))
        offset += length
    if offset != extension_end:
        raise ValueError("invalid ClientHello extensions")

    by_type = {kind: value for kind, value in extensions if not is_grease(kind)}
    server_name_body = by_type[0x0000]
    server_name_length = int.from_bytes(server_name_body[3:5], "big")
    server_name = server_name_body[5 : 5 + server_name_length].decode("ascii")

    key_share_body = by_type[0x0033]
    key_share_size = int.from_bytes(key_share_body[:2], "big")
    key_shares = []
    index = 2
    while index < 2 + key_share_size:
        group = int.from_bytes(key_share_body[index : index + 2], "big")
        length = int.from_bytes(key_share_body[index + 2 : index + 4], "big")
        index += 4
        key_shares.append({"group": hex_u16(group), "length": length})
        index += length

    versions_body = by_type[0x002B]
    signature_body = by_type[0x000D]
    ech = by_type[0xFE0D]
    enc_length = int.from_bytes(ech[6:8], "big")
    payload_offset = 8 + enc_length
    payload_length = int.from_bytes(ech[payload_offset : payload_offset + 2], "big")
    extension_types = [hex_u16(kind) for kind, _ in extensions]
    grease_extensions = [(kind, value) for kind, value in extensions if is_grease(kind)]
    return {
        "legacy-version": body[:2].hex(),
        "session-id-length": session_id_length,
        "ciphers": ciphers,
        "compression": compression,
        "extension-types": sorted(extension_types),
        "extension-count": len(extension_types),
        "grease-bookends": bool(
            extensions
            and is_grease(extensions[0][0])
            and is_grease(extensions[-1][0])
            and len(grease_extensions) == 2
            and grease_extensions[0][0] != grease_extensions[1][0]
        ),
        "grease-extension-lengths": sorted(len(value) for _, value in grease_extensions),
        "server-name": server_name,
        "extended-master-secret": by_type[0x0017].hex(),
        "renegotiation-info": by_type[0xFF01].hex(),
        "groups": parse_vector_u16(by_type[0x000A]),
        "point-formats": list(by_type[0x000B][1 : 1 + by_type[0x000B][0]]),
        "session-ticket": by_type[0x0023].hex(),
        "alpn": parse_protocols(by_type[0x0010]),
        "status-request": by_type[0x0005].hex(),
        "signature-algorithms": parse_vector_u16(signature_body),
        "signed-certificate-timestamps": by_type[0x0012].hex(),
        "key-shares": key_shares,
        "psk-modes": list(by_type[0x002D][1 : 1 + by_type[0x002D][0]]),
        "supported-versions": [
            hex_u16(int.from_bytes(versions_body[index : index + 2], "big"))
            for index in range(1, 1 + versions_body[0], 2)
        ],
        "certificate-compression": parse_u8_sized_u16_vector(by_type[0x001B]),
        "application-settings": parse_protocols(by_type[0x44CD]),
        "ech-shape": {
            "outer": ech[0],
            "kdf": ech[1:3].hex(),
            "aead": ech[3:5].hex(),
            "enc-length": enc_length,
            "payload-length-valid": payload_length in (144, 176, 208, 240),
        },
    }


class ClientHelloCapture:
    def __init__(self) -> None:
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = int(self.listener.getsockname()[1])
        self.record: bytes | None = None
        self.error: Exception | None = None
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._capture, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _capture(self) -> None:
        try:
            stream, _ = self.listener.accept()
            with stream:
                stream.settimeout(IO_DEADLINE)
                header = bytearray()
                while len(header) < 5:
                    chunk = stream.recv(5 - len(header))
                    if not chunk:
                        raise EOFError("ClientHello record header")
                    header.extend(chunk)
                body = bytearray()
                length = int.from_bytes(header[3:5], "big")
                while len(body) < length:
                    chunk = stream.recv(length - len(body))
                    if not chunk:
                        raise EOFError("ClientHello record body")
                    body.extend(chunk)
                self.record = bytes(header + body)
        except Exception as error:
            self.error = error
        finally:
            self.done.set()

    def shape(self) -> dict[str, Any]:
        if not self.done.wait(IO_DEADLINE):
            raise TimeoutError("ClientHello capture timed out")
        if self.error is not None:
            raise self.error
        if self.record is None:
            raise RuntimeError("ClientHello capture is empty")
        return parse_client_hello(self.record)

    def close(self) -> None:
        self.listener.close()
        self.thread.join(timeout=2)


def wait_observations(output: pathlib.Path, expected: set[str]) -> list[str]:
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        observed = {
            line.strip()
            for line in output.read_text(errors="replace").splitlines()
            if line.startswith("CONNECT ")
        }
        if expected <= observed:
            return sorted(expected)
        time.sleep(0.05)
    raise TimeoutError(f"missing VLESS REALITY observations: {sorted(expected - observed)}")


def initial_exchange(mixed_port: int) -> bool:
    deadline = time.monotonic() + IO_DEADLINE
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if exchange(mixed_port, "reality.phase6e", 26022, b"vless-reality"):
                return True
        except (AssertionError, EOFError, OSError, ValueError) as error:
            last_error = error
        time.sleep(0.05)
    if last_error is not None:
        raise last_error
    return False


def exercise(binary: pathlib.Path, scratch: pathlib.Path, authority_binary: pathlib.Path) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    client_hello = ClientHelloCapture()
    client_hello.start()
    authority_port = reserve_port()
    authority_scratch = scratch / "authority"
    authority_scratch.mkdir(parents=True, exist_ok=True)
    authority_stdout_path = authority_scratch / "reality-authority-stdout.log"
    authority_stdout = authority_stdout_path.open("wb")
    authority_stderr = (authority_scratch / "reality-authority-stderr.log").open("wb")
    authority_output = authority_scratch / "reality-authority-output.log"
    authority_process = subprocess.Popen(
        [
            str(authority_binary),
            "-listen",
            f"127.0.0.1:{authority_port}",
            "-uuid",
            STANDARD_UUID,
        ],
        stdout=authority_stdout,
        stderr=authority_stderr,
        start_new_session=True,
    )
    try:
        ready_deadline = time.monotonic() + IO_DEADLINE
        while time.monotonic() < ready_deadline:
            text = authority_stdout_path.read_text(errors="replace")
            if "READY " in text:
                break
            if authority_process.poll() is not None:
                raise RuntimeError(
                    f"reality authority exited early: {authority_stderr.read().decode(errors='replace')}"
                )
            time.sleep(0.05)
        else:
            raise TimeoutError("reality authority did not become ready")

        mixed_port, controller_port = reserve_port(), reserve_port()
        config = scratch / "config.yaml"
        config.write_text(
            f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
proxies:
{reality_record("vless-reality", authority_port)}{reality_record("vless-reality-hybrid", authority_port, support_mlkem=True)}{reality_record("vless-reality-capture", client_hello.port)}rules:
  - DST-PORT,26022,vless-reality
  - DST-PORT,26023,vless-reality-hybrid
  - DST-PORT,26024,vless-reality-capture
  - MATCH,REJECT
"""
        )
        process, stdout, stderr = launch(binary, config, scratch)
        try:
            wait_ready(process, mixed_port)
            wait_controller(process, controller_port)
            # The Go oracle announces its listeners slightly before the default
            # proxy provider is routable. Keep the readiness probe bounded and
            # require a real end-to-end exchange before collecting evidence.
            small = initial_exchange(mixed_port)
            large = exchange(mixed_port, "reality-large.phase6e", 26022, LARGE_PAYLOAD)
            half_close = exchange(
                mixed_port,
                "reality-half.phase6e",
                26022,
                b"vless-reality-half",
                half_close=True,
            )
            hybrid = exchange(
                mixed_port,
                "reality-hybrid.phase6e",
                26023,
                b"vless-reality-hybrid",
            )
            capture_rejected = rejected_exchange(
                mixed_port, "clienthello.phase6e", 26024
            )
            reality_without_tls = (
                config_validation(
                    binary,
                    scratch,
                    "proxies:\n"
                    "  - name: bad\n    type: vless\n    server: 127.0.0.1\n    port: 1\n"
                    f"    uuid: {STANDARD_UUID}\n    encryption: none\n    network: tcp\n"
                    "    client-fingerprint: chrome\n    reality-opts:\n"
                    f"      public-key: {REALITY_PUBLIC_KEY}\n      short-id: {REALITY_SHORT_ID}\n",
                )
                is False
            )
            reality_without_fingerprint = (
                config_validation(
                    binary,
                    scratch,
                    "proxies:\n"
                    "  - name: bad\n    type: vless\n    server: 127.0.0.1\n    port: 1\n"
                    f"    uuid: {STANDARD_UUID}\n    encryption: none\n    network: tcp\n    tls: true\n"
                    "    servername: itunes.apple.com\n    reality-opts:\n"
                    f"      public-key: {REALITY_PUBLIC_KEY}\n      short-id: {REALITY_SHORT_ID}\n",
                )
                is False
            )
            expected = {
                "CONNECT reality.phase6e:26022",
                "CONNECT reality-large.phase6e:26022",
                "CONNECT reality-half.phase6e:26022",
                "CONNECT reality-hybrid.phase6e:26023",
            }
            authority_stdout_path.read_text(errors="replace")
            # Mirror authority CONNECT lines into a dedicated observation file.
            authority_output.write_text(authority_stdout_path.read_text(errors="replace"))
            return {
                "small": small,
                "large": large,
                "half-close": half_close,
                "hybrid-mlkem": hybrid,
                "capture-connection-rejected": capture_rejected,
                "clienthello-shape": client_hello.shape(),
                "reality-without-tls-rejected": reality_without_tls,
                "reality-without-fingerprint-rejected": reality_without_fingerprint,
                "authority": wait_observations(authority_output, expected),
                "process-alive": process.poll() is None,
            }
        finally:
            stop(process)
            stdout.close()
            stderr.close()
    finally:
        stop(authority_process)
        authority_stdout.close()
        authority_stderr.close()
        client_hello.close()


def contract_errors(name: str, observations: dict[str, Any]) -> list[str]:
    errors = []
    for field in [
        "small",
        "large",
        "half-close",
        "hybrid-mlkem",
        "capture-connection-rejected",
        "process-alive",
    ]:
        if observations[field] is not True:
            errors.append(f"{name}: {field} was not true")
    if name == "rust":
        for field in ["reality-without-tls-rejected", "reality-without-fingerprint-rejected"]:
            if observations[field] is not True:
                errors.append(f"{name}: {field} was not rejected")
    return errors


def main() -> int:
    scratch = pathlib.Path(tempfile.mkdtemp(prefix="phase6e-vless-reality-"))
    authority_binary = build_authority(scratch)
    binaries = build_binaries(scratch, "PHASE6EVLESSREALITY_CARGO_TARGET", "phase6e-h-vless")
    results: dict[str, Any] = {}
    errors: list[str] = []
    for name in ("go", "rust"):
        binary = binaries[name]
        try:
            results[name] = exercise(binary, scratch / name, authority_binary)
            errors.extend(contract_errors(name, results[name]))
        except Exception as error:
            results[name] = {"error": str(error), "debug": debug_files(scratch / name)}
            errors.append(f"{name}: {error}")
    if not errors and results["go"]["clienthello-shape"] != results["rust"]["clienthello-shape"]:
        errors.append("Go/Rust REALITY ClientHello normalized structures differ")
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    FAILURE_ARTIFACT.write_text(json.dumps(results, indent=2) + "\n")
    if errors:
        raise SystemExit("\n".join(errors))
    print("phase6e_vless_reality: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

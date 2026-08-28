#!/usr/bin/env python3
"""Phase 5E controller TLS client-auth mode differential."""

from __future__ import annotations

import json
import pathlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from typing import Any

from phase1 import IO_DEADLINE, ROOT, reserve_port, wait_ready
from phase3 import launch, stop
from phase5b1a import build_binaries, debug_files
from phase5d_streams import SECRET


FAILURE_ARTIFACT = ROOT / "compat/artifacts/phase5e-tls-client-auth-diff.json"


def command(*arguments: str) -> None:
    subprocess.run(
        ["openssl", *arguments],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def certificates(root: pathlib.Path) -> dict[str, pathlib.Path]:
    ca_key, client_ca = root / "client-ca.key", root / "client-ca.pem"
    command(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-subj", "/CN=phase5e-client-root", "-keyout", str(ca_key), "-out", str(client_ca),
    )

    def signed(name: str, usage: str) -> tuple[pathlib.Path, pathlib.Path]:
        key, csr, cert = root / f"{name}.key", root / f"{name}.csr", root / f"{name}.pem"
        command(
            "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}",
            "-keyout", str(key), "-out", str(csr),
        )
        extension = root / f"{name}.ext"
        extension.write_text(f"extendedKeyUsage={usage}\nsubjectAltName=IP:127.0.0.1\n")
        command(
            "x509", "-req", "-in", str(csr), "-CA", str(client_ca), "-CAkey", str(ca_key),
            "-CAcreateserial", "-days", "2", "-extfile", str(extension), "-out", str(cert),
        )
        return cert, key

    client, client_key = signed("phase5e-client", "clientAuth")
    untrusted, untrusted_key = root / "untrusted.pem", root / "untrusted.key"
    command(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-subj", "/CN=untrusted-client", "-addext", "extendedKeyUsage=clientAuth",
        "-keyout", str(untrusted_key), "-out", str(untrusted),
    )
    return {
        "ca": ROOT / "compat/fixtures/phase4/phase4e2-root.pem",
        "client-ca": client_ca,
        "server": ROOT / "compat/fixtures/phase4/phase4e2-server.pem",
        "server-key": ROOT / "compat/fixtures/phase4/phase4e2-server-key.pem",
        "trusted": client,
        "trusted-key": client_key,
        "untrusted": untrusted,
        "untrusted-key": untrusted_key,
    }


def tls_request(
    port: int,
    material: dict[str, pathlib.Path],
    client: str | None,
) -> str:
    context = ssl.create_default_context(cafile=str(material["ca"]))
    context.check_hostname = False
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    if client is not None:
        context.load_cert_chain(material[client], material[f"{client}-key"])
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=IO_DEADLINE) as raw:
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as stream:
                stream.sendall(
                    b"GET / HTTP/1.1\r\nHost: controller\r\n"
                    + f"Authorization: Bearer {SECRET}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                )
                response = stream.recv(4096)
                return "ok" if b" 200 " in response.split(b"\r\n", 1)[0] else "rejected"
    except (OSError, ssl.SSLError):
        return "rejected"


def exercise_mode(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    material: dict[str, pathlib.Path],
    mode: str,
) -> dict[str, str]:
    mixed, controller = reserve_port(), reserve_port()
    config = scratch / f"{mode}.yaml"
    config.write_text(
        f"""mixed-port: {mixed}
external-controller-tls: 127.0.0.1:{controller}
secret: {SECRET}
mode: rule
log-level: info
ipv6: false
tls:
  certificate: {material['server']}
  private-key: {material['server-key']}
  client-auth-type: {mode}
  client-auth-cert: {material['client-ca']}
rules:
  - MATCH,DIRECT
"""
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed)
        deadline = time.monotonic() + IO_DEADLINE
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", controller), timeout=0.1):
                    break
            except OSError:
                pass
            time.sleep(0.02)
        else:
            raise TimeoutError(f"TLS controller did not become ready for {mode}")
        return {
            "none": tls_request(controller, material, None),
            "trusted": tls_request(controller, material, "trusted"),
            "untrusted": tls_request(controller, material, "untrusted"),
        }
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def exercise(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    material: dict[str, pathlib.Path],
) -> dict[str, Any]:
    profile = scratch / ".config/mihomo"
    profile.mkdir(parents=True)
    local: dict[str, pathlib.Path] = {}
    for name, path in material.items():
        local[name] = profile / path.name
        shutil.copyfile(path, local[name])
    return {
        mode: exercise_mode(binary, scratch, local, mode)
        for mode in ("request", "require-any", "verify-if-given", "require-and-verify")
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase5e-tls-auth-") as temporary:
        root = pathlib.Path(temporary)
        material = certificates(root)
        binaries = build_binaries(root, "PHASE5ETLSAUTH_CARGO_TARGET", "phase5e-tls-auth")
        try:
            for name, binary in binaries.items():
                scratch = root / name
                scratch.mkdir()
                observations[name] = exercise(binary, scratch, material)
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(json.dumps({
                "error": f"{type(error).__name__}: {error}",
                "observations": observations,
                "debug": debug_files(root),
            }, indent=2, sort_keys=True))
            raise
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5E TLS client-auth differential passed")
    print(json.dumps(observations["rust"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

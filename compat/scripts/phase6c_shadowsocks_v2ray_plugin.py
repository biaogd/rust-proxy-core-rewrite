#!/usr/bin/env python3
"""Unified Go/Rust differential for the documented v2ray-plugin TCP surface."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import textwrap
import time
from typing import Any

from phase1 import EchoHandler, HalfCloseHandler, IO_DEADLINE, ROOT, cargo_target_path, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase4e2 import ROOT_CERTIFICATE, SERVER_CERTIFICATE, SERVER_KEY
from phase4f10 import LocalAuthority
from phase5b1a import build_binaries, debug_files
from phase6c_shadowsocks import CIPHER, PASSWORD
from phase6c_shadowsocks_ciphers import LARGE_PAYLOAD, echo, half_close, wait_route
from phase6c_shadowsocks_v2ray_websocket import start_authority


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase6c-shadowsocks-v2ray-plugin-diff.json"
TARGET_ENV = "PHASE6CSSV2RAYPLUGIN_CARGO_TARGET"
TARGET_NAME = "phase6c-shadowsocks-v2ray-plugin"


def target_dir() -> pathlib.Path:
    return cargo_target_path(TARGET_ENV, TARGET_NAME)


def authority_binary() -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    return target_dir() / "debug" / f"rewrite-shadowsocks-websocket-authority{suffix}"


def build_ech_authority() -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    output = target_dir() / f"v2ray-ech-authority{suffix}"
    subprocess.run(
        ["go", "build", "-o", str(output), "./compat/helpers/v2ray_ech_authority"],
        cwd=ROOT,
        check=True,
        timeout=120,
    )
    return output


def tls_root_yaml() -> str:
    root = pathlib.Path(ROOT_CERTIFICATE).read_text().strip()
    return "tls:\n  custom-certifactes:\n    - |-\n" + textwrap.indent(root, "      ") + "\n"


def config_text(
    mixed_port: int,
    authority_port: int,
    options: str,
    *,
    trust_root: bool = False,
    dns_block: str = "",
) -> str:
    prefix = (tls_root_yaml() if trust_root else "") + dns_block
    return f"""{prefix}mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: false
proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: {authority_port}
    cipher: {CIPHER}
    password: {PASSWORD}
    plugin: v2ray-plugin
    plugin-opts:
{options}rules:
  - MATCH,local-ss
"""


def write_options(path: pathlib.Path, **values: Any) -> pathlib.Path:
    path.write_text(json.dumps(values, sort_keys=True))
    return path


def safe_echo(mixed_port: int, echo_port: int, payload: bytes) -> bool:
    try:
        return echo(mixed_port, "localhost", echo_port, payload)
    except (EOFError, OSError):
        return False


def run_case(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    echo_port: int,
    *,
    host: str,
    path: str,
    plugin_options: str,
    authority_options: dict[str, Any],
    tls: bool = False,
    trust_root: bool = False,
    half_close_port: int | None = None,
) -> dict[str, bool]:
    scratch.mkdir()
    authority_port = reserve_port()
    mixed_port = reserve_port()
    options_path = write_options(scratch / "authority.json", **authority_options)
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority,
        scratch,
        authority_port,
        host=host,
        path=path,
        certificate=pathlib.Path(SERVER_CERTIFICATE) if tls else None,
        private_key=pathlib.Path(SERVER_KEY) if tls else None,
        options=options_path,
    )
    config = scratch / "config.yaml"
    config.write_text(config_text(mixed_port, authority_port, plugin_options, trust_root=trust_root))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_route(process, mixed_port, echo_port)
        result = {
            "domain": safe_echo(mixed_port, echo_port, b"v2ray-plugin-complete"),
            "large": safe_echo(mixed_port, echo_port, LARGE_PAYLOAD),
            "process-alive": process.poll() is None,
        }
        if half_close_port is not None:
            try:
                result["half-close"] = half_close(mixed_port, half_close_port)
            except (EOFError, OSError):
                result["half-close"] = False
        return result
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()


def run_rejected_tls_case(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    echo_port: int,
) -> dict[str, bool]:
    scratch.mkdir()
    authority_port = reserve_port()
    mixed_port = reserve_port()
    options_path = write_options(scratch / "authority.json", mux=False)
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority,
        scratch,
        authority_port,
        host="dot.phase4.test",
        path="/untrusted",
        certificate=pathlib.Path(SERVER_CERTIFICATE),
        private_key=pathlib.Path(SERVER_KEY),
        options=options_path,
    )
    plugin = """      mode: websocket
      host: dot.phase4.test
      path: /untrusted
      mux: false
      tls: true
"""
    config = scratch / "config.yaml"
    config.write_text(config_text(mixed_port, authority_port, plugin))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        return {
            "route-rejected": not safe_echo(mixed_port, echo_port, b"untrusted"),
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()


def generate_client_identity(scratch: pathlib.Path) -> tuple[str, str, pathlib.Path]:
    root_certificate = scratch / "client-root.pem"
    root_key = scratch / "client-root-key.pem"
    certificate = scratch / "client.pem"
    private_key = scratch / "client-key.pem"
    request = scratch / "client.csr"
    extensions = scratch / "client.ext"
    extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=phase6c-v2ray-client-root", "-days", "2",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(root_key), "-out", str(root_certificate),
        ],
        cwd=scratch,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=IO_DEADLINE,
    )
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=phase6c-v2ray-client",
            "-keyout", str(private_key), "-out", str(request),
        ],
        cwd=scratch,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=IO_DEADLINE,
    )
    subprocess.run(
        [
            "openssl", "x509", "-req", "-in", str(request),
            "-CA", str(root_certificate), "-CAkey", str(root_key), "-CAcreateserial",
            "-days", "2", "-extfile", str(extensions), "-out", str(certificate),
        ],
        cwd=scratch,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=IO_DEADLINE,
    )
    return certificate.read_text().strip(), private_key.read_text().strip(), root_certificate


def run_mtls_case(
    binary: pathlib.Path,
    authority: pathlib.Path,
    scratch: pathlib.Path,
    echo_port: int,
    certificate_pem: str,
    private_key_pem: str,
    client_ca: pathlib.Path,
) -> dict[str, bool]:
    scratch.mkdir()
    authority_port = reserve_port()
    mixed_port = reserve_port()
    options = write_options(
        scratch / "authority.json",
        mux=True,
        client_ca_certificate=str(client_ca),
    )
    authority_process, authority_stdout, authority_stderr = start_authority(
        authority,
        scratch,
        authority_port,
        host="dot.phase4.test",
        path="/mtls",
        certificate=pathlib.Path(SERVER_CERTIFICATE),
        private_key=pathlib.Path(SERVER_KEY),
        options=options,
    )
    cert_yaml = textwrap.indent(certificate_pem, "          ")
    key_yaml = textwrap.indent(private_key_pem, "          ")
    plugin = f"""      mode: websocket
      host: dot.phase4.test
      path: /mtls
      tls: true
      certificate: |-
{cert_yaml}
      private-key: |-
{key_yaml}
"""
    config = scratch / "config.yaml"
    config.write_text(config_text(mixed_port, authority_port, plugin, trust_root=True))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_route(process, mixed_port, echo_port)
        return {"route": safe_echo(mixed_port, echo_port, b"mtls"), "process-alive": process.poll() is None}
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()


def generate_ech_pair(go_binary: pathlib.Path, scratch: pathlib.Path) -> tuple[str, pathlib.Path]:
    result = subprocess.run(
        [str(go_binary), "generate", "ech-keypair", "dot.phase4.test"],
        cwd=scratch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        timeout=IO_DEADLINE,
        text=True,
    )
    config = result.stdout.split("Config: ", 1)[1].splitlines()[0].strip()
    key = "\n".join(
        stripped
        for line in result.stdout.split("Key: ", 1)[1].splitlines()
        if (stripped := line.strip())
    ) + "\n"
    key_path = scratch / "ech-key.pem"
    key_path.write_text(key)
    return config, key_path


def start_ech_authority(
    binary: pathlib.Path,
    scratch: pathlib.Path,
    port: int,
    key_path: pathlib.Path,
):
    stdout = (scratch / "ech-authority-stdout.log").open("wb")
    stderr = (scratch / "ech-authority-stderr.log").open("wb")
    process = subprocess.Popen(
        [
            str(binary), f"127.0.0.1:{port}", PASSWORD, CIPHER,
            str(SERVER_CERTIFICATE), str(SERVER_KEY), key_path.read_text(),
        ],
        cwd=scratch,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    deadline = time.monotonic() + IO_DEADLINE
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"ECH authority exited with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return process, stdout, stderr
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("ECH authority did not become ready")


def run_ech_case(
    binary: pathlib.Path,
    ech_authority: pathlib.Path,
    scratch: pathlib.Path,
    echo_port: int,
    ech_config: str,
    ech_key: pathlib.Path,
) -> dict[str, bool]:
    scratch.mkdir()
    authority_port = reserve_port()
    mixed_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_ech_authority(
        ech_authority, scratch, authority_port, ech_key
    )
    plugin = f"""      mode: websocket
      host: dot.phase4.test
      path: /ech
      mux: false
      tls: true
      ech-opts:
        enable: true
        config: {ech_config}
"""
    config = scratch / "config.yaml"
    config.write_text(config_text(mixed_port, authority_port, plugin, trust_root=True))
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_route(process, mixed_port, echo_port)
        return {"route": safe_echo(mixed_port, echo_port, b"ech"), "process-alive": process.poll() is None}
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()


def run_dns_ech_case(
    binary: pathlib.Path,
    ech_authority: pathlib.Path,
    scratch: pathlib.Path,
    echo_port: int,
    ech_config: str,
    ech_key: pathlib.Path,
) -> dict[str, bool]:
    scratch.mkdir()
    main_dns = LocalAuthority({65: ("https", None, 0.0)})
    proxy_dns = LocalAuthority({65: ("ech", base64.b64decode(ech_config), 0.0)})
    authority_port = reserve_port()
    mixed_port = reserve_port()
    authority_process, authority_stdout, authority_stderr = start_ech_authority(
        ech_authority, scratch, authority_port, ech_key
    )
    plugin = """      mode: websocket
      host: dot.phase4.test
      path: /dns-ech
      mux: false
      tls: true
      ech-opts:
        enable: true
        query-server-name: ech-query.phase6c.test
"""
    dns_block = f"""dns:
  enable: true
  listen: 127.0.0.1:{reserve_port()}
  use-hosts: false
  use-system-hosts: false
  nameserver:
    - udp://127.0.0.1:{main_dns.port}
  proxy-server-nameserver:
    - udp://127.0.0.1:{proxy_dns.port}
"""
    config = scratch / "config.yaml"
    config.write_text(
        config_text(
            mixed_port,
            authority_port,
            plugin,
            trust_root=True,
            dns_block=dns_block,
        )
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, mixed_port)
        wait_route(process, mixed_port, echo_port)
        return {
            "route": safe_echo(mixed_port, echo_port, b"dns-ech"),
            "main-dns-unused": not main_dns.state.contacted(65),
            "proxy-dns-used": proxy_dns.state.contacted(65),
            "process-alive": process.poll() is None,
        }
    finally:
        stop(process)
        stop(authority_process)
        stdout.close()
        stderr.close()
        authority_stdout.close()
        authority_stderr.close()
        main_dns.close()
        proxy_dns.close()


def validate(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, bool]:
    valid = """      mode: websocket
      host: phase6c.example
      path: /all?ed=2048
      headers:
        Host: front.example
        X-Phase: 6c
      mux: true
      v2ray-http-upgrade: true
      v2ray-http-upgrade-fast-open: true
"""
    invalid_ech = """      mode: websocket
      tls: true
      ech-opts:
        enable: true
        config: not-base64
"""
    results: dict[str, bool] = {}
    for label, options, expected in (("full", valid, True), ("invalid-ech", invalid_ech, False)):
        config = scratch / f"{label}.yaml"
        config.write_text(config_text(reserve_port(), reserve_port(), options))
        result = subprocess.run(
            [str(binary), "-t", "-f", str(config)],
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=IO_DEADLINE,
        )
        results[label] = (result.returncode == 0) == expected
    return results


def exercise(
    name: str,
    binary: pathlib.Path,
    authority: pathlib.Path,
    ech_authority: pathlib.Path,
    root: pathlib.Path,
    echo_port: int,
    half_close_port: int,
    client_certificate: str,
    client_private_key: str,
    client_ca: pathlib.Path,
    ech_config: str,
    ech_key: pathlib.Path,
) -> dict[str, Any]:
    scratch = root / name
    scratch.mkdir()
    baseline_plain = run_case(
        binary, authority, scratch / "baseline-plain", echo_port,
        host="phase6c.example", path="/baseline",
        plugin_options="""      mode: websocket
      host: phase6c.example
      path: /baseline
      mux: false
""",
        authority_options={"mux": False},
        half_close_port=half_close_port,
    )
    baseline_tls = run_case(
        binary, authority, scratch / "baseline-tls", echo_port,
        host="dot.phase4.test", path="/trusted",
        plugin_options="""      mode: websocket
      host: dot.phase4.test
      path: /trusted
      mux: false
      tls: true
""",
        authority_options={"mux": False}, tls=True, trust_root=True,
        half_close_port=half_close_port,
    )
    skip_tls = run_case(
        binary, authority, scratch / "skip-tls", echo_port,
        host="dot.phase4.test", path="/skip",
        plugin_options="""      mode: websocket
      host: dot.phase4.test
      path: /skip
      mux: false
      tls: true
      skip-cert-verify: true
""",
        authority_options={"mux": False}, tls=True,
    )
    untrusted_tls = run_rejected_tls_case(
        binary, authority, scratch / "untrusted-tls", echo_port
    )
    ordinary = run_case(
        binary, authority, scratch / "ordinary", echo_port,
        host="front.phase6c.test", path="/complete",
        plugin_options="""      mode: websocket
      host: phase6c.test
      path: /complete?z=2&ed=2048&a=1
      headers:
        Host: front.phase6c.test
        X-Phase: complete
""",
        authority_options={
            "expected_headers": {"X-Phase": "complete"},
            "early_data_header": "Sec-WebSocket-Protocol",
            "mux": True,
        },
    )
    raw = {}
    for fast_open in (False, True):
        label = "fast" if fast_open else "normal"
        raw[label] = run_case(
            binary, authority, scratch / f"raw-{label}", echo_port,
            host="raw.phase6c.test", path="/raw",
            plugin_options=f"""      mode: websocket
      host: raw.phase6c.test
      path: /raw?ed=1024
      v2ray-http-upgrade: true
      v2ray-http-upgrade-fast-open: {str(fast_open).lower()}
""",
            authority_options={
                "early_data_header": "Sec-WebSocket-Protocol",
                "mux": True,
                "raw_http_upgrade": True,
            },
        )
    name_override = run_case(
        binary, authority, scratch / "name-override", echo_port,
        host="front.phase6c.test", path="/tls-name",
        plugin_options="""      mode: websocket
      host: dot.phase4.test
      path: /tls-name
      tls: true
      name-cert-verify: dot.phase4.test
      headers:
        Host: front.phase6c.test
""",
        authority_options={"mux": True}, tls=True, trust_root=True,
    )
    # The pin is over DER, not PEM.
    certificate_der = subprocess.run(
        ["openssl", "x509", "-in", str(SERVER_CERTIFICATE), "-outform", "DER"],
        stdout=subprocess.PIPE, check=True, timeout=IO_DEADLINE,
    ).stdout
    fingerprint_hex = hashlib.sha256(certificate_der).hexdigest()
    pin = run_case(
        binary, authority, scratch / "pin", echo_port,
        host="pin.invalid", path="/pin",
        plugin_options=f"""      mode: websocket
      host: pin.invalid
      path: /pin
      tls: true
      fingerprint: {fingerprint_hex}
""",
        authority_options={"mux": True}, tls=True,
    )
    mtls = run_mtls_case(
        binary, authority, scratch / "mtls", echo_port,
        client_certificate, client_private_key, client_ca,
    )
    ech = run_ech_case(
        binary, ech_authority, scratch / "ech", echo_port, ech_config, ech_key
    )
    dns_ech = run_dns_ech_case(
        binary, ech_authority, scratch / "dns-ech", echo_port, ech_config, ech_key
    )
    return {
        "config": validate(binary, scratch),
        "baseline-plain": baseline_plain,
        "baseline-tls": baseline_tls,
        "skip-tls": skip_tls,
        "untrusted-tls": untrusted_tls,
        "ordinary": ordinary,
        "raw": raw,
        "name-override": name_override,
        "certificate-pin": pin,
        "mtls": mtls,
        "ech": ech,
        "dns-ech": dns_ech,
    }


def main() -> int:
    observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="phase6c-shadowsocks-v2ray-plugin-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, TARGET_ENV, TARGET_NAME)
        authority = authority_binary()
        ech_authority = build_ech_authority()
        echo_server = start_server(EchoHandler)
        half_close_server = start_server(HalfCloseHandler)
        identity = root / "identity"
        identity.mkdir()
        client_certificate, client_private_key, client_ca = generate_client_identity(identity)
        ech_config, ech_key = generate_ech_pair(binaries["go"], root)
        try:
            for name, binary in binaries.items():
                observations[name] = exercise(
                    name, binary, authority, ech_authority, root,
                    echo_server.port, half_close_server.port,
                    client_certificate, client_private_key, client_ca,
                    ech_config, ech_key,
                )
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(json.dumps({
                "error": f"{type(error).__name__}: {error}",
                "observations": observations,
                "debug": debug_files(root),
            }, indent=2, sort_keys=True))
            raise
        finally:
            echo_server.close()
            half_close_server.close()
    if observations["go"] != observations["rust"]:
        FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
        return 1
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 6C-M5 complete Shadowsocks v2ray-plugin differential passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

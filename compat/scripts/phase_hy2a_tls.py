#!/usr/bin/env python3
"""Verified TLS positive/negative contracts against the Go HY2 server.

Go constructs proxy TLS pools before applying global custom roots. Bootstrap
the root-only configuration, then reload the proxy on BOTH engines. Separately
require Rust cold-start trust to work; do not reproduce the Go initialization bug.
"""

import json
import pathlib
import tempfile

from hy2_support import build_binaries
from phase1 import EchoHandler, ROOT, reload_via_controller, reserve_port, start_server, wait_ready
from phase3 import launch, stop
from phase5b1a import debug_files
from phase5d_streams import SECRET, wait_controller
from phase6e_vless_tcp import rejected_exchange
from phase_hy2a_hysteria2_tcp import hy2_record, start_authority, trust_roots, wait_exchange

FAILURE_ARTIFACT = ROOT / "compat/artifacts/phase-hy2a-tls-diff.json"


def assert_authority_reachable(binary, scratch, authority_port, echo_port):
    """A negative TLS test must not pass merely because the server is down."""
    scratch.mkdir()
    port = reserve_port()
    config = scratch / "config.yaml"
    config.write_text(
        f"mixed-port: {port}\nmode: rule\nlog-level: warning\nproxies:\n"
        + hy2_record("control", authority_port, skip_verify=True)
        + "rules:\n  - MATCH,control\n"
    )
    process, stdout, stderr = launch(binary, config, scratch)
    try:
        wait_ready(process, port)
        if not wait_exchange(process, port, "127.0.0.1", echo_port, b"authority-control"):
            raise AssertionError("negative TLS control server unavailable")
    finally:
        stop(process)
        stdout.close()
        stderr.close()


def exercise(binary, oracle, scratch, *, trusted, wrong_name=False, cold=False):
    echo = start_server(EchoHandler)
    authority_dir = scratch / "authority"
    authority_dir.mkdir()
    authority_port, mixed_port, controller_port = (reserve_port() for _ in range(3))
    authority, a_out, a_err = start_authority(oracle, authority_dir, authority_port)
    process = stdout = stderr = None
    try:
        prefix = (trust_roots() if trusted else "") + (
            f"mixed-port: {mixed_port}\nexternal-controller: 127.0.0.1:{controller_port}\n"
            f"secret: {SECRET}\nmode: rule\nlog-level: warning\nipv6: false\n"
        )
        proxy = hy2_record("verified-hy2", authority_port, skip_verify=False)
        if wrong_name:
            proxy = proxy.replace("sni: dot.phase4.test", "sni: wrong.hy2.invalid")
        full = prefix + "proxies:\n" + proxy + "rules:\n  - MATCH,verified-hy2\n"
        config = scratch / "config.yaml"
        config.write_text(full if cold else prefix + "rules:\n  - MATCH,DIRECT\n")
        process, stdout, stderr = launch(binary, config, scratch)
        wait_ready(process, mixed_port)
        wait_controller(process, controller_port)
        if not cold:
            config.write_text(full)
            reload_via_controller(process, controller_port, config, secret=SECRET)
        if trusted and not wrong_name:
            result = wait_exchange(process, mixed_port, "127.0.0.1", echo.port, b"verified-tls")
        else:
            assert_authority_reachable(binary, scratch / "control", authority_port, echo.port)
            result = rejected_exchange(mixed_port, "127.0.0.1", echo.port)
        if not result:
            raise AssertionError("verified TLS contract failed")
        return True
    finally:
        if process is not None:
            stop(process)
            stdout.close()
            stderr.close()
        stop(authority)
        a_out.close()
        a_err.close()
        echo.close()


def main():
    observations = {}
    with tempfile.TemporaryDirectory(prefix="phase-hy2a-tls-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root, "PHASE_HY2A_CARGO_TARGET", "phase-hy2a")
        try:
            for engine in ("rust", "go"):
                observations[engine] = {}
                for case, options in (
                    ("trusted", {"trusted": True}),
                    ("wrong-name", {"trusted": True, "wrong_name": True}),
                    ("untrusted", {"trusted": False}),
                ):
                    scratch = root / engine / case
                    scratch.mkdir(parents=True)
                    observations[engine][case] = exercise(
                        binaries[engine], binaries["go"], scratch, **options
                    )
            scratch = root / "rust-cold-start"
            scratch.mkdir()
            observations["rust-cold-start"] = exercise(
                binaries["rust"], binaries["go"], scratch, trusted=True, cold=True
            )
            assert observations["rust"] == observations["go"]
        except Exception as error:
            FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            FAILURE_ARTIFACT.write_text(json.dumps({
                "error": repr(error), "observations": observations, "debug": debug_files(root)
            }, indent=2))
            raise
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("HY2-A verified TLS differential passed")
    print(json.dumps(observations, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

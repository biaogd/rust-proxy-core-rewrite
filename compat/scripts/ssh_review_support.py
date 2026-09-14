"""SSH review regressions against a SHA-2-only, delayed-confirm Go authority."""

import concurrent.futures
import os
import pathlib
import socketserver
import subprocess
import threading
import time

from phase1 import EchoHandler, ROOT, reserve_port, wait_ready
from phase3 import launch, stop


def exercise_review(binaries: dict[str, pathlib.Path], root: pathlib.Path) -> None:
    # Import here because phase6j_ssh_tcp also invokes this helper.
    from phase6j_ssh_tcp import config_validation, exchange, ssh_record, wait_exchange

    authority = root / ("ssh-review-authority.exe" if os.name == "nt" else "ssh-review-authority")
    subprocess.run(
        ["go", "build", "-o", str(authority), "./compat/ssh-review-authority"],
        cwd=ROOT, check=True,
    )
    key = root / "rsa-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", str(key)],
        check=True, capture_output=True,
    )
    encrypted = root / "encrypted-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "phrase", "-f", str(encrypted)],
        check=True, capture_output=True,
    )
    for name, binary in binaries.items():
        scratch = root / f"{name}-review"
        scratch.mkdir()
        marker = scratch / "blocked"
        mixed, port = reserve_port(), reserve_port()
        config = scratch / "config.yaml"
        # Inline material avoids different platform/home path policies.
        pem = "    private-key: |\n" + "".join(f"      {line}\n" for line in key.read_text().splitlines())
        config.write_text(
            f"mixed-port: {mixed}\nipv6: false\nproxies:\n"
            + ssh_record("rsa-ssh", port, password=None, extra=pem)
            + "rules:\n  - MATCH,rsa-ssh\n"
        )
        with (scratch / "authority.log").open("wb") as log:
            server = subprocess.Popen(
                [str(authority), "-listen", f"127.0.0.1:{port}", "-authorized-key",
                 str(key) + ".pub", "-marker", str(marker)], stdout=log, stderr=log,
            )
            process = None
            try:
                wait_ready(server, port)
                with socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler) as echo:
                    thread = threading.Thread(target=echo.serve_forever, daemon=True)
                    thread.start()
                    try:
                        process, stdout, stderr = launch(binary, config, scratch)
                        wait_ready(process, mixed)
                        target = echo.server_address[1]
                        assert wait_exchange(process, mixed, "127.0.0.1", target, b"rsa-sha2-only"), name
                        encrypted_pem = "    private-key: |\n" + "".join(
                            f"      {line}\n" for line in encrypted.read_text().splitlines()
                        )
                        for passphrase, expected in [("phrase", True), ("incorrect", False)]:
                            accepted = config_validation(
                                binary, scratch / f"validate-{passphrase}",
                                "proxies:\n" + ssh_record("encrypted", port, password=None,
                                    extra=encrypted_pem + f"    private-key-passphrase: {passphrase}\n"),
                            )
                            assert accepted == expected, f"{name}: passphrase validation disagrees"

                        def blocked() -> None:
                            try:
                                exchange(mixed, "127.0.0.1", 9, b"blocked", timeout=20)
                            except (OSError, EOFError, AssertionError):
                                pass

                        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                            pending = pool.submit(blocked)
                            try:
                                deadline = time.monotonic() + 5
                                while not marker.exists():
                                    if time.monotonic() >= deadline:
                                        raise AssertionError(f"{name}: stalled channel never reached authority")
                                    time.sleep(0.01)
                                # The authority cannot confirm channel 1 until we release it.
                                # Channel 2 must still complete over the reused session.
                                assert exchange(mixed, "127.0.0.1", target, b"independent-channel", timeout=2), name
                                assert not pending.done(), f"{name}: delayed channel unexpectedly finished"
                            finally:
                                marker.with_name(marker.name + ".release").touch()
                    finally:
                        if process is not None:
                            stop(process)
                            stdout.close()
                            stderr.close()
                            process = None
                        echo.shutdown()
                        thread.join()
            finally:
                if process is not None:
                    stop(process)
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)

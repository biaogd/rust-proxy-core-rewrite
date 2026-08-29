#!/usr/bin/env python3
"""Local Shadowsocks upstream fixtures for Phase 6C differentials."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from phase1 import ROOT, reserve_port
from phase3 import launch, stop

_LISTEN_RE = re.compile(
    r"ShadowSocks\[[^\]]+\] proxy listening at: (?P<addr>[0-9a-fA-F:.]+)"
)


class GoOracleShadowsocksInbound:
    """Run the Go oracle with a sing-shadowsocks AEAD inbound listener."""

    def __init__(
        self,
        password: str,
        *,
        cipher: str = "aes-256-gcm",
        go_binary: Path | None = None,
    ) -> None:
        self.observations: list[dict[str, Any]] = []
        self.password = password
        self.cipher = cipher
        self._scratch = tempfile.TemporaryDirectory(prefix="phase6c-ss-inbound-")
        scratch = Path(self._scratch.name)
        scratch.mkdir(parents=True, exist_ok=True)

        listen_port = reserve_port()
        config = scratch / "config.yaml"
        config.write_text(
            f"""mode: rule
ipv6: false
log-level: info
listeners:
  - name: ss-in
    type: shadowsocks
    listen: 127.0.0.1
    port: {listen_port}
    cipher: {cipher}
    password: {password}
    udp: false
rules:
  - MATCH,DIRECT
"""
        )

        binary = go_binary or _default_go_binary()
        self.process, self._stdout, self._stderr = launch(binary, config, scratch)
        self.address = _wait_listen(scratch / "stdout.log", listen_port)
        self.port = int(self.address.rsplit(":", 1)[-1])

    def close(self) -> None:
        if self.process.poll() is None:
            stop(self.process)
        self._stdout.close()
        self._stderr.close()
        self._scratch.cleanup()


def _default_go_binary() -> Path:
    override = os.environ.get("PHASE6CSS_GO_BINARY")
    if override:
        return Path(override)
    binary = ROOT / "compat" / "artifacts" / "phase6c-go-oracle"
    if not binary.exists():
        binary.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["go", "build", "-trimpath", "-o", str(binary), "."],
            cwd=ROOT,
            check=True,
        )
    return binary


def _wait_listen(log_path: Path, fallback_port: int) -> str:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if log_path.exists():
            for line in log_path.read_text(errors="replace").splitlines():
                match = _LISTEN_RE.search(line)
                if match:
                    return match.group("addr")
        time.sleep(0.02)
    return f"127.0.0.1:{fallback_port}"


ShadowsocksAeadServer = GoOracleShadowsocksInbound

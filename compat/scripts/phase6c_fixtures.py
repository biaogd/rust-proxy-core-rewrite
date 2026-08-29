#!/usr/bin/env python3
"""Local Shadowsocks upstream fixtures for Phase 6C differentials."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from phase1 import reserve_port

ROOT = Path(__file__).resolve().parents[2]


class SsserverFixture:
    """Runs shadowsocks-rust ssserver on an ephemeral port."""

    def __init__(self, password: str, *, cipher: str = "aes-256-gcm") -> None:
        self.observations: list[dict[str, Any]] = []
        self.password = password
        self.cipher = cipher
        self._scratch = tempfile.TemporaryDirectory(prefix="phase6c-ssserver-")
        listen_port = reserve_port()
        config_path = Path(self._scratch.name) / "config.json"
        config_path.write_text(
            json.dumps(
                {
                    "servers": [
                        {
                            "server": "127.0.0.1",
                            "server_port": listen_port,
                            "password": password,
                            "method": cipher,
                        }
                    ],
                }
            )
        )
        ssserver = shutil.which("ssserver")
        if ssserver is None:
            raise RuntimeError("ssserver not found; install shadowsocks-rust locally")
        self.process = subprocess.Popen(
            [ssserver, "-c", str(config_path), "-v"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.address = f"127.0.0.1:{listen_port}"
        self.port = listen_port
        if self.process.poll() is not None:
            raise RuntimeError("ssserver failed to start")

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self._scratch.cleanup()


ShadowsocksAeadServer = SsserverFixture

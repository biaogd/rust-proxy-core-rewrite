#!/usr/bin/env python3
"""Local Shadowsocks/ShadowsocksR upstream fixtures for Phase 6C differentials."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / "compat" / "helpers"
ARTIFACTS = ROOT / "compat" / "artifacts"


class GoFixtureServer:
    """Wraps a Go oracle helper that prints its listen address on stdout."""

    def __init__(self, helper: Path, *args: str) -> None:
        self.observations: list[dict[str, Any]] = []
        self.process = subprocess.Popen(
            [str(helper), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        line = self.process.stdout.readline().strip() if self.process.stdout else ""
        if self.process.stdout:
            self.process.stdout.close()
        if not line or self.process.poll() is not None:
            raise RuntimeError("fixture server failed to start")
        self.address = line
        self.port = int(self.address.rsplit(":", 1)[-1])

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


def _helper(name: str) -> Path:
    suffix = ".exe" if sys.platform == "win32" else ""
    source = HELPERS / name / "main.go"
    if not source.exists():
        raise FileNotFoundError(source)
    binary = ARTIFACTS / f"{name}{suffix}"
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    if not binary.exists() or binary.stat().st_mtime < source.stat().st_mtime:
        subprocess.run(
            ["go", "build", "-trimpath", "-o", str(binary), str(source.parent)],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
    return binary


class ShadowsocksAeadServer(GoFixtureServer):
    def __init__(self, password: str, *, cipher: str = "aes-256-gcm") -> None:
        super().__init__(
            _helper("phase6c-ss-server"),
            "-password",
            password,
            "-cipher",
            cipher,
        )
        self.password = password


class ShadowsocksRServer(GoFixtureServer):
    def __init__(
        self,
        password: str,
        *,
        cipher: str = "aes-256-cfb",
        protocol: str = "origin",
    ) -> None:
        super().__init__(
            _helper("phase6c-ssr-server"),
            "-password",
            password,
            "-cipher",
            cipher,
            "-protocol",
            protocol,
        )
        self.password = password
        self.cipher = cipher
        self.protocol = protocol

"""Hysteria2 build policy; never changes network assertions or timeouts."""

import os
import pathlib

from phase5b1a import build_binaries as build_workspace_binaries


def build_binaries(
    output: pathlib.Path, cargo_target_variable: str, default_target_name: str
) -> dict[str, pathlib.Path]:
    return build_workspace_binaries(
        output,
        cargo_target_variable,
        default_target_name,
        profile=os.environ.get("HY2_BUILD_PROFILE", "debug"),
        stage_runtime=True,
    )

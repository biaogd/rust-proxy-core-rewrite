#!/usr/bin/env python3
"""Go/Rust differential gate for Phase 5A1 configuration input precedence."""

from __future__ import annotations

import base64
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time
from typing import Any

from phase1 import (
    IO_DEADLINE,
    ROOT,
    RUST_ROOT,
    assert_go_oracle_baseline,
    cargo_target_path,
    kill_process,
    reserve_port,
    wait_for_linux_signal_handlers,
)
from phase4 import LocalAuthority, dns_query, udp_query, wait_dns_ready


FAILURE_ARTIFACT = ROOT / "compat" / "artifacts" / "phase5a1-diff.json"
CONTROLLED_ENV = {
    "CLASH_CONFIG_FILE",
    "CLASH_CONFIG_STRING",
    "CLASH_HOME_DIR",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "XDG_CONFIG_HOME",
}
VALID = """mixed-port: 7890
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
"""
INVALID = VALID.replace("mode: rule", "mode: invalid-phase5a1")


def build_binaries(output: pathlib.Path) -> dict[str, pathlib.Path]:
    assert_go_oracle_baseline()
    go_binary = output / "go-oracle"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(go_binary), "."],
        cwd=ROOT,
        check=True,
    )
    target = cargo_target_path("PHASE5A1_CARGO_TARGET", "phase5a1-rust")
    subprocess.run(
        ["cargo", "build", "--workspace", "--target-dir", str(target)],
        cwd=RUST_ROOT,
        check=True,
    )
    return {"go": go_binary, "rust": target / "debug" / "rewrite-core"}


def clean_environment(home: pathlib.Path) -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if key not in CONTROLLED_ENV
    }
    environment["HOME"] = str(home)
    # Go's os.UserHomeDir and Rust's home crate both use USERPROFILE on
    # Windows.  Isolate it alongside HOME so the candidate cannot create the
    # fixture config in the hosted runner account instead of the case root.
    environment["USERPROFILE"] = str(home)
    return environment


def classify_error(output: str) -> str:
    lowered = output.lower()
    if "invalid mode" in lowered:
        return "invalid-mode"
    if "illegal base64" in lowered or "invalid symbol" in lowered:
        return "base64"
    if "no such file" in lowered or "cannot read configuration" in lowered:
        return "missing-file"
    if "yaml" in lowered or "unmarshal" in lowered:
        return "yaml"
    return "other"


def success_path(output: str, case_root: pathlib.Path) -> str | None:
    prefix = "configuration file "
    suffix = " test is successful"
    for line in output.splitlines():
        if line.startswith(prefix) and line.endswith(suffix):
            path = line[len(prefix) : -len(suffix)]
            return path.replace(str(case_root), "<CASE>").replace("\\", "/")
    return None


def run_case(
    binary: pathlib.Path,
    case_root: pathlib.Path,
    *,
    arguments: list[str],
    environment: dict[str, str],
    standard_input: str = "",
) -> dict[str, Any]:
    working = case_root / "work"
    working.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [str(binary), "-t", *arguments],
        cwd=working,
        env=environment,
        input=standard_input,
        text=True,
        capture_output=True,
        timeout=2 * IO_DEADLINE,
    )
    output = result.stdout + result.stderr
    accepted = result.returncode == 0
    return {
        "accepted": accepted,
        "error-class": None if accepted else classify_error(output),
        "path": success_path(output, case_root) if accepted else None,
    }


def runtime_config(proxy_port: int, dns_port: int, upstream_port: int) -> str:
    return f"""mixed-port: {proxy_port}
mode: rule
log-level: info
ipv6: false
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  nameserver:
    - udp://127.0.0.1:{upstream_port}
rules:
  - MATCH,DIRECT
"""


def run_frozen_reload_case(
    binary: pathlib.Path, case_root: pathlib.Path, source: str
) -> dict[str, Any]:
    working = case_root / "work"
    home = case_root / "user"
    working.mkdir(parents=True, exist_ok=True)
    home.mkdir(exist_ok=True)
    selected_port, dns_port = reserve_port(), reserve_port()
    selected_authority, shadow_authority = LocalAuthority(), LocalAuthority()
    selected_yaml = runtime_config(
        selected_port, dns_port, selected_authority.port
    )
    shadow = working / "shadow.yaml"
    shadow.write_text(runtime_config(selected_port, dns_port, shadow_authority.port))
    environment = clean_environment(home)
    command = [str(binary)]
    standard_input: int | None = subprocess.DEVNULL
    if source == "inline":
        command.extend(
            [
                "-config",
                base64.b64encode(selected_yaml.encode()).decode(),
                "-f",
                str(shadow),
            ]
        )
    else:
        command.extend(["-f", "-"])
        standard_input = subprocess.PIPE
        environment["CLASH_CONFIG_FILE"] = str(shadow)

    stdout = (case_root / "stdout.log").open("wb")
    stderr = (case_root / "stderr.log").open("wb")
    process = subprocess.Popen(
        command,
        cwd=working,
        env=environment,
        stdin=standard_input,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    if source == "stdin":
        assert process.stdin is not None
        process.stdin.write(selected_yaml.encode())
        process.stdin.close()
    try:
        wait_dns_ready(process, dns_port)
        udp_query(dns_port, dns_query("frozen.phase5a1.test", 0x7500))
        initial_source = (
            "frozen"
            if selected_authority.state.snapshot()["udp"] == 1
            and shadow_authority.state.snapshot()["udp"] == 0
            else "shadow-file"
        )
        wait_for_linux_signal_handlers(process)
        os.kill(process.pid, signal.SIGHUP)
        deadline = time.monotonic() + IO_DEADLINE
        identifier = 0x7501
        reload_source = "not-observed"
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(f"{source} candidate exited during reload")
            try:
                udp_query(
                    dns_port,
                    dns_query("frozen.phase5a1.test", identifier),
                )
            except (OSError, TimeoutError):
                pass
            selected_count = selected_authority.state.snapshot()["udp"]
            shadow_count = shadow_authority.state.snapshot()["udp"]
            if selected_count >= 2:
                reload_source = "frozen"
                break
            if shadow_count > 0:
                reload_source = "shadow-file"
                break
            identifier = (identifier + 1) & 0xFFFF
            time.sleep(0.02)
        if reload_source == "not-observed":
            raise AssertionError(f"{source} reload did not reset the DNS cache")
        os.kill(process.pid, signal.SIGTERM)
        exit_code = process.wait(timeout=IO_DEADLINE)
        return {
            "initial-source": initial_source,
            "reload-source": reload_source,
            "exit-code": exit_code,
        }
    finally:
        if process.poll() is None:
            kill_process(process)
        stdout.close()
        stderr.close()
        selected_authority.close()
        shadow_authority.close()


def observe(binary: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    observations: dict[str, Any] = {}

    def case(name: str) -> tuple[pathlib.Path, pathlib.Path, dict[str, str]]:
        root = scratch / name
        home = root / "user"
        home.mkdir(parents=True, exist_ok=True)
        return root, home, clean_environment(home)

    root, _, environment = case("relative-file")
    (root / "work" / "configs").mkdir(parents=True)
    (root / "work" / "configs" / "valid.yaml").write_text(VALID)
    observations["relative-file-is-cwd-relative"] = run_case(
        binary,
        root,
        arguments=["-f", "configs/valid.yaml"],
        environment=environment,
    )

    root, _, environment = case("absolute-file")
    selected = root / "selected.yaml"
    selected.write_text(VALID)
    environment["CLASH_CONFIG_FILE"] = str(root / "missing.yaml")
    observations["absolute-cli-file-overrides-env"] = run_case(
        binary,
        root,
        arguments=["-f", str(selected)],
        environment=environment,
    )

    root, _, environment = case("relative-home-flag")
    (root / "work" / "cli-home").mkdir(parents=True)
    (root / "work" / "cli-home" / "config.yaml").write_text(VALID)
    bad_home = root / "bad-home"
    bad_home.mkdir()
    (bad_home / "config.yaml").write_text(INVALID)
    environment["CLASH_HOME_DIR"] = str(bad_home)
    observations["relative-home-flag-overrides-env"] = run_case(
        binary,
        root,
        arguments=["-d", "cli-home"],
        environment=environment,
    )

    root, _, environment = case("relative-home-env")
    (root / "work" / "env-home").mkdir(parents=True)
    (root / "work" / "env-home" / "config.yaml").write_text(VALID)
    environment["CLASH_HOME_DIR"] = "env-home"
    observations["relative-home-env"] = run_case(
        binary, root, arguments=[], environment=environment
    )

    root, home, environment = case("legacy-home")
    legacy = home / ".config" / "mihomo"
    legacy.mkdir(parents=True)
    (legacy / "config.yaml").write_text(VALID)
    xdg = root / "xdg" / "mihomo"
    xdg.mkdir(parents=True)
    (xdg / "config.yaml").write_text(INVALID)
    environment["XDG_CONFIG_HOME"] = str(root / "xdg")
    observations["existing-legacy-home-beats-xdg"] = run_case(
        binary, root, arguments=[], environment=environment
    )

    root, _, environment = case("xdg-fallback")
    xdg = root / "xdg" / "mihomo"
    xdg.mkdir(parents=True)
    (xdg / "config.yaml").write_text(VALID)
    environment["XDG_CONFIG_HOME"] = str(root / "xdg")
    observations["missing-legacy-home-uses-xdg"] = run_case(
        binary, root, arguments=[], environment=environment
    )

    root, _, environment = case("relative-xdg")
    xdg = root / "work" / "xdg" / "mihomo"
    xdg.mkdir(parents=True)
    (xdg / "config.yaml").write_text(VALID)
    environment["XDG_CONFIG_HOME"] = "xdg"
    observations["relative-xdg-remains-relative"] = run_case(
        binary, root, arguments=[], environment=environment
    )

    root, home, environment = case("default-create")
    created_default = home / ".config" / "mihomo" / "config.yaml"
    default_observation = run_case(
        binary, root, arguments=[], environment=environment
    )
    default_observation["created-content"] = created_default.read_text()
    observations["missing-default-is-created"] = default_observation

    root, _, environment = case("explicit-create")
    created_explicit = root / "work" / "created.yaml"
    explicit_observation = run_case(
        binary,
        root,
        arguments=["-f", "created.yaml"],
        environment=environment,
    )
    explicit_observation["created-content"] = created_explicit.read_text()
    observations["missing-explicit-file-is-created"] = explicit_observation

    root, _, environment = case("missing-explicit-parent")
    observations["missing-explicit-parent-is-not-created"] = run_case(
        binary,
        root,
        arguments=["-f", "missing/created.yaml"],
        environment=environment,
    )

    root, _, environment = case("env-file")
    (root / "work" / "env").mkdir(parents=True)
    (root / "work" / "env" / "valid.yaml").write_text(VALID)
    environment["CLASH_CONFIG_FILE"] = "env/valid.yaml"
    observations["config-file-env"] = run_case(
        binary, root, arguments=[], environment=environment
    )

    root, _, environment = case("inline-flag")
    invalid_file = root / "invalid.yaml"
    invalid_file.write_text(INVALID)
    encoded_valid = base64.b64encode(VALID.encode()).decode()
    observations["inline-flag-beats-file-and-stdin"] = run_case(
        binary,
        root,
        arguments=["-config", encoded_valid, "-f", str(invalid_file)],
        environment=environment,
        standard_input=INVALID,
    )

    root, _, environment = case("inline-env")
    invalid_file = root / "invalid.yaml"
    invalid_file.write_text(INVALID)
    environment["CLASH_CONFIG_STRING"] = encoded_valid
    environment["CLASH_CONFIG_FILE"] = str(invalid_file)
    observations["inline-env-beats-file"] = run_case(
        binary, root, arguments=[], environment=environment
    )

    root, _, environment = case("inline-flag-over-env")
    environment["CLASH_CONFIG_STRING"] = base64.b64encode(INVALID.encode()).decode()
    observations["inline-flag-overrides-inline-env"] = run_case(
        binary,
        root,
        arguments=["-config", encoded_valid],
        environment=environment,
    )

    root, _, environment = case("empty-inline-flag")
    selected = root / "selected.yaml"
    selected.write_text(VALID)
    environment["CLASH_CONFIG_STRING"] = base64.b64encode(INVALID.encode()).decode()
    observations["empty-inline-flag-disables-inline-env"] = run_case(
        binary,
        root,
        arguments=["-config", "", "-f", str(selected)],
        environment=environment,
    )

    root, _, environment = case("stdin-flag")
    environment["CLASH_CONFIG_FILE"] = str(root / "missing.yaml")
    observations["stdin-flag-overrides-file-env"] = run_case(
        binary,
        root,
        arguments=["-f", "-"],
        environment=environment,
        standard_input=VALID,
    )

    root, _, environment = case("stdin-env")
    environment["CLASH_CONFIG_FILE"] = "-"
    observations["stdin-env"] = run_case(
        binary,
        root,
        arguments=[],
        environment=environment,
        standard_input=VALID,
    )

    root, _, environment = case("inline-over-stdin")
    observations["inline-beats-stdin"] = run_case(
        binary,
        root,
        arguments=["-config", encoded_valid, "-f", "-"],
        environment=environment,
        standard_input=INVALID,
    )

    root, _, environment = case("empty-inline-bytes")
    (root / "work").mkdir()
    (root / "work" / "config.yaml").write_text(VALID)
    ignored = root / "ignored.yaml"
    ignored.write_text(INVALID)
    observations["empty-decoded-inline-uses-cwd-config-without-init"] = run_case(
        binary,
        root,
        arguments=["-config", "\n", "-f", str(ignored)],
        environment=environment,
    )

    root, _, environment = case("empty-stdin")
    (root / "work").mkdir()
    (root / "work" / "config.yaml").write_text(VALID)
    observations["empty-stdin-uses-cwd-config-without-init"] = run_case(
        binary,
        root,
        arguments=["-f", "-"],
        environment=environment,
        standard_input="",
    )

    root, _, environment = case("empty-stdin-missing")
    missing_empty_observation = run_case(
        binary,
        root,
        arguments=["-f", "-"],
        environment=environment,
        standard_input="",
    )
    missing_empty_observation["created"] = (root / "work" / "config.yaml").exists()
    observations["empty-stdin-does-not-initialize-cwd-config"] = (
        missing_empty_observation
    )

    root, _, environment = case("invalid-base64")
    observations["invalid-base64"] = run_case(
        binary,
        root,
        arguments=["-config", "!not-base64!"],
        environment=environment,
    )

    root, _, environment = case("invalid-inline-yaml")
    observations["invalid-inline-yaml"] = run_case(
        binary,
        root,
        arguments=["-config", base64.b64encode(INVALID.encode()).decode()],
        environment=environment,
    )

    if os.name != "nt":
        root, _, _ = case("runtime-inline-reload")
        observations["runtime-inline-reload-retains-bytes"] = run_frozen_reload_case(
            binary, root, "inline"
        )

        root, _, _ = case("runtime-stdin-reload")
        observations["runtime-stdin-reload-retains-bytes"] = run_frozen_reload_case(
            binary, root, "stdin"
        )

    return observations


def main() -> None:
    FAILURE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-phase5a1-") as temporary:
        root = pathlib.Path(temporary)
        binaries = build_binaries(root)
        observations = {
            name: observe(binary, root / name) for name, binary in binaries.items()
        }
        if observations["go"] != observations["rust"]:
            FAILURE_ARTIFACT.write_text(json.dumps(observations, indent=2, sort_keys=True))
            raise SystemExit(f"Phase 5A1 mismatch; see {FAILURE_ARTIFACT}")
    FAILURE_ARTIFACT.unlink(missing_ok=True)
    print("Phase 5A1 configuration input differential passed")


if __name__ == "__main__":
    main()

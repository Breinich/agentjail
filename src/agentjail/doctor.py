"""``agentjail doctor``: report the host facts the launcher will depend on.

Read-only by construction: it only runs ``podman`` inspection commands and
reads a handful of /proc and /sys files. It never starts containers, never
writes configuration, and never runs with elevated privileges.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import __version__, paths
from .errors import DoctorReport

__all__ = ["SUBPROCESS_TIMEOUT", "collect", "render_human", "render_json"]

SUBPROCESS_TIMEOUT = 10.0


def _run(command: list[str]) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 127, "", ""
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def _podman_format(expression: str) -> str | None:
    code, out, _ = _run(["podman", "info", "--format", expression])
    if code != 0 or not out:
        return None
    return out


def _selinux_state() -> str:
    enforce_file = Path("/sys/fs/selinux/enforce")
    if not enforce_file.is_file():
        return "absent"
    try:
        enforcing = enforce_file.read_text(encoding="ascii").strip() == "1"
    except OSError:
        return "unknown"
    return "enforcing" if enforcing else "permissive"


def _container_hint() -> str | None:
    if Path("/run/.containerenv").exists():
        return "podman"
    if Path("/.dockerenv").exists():
        return "docker"
    if os.environ.get("container"):  # noqa: SIM112 - set by the runtime, lowercase
        return os.environ["container"]  # noqa: SIM112
    return None


def collect(env: Mapping[str, str] | None = None) -> DoctorReport:
    """Gather the report. Never raises for missing tooling."""
    env = os.environ if env is None else env
    report = DoctorReport()

    report.add("agentjail", "version", __version__)
    report.add("agentjail", "python", sys.version.split()[0])
    report.add("agentjail", "platform", platform.platform())

    podman_path = shutil.which("podman")
    if podman_path is None:
        report.add("podman", "binary", "not found")
        report.warn("podman is not installed or not on PATH; nothing can be launched")
        report.ok = False
    else:
        report.add("podman", "binary", podman_path)
        code, out, err = _run(["podman", "--version"])
        report.add("podman", "version", out or err or f"unknown (exit {code})")
        rootless = _podman_format("{{.Host.Security.Rootless}}")
        report.add("podman", "rootless", rootless if rootless is not None else "unknown")
        if rootless == "false":
            report.warn(
                "podman reports rootful mode; agentjail expects rootless podman and will refuse "
                "to launch under root in later increments"
            )
        driver = _podman_format("{{.Store.GraphDriverName}}")
        report.add("podman", "storage_driver", driver if driver is not None else "unknown")
        if driver == "vfs":
            report.warn(
                "vfs storage driver wastes disk and cannot enforce per-container size limits"
            )
        cgroup_manager = _podman_format("{{.Host.CgroupManager}}")
        report.add(
            "podman", "cgroup_manager", cgroup_manager if cgroup_manager is not None else "unknown"
        )
        report.add(
            "podman",
            "cgroup_version",
            "v2" if Path("/sys/fs/cgroup/cgroup.controllers").is_file() else "v1",
        )

    report.add("selinux", "state", _selinux_state())
    report.add(
        "process",
        "euid",
        f"{os.geteuid()} ({'root' if os.geteuid() == 0 else 'unprivileged user'})",
    )
    container = _container_hint()
    if container:
        report.add("process", "running_inside", container)

    for label, directory in (
        ("config_dir", paths.config_dir(env)),
        ("data_dir", paths.data_dir(env)),
        ("state_dir", paths.state_dir(env)),
    ):
        report.add(
            "paths", label, f"{directory} ({'present' if directory.is_dir() else 'missing'})"
        )
    search_dirs = paths.profile_search_dirs(env)
    report.add("paths", "profile_search", ", ".join(str(directory) for directory in search_dirs))
    if not any(directory.is_dir() for directory in search_dirs):
        report.warn(
            "no profile search directory exists yet; profiles/<name>.toml must exist before "
            "`agentjail profile validate` can find a profile by name"
        )

    return report


def render_human(report: DoctorReport) -> str:
    lines: list[str] = []
    for section, entries in report.sections.items():
        lines.append(f"[{section}]")
        width = max(len(key) for key, _ in entries) if entries else 0
        for key, value in entries:
            lines.append(f"  {key.ljust(width)}  {value}")
        lines.append("")
    if report.warnings:
        lines.append("warnings:")
        lines.extend(f"  ! {warning}" for warning in report.warnings)
        lines.append("")
    lines.append("result: " + ("ok" if report.ok else "problems found"))
    return "\n".join(lines)


def render_json(report: DoctorReport) -> str:
    import json

    payload: dict[str, Any] = {
        "ok": report.ok,
        "sections": {section: dict(entries) for section, entries in report.sections.items()},
        "warnings": report.warnings,
    }
    return json.dumps(payload, indent=2, sort_keys=True)

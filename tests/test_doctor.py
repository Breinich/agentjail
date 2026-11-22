"""Doctor: host facts, graceful degradation, and renderers."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from agentjail import doctor
from agentjail.errors import DoctorReport

FAKE_PODMAN = """\
#!/bin/sh
case "$1" in
  --version)
    echo "podman version 9.9.9"
    ;;
  info)
    case "$3" in
      *Rootless*) echo "true" ;;
      *GraphDriverName*) echo "overlay" ;;
      *CgroupManager*) echo "systemd" ;;
      *) echo "unknown" ;;
    esac
    ;;
  *)
    echo "unexpected: $*" >&2
    exit 1
    ;;
esac
"""


@pytest.fixture
def fake_podman(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    binary = tmp_path / "podman"
    binary.write_text(FAKE_PODMAN, encoding="utf-8")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(tmp_path))
    return binary


def test_collect_with_fake_podman(fake_podman: Path) -> None:
    report = doctor.collect(env={"HOME": "/home/example"})
    assert report.ok is True
    sections = {name: dict(entries) for name, entries in report.sections.items()}
    podman = dict(sections["podman"])
    assert podman["version"] == "podman version 9.9.9"
    assert podman["rootless"] == "true"
    assert podman["storage_driver"] == "overlay"
    assert podman["cgroup_manager"] == "systemd"
    assert podman["cgroup_version"] in {"v1", "v2"}
    assert podman["binary"] == str(fake_podman)
    assert "config_dir" in dict(sections["paths"])
    assert dict(sections["agentjail"])["version"] == "0.1.0"


def test_collect_without_podman(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "")
    report = doctor.collect(env={"HOME": "/home/example"})
    assert report.ok is False
    assert dict(report.sections["podman"])["binary"] == "not found"
    assert any("podman is not installed" in warning for warning in report.warnings)


def test_collect_warns_when_rootful(fake_podman: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    script = fake_podman.read_text(encoding="utf-8").replace(
        '*Rootless*) echo "true"', '*Rootless*) echo "false"'
    )
    fake_podman.write_text(script, encoding="utf-8")
    report = doctor.collect(env={"HOME": "/home/example"})
    assert any("rootful mode" in warning for warning in report.warnings)


def test_collect_does_not_fail_when_selinux_is_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor, "_selinux_state", lambda: "absent")
    report = doctor.collect(env={"HOME": "/home/example"})
    assert dict(report.sections["selinux"])["state"] == "absent"


def test_collect_never_raises_for_missing_directories(tmp_path: Path) -> None:
    report = doctor.collect(env={"HOME": str(tmp_path), "XDG_CONFIG_HOME": str(tmp_path / "nyc")})
    paths = dict(report.sections["paths"])
    assert "missing" in paths["config_dir"]


def test_render_json_is_machine_readable() -> None:
    report = DoctorReport()
    report.add("agentjail", "version", "0.1.0")
    report.warn("something to know")
    payload = json.loads(doctor.render_json(report))
    assert payload["ok"] is True
    assert payload["sections"]["agentjail"]["version"] == "0.1.0"
    assert payload["warnings"] == ["something to know"]


def test_render_human_has_sections_and_result() -> None:
    report = DoctorReport()
    report.add("podman", "rootless", "true")
    report.warn("a warning")
    text = doctor.render_human(report)
    assert "[podman]" in text
    assert "rootless" in text
    assert "! a warning" in text
    assert text.rstrip().endswith("result: ok")


def test_selinux_state_is_one_of_the_expected_values() -> None:
    assert doctor._selinux_state() in {"absent", "enforcing", "permissive", "unknown"}

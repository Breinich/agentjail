"""CLI wiring: exit codes, help text contracts, and real vs stubbed commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentjail import cli
from agentjail.errors import DoctorReport
from tests.conftest import MINIMAL_PROFILE


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == "agentjail 0.1.0"


def test_no_command_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main([])
    assert excinfo.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_profile_validate_ok(
    minimal_profile_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["profile", "validate", str(minimal_profile_path)]) == 0
    out = capsys.readouterr().out
    assert f"OK {minimal_profile_path.resolve()}" in out
    assert "no egress" in out


def test_profile_validate_reports_every_error(
    write_profile, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_profile(
        MINIMAL_PROFILE.replace('dns = "none"', 'dns = "none"\nproxy = "http://example"').replace(
            'args = ["-l"]', 'args = ["{nope}"]'
        )
    )
    assert cli.main(["profile", "validate", str(path)]) == 1
    err = capsys.readouterr().err
    assert "is invalid (2 error(s))" in err
    assert "unknown property" in err
    assert "unknown placeholder {nope}" in err


def test_profile_validate_rejects_inline_secret(
    write_profile, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_profile(
        MINIMAL_PROFILE
        + '\n[[secrets]]\nsource = "env"\nref = "EXAMPLE_TOKEN"\n'
        + 'target = "EXAMPLE_TOKEN"\nvalue = "fake-value-not-real"\n'
    )
    assert cli.main(["profile", "validate", str(path)]) == 1
    err = capsys.readouterr().err
    assert "inline secret material is not allowed" in err


def test_profile_not_found_lists_search_paths(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["profile", "validate", "definitely-missing"]) == 1
    err = capsys.readouterr().err
    assert "not found" in err
    assert "definitely-missing.toml" in err


def test_profile_dir_is_searched_first(
    tmp_path: Path, minimal_profile_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir()
    (profile_dir / "named.toml").write_text(MINIMAL_PROFILE, encoding="utf-8")
    assert cli.main(["--profile-dir", str(profile_dir), "profile", "validate", "named"]) == 0
    assert "named.toml" in capsys.readouterr().out


def test_profile_show_prints_resolved_defaults(
    allowlist_profile_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["profile", "show", str(allowlist_profile_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "allowlist"
    assert payload["source"] == str(allowlist_profile_path.resolve())
    profile = payload["profile"]
    assert profile["mounts"][0]["read_only"] is True
    assert profile["network"]["egress"][0]["protocol"] == "tls"
    assert profile["secrets"][0]["delivery"] == "env"
    assert profile["resources"]["nofile"] == 1024
    # references only, never values
    assert profile["secrets"][0]["ref"] == "EXAMPLE_FORGE_TOKEN"
    assert "value" not in profile["secrets"][0]


def test_run_is_stubbed_with_exit_code_3(
    minimal_profile_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["run", str(minimal_profile_path), "--", "my-agent", "--version"]) == 3
    err = capsys.readouterr().err
    assert "not implemented in this increment" in err
    assert "would exec my-agent --version" in err
    assert "pipes not TTY" in err
    assert "docs/cli.md" in err


def test_run_uses_profile_agent_when_no_command(
    minimal_profile_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["run", str(minimal_profile_path)]) == 3
    assert "would exec bash -l" in capsys.readouterr().err


@pytest.mark.parametrize("position", ["before", "after"])
def test_run_no_secrets_is_expressible(
    allowlist_profile_path: Path, capsys: pytest.CaptureFixture[str], position: str
) -> None:
    argv = (
        ["run", "--no-secrets", str(allowlist_profile_path)]
        if position == "before"
        else ["run", str(allowlist_profile_path), "--no-secrets"]
    )
    assert cli.main(argv) == 3
    err = capsys.readouterr().err
    assert "all secrets suppressed (--no-secrets)" in err
    assert "1 secret reference(s) would be injected" not in err


def test_run_validates_before_reporting_not_implemented(
    write_profile, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_profile(
        MINIMAL_PROFILE.replace('home = "/home/agent"', 'home = "/home/agent"\nbogus = 1')
    )
    assert cli.main(["run", str(path)]) == 1
    assert "unknown property" in capsys.readouterr().err


def test_selftest_is_stubbed_with_exit_code_3(
    minimal_profile_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["selftest", str(minimal_profile_path)]) == 3
    err = capsys.readouterr().err
    assert "not implemented in this increment" in err
    assert "host secrets unreadable" in err
    assert "positive control" in err


def test_run_help_documents_the_launcher_contract(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["run", "--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "stdin and stdout are a pair of pipes" in out.replace("\n", " ").replace("    ", " ")
    assert "SIGINT, SIGTERM and SIGQUIT" in out
    assert "128 + signal number" in out
    assert "no jail is orphaned" in out


def test_selftest_help_documents_the_negative_set(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["selftest", "--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "no podman/docker socket" in out
    assert "two concurrent jails" in out
    assert "writable-layer size" in out


def test_doctor_uses_report_and_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    report = DoctorReport()
    report.add("podman", "version", "podman version 9.9.9")
    report.add("podman", "rootless", "true")
    monkeypatch.setattr(cli.doctor, "collect", lambda: report)
    assert cli.main(["doctor", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["sections"]["podman"]["rootless"] == "true"


def test_doctor_exits_non_zero_when_podman_is_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PATH", "")
    assert cli.main(["doctor", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert any("podman" in warning for warning in payload["warnings"])


def test_unknown_subcommand_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["frobnicate"])
    assert excinfo.value.code == 2


def test_launcher_contract_mentions_every_required_property() -> None:
    contract = cli.LAUNCHER_CONTRACT
    for needle in (
        "pipes",
        "stderr",
        "SIGINT",
        "SIGTERM",
        "SIGQUIT",
        "resize",
        "exit code",
        "orphan",
    ):
        assert needle in contract

"""Containerfile checks: parsing plus the policy rules the build must satisfy."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "check_containerfile.py"


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_containerfile", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def checker() -> ModuleType:
    return load_script()


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_repository_containerfile_passes(checker: ModuleType) -> None:
    assert checker.check(REPO_ROOT / "images" / "base" / "Containerfile") == []


def test_discover_finds_containerfiles(checker: ModuleType) -> None:
    found = checker.discover(REPO_ROOT / "images")
    assert REPO_ROOT / "images" / "base" / "Containerfile" in found


def test_repository_containerfile_pins_the_base_by_digest() -> None:
    text = (REPO_ROOT / "images" / "base" / "Containerfile").read_text(encoding="utf-8")
    from_lines = [line for line in text.splitlines() if line.startswith("FROM ")]
    assert from_lines, "expected at least one FROM"
    for line in from_lines:
        assert "@sha256:" in line


def test_unpinned_from_is_rejected(checker: ModuleType, tmp_path: Path) -> None:
    path = write(
        tmp_path / "Containerfile",
        'FROM node:24-bookworm-slim\nUSER 1000\nCMD ["bash"]\n',
    )
    problems = checker.check(path)
    assert any("not pinned by digest" in problem for problem in problems)


def test_root_user_in_final_stage_is_rejected(checker: ModuleType, tmp_path: Path) -> None:
    path = write(
        tmp_path / "Containerfile",
        "FROM debian@sha256:" + "a" * 64 + '\nUSER root\nCMD ["bash"]\n',
    )
    assert any("runs as root" in problem for problem in checker.check(path))


def test_missing_user_is_rejected(checker: ModuleType, tmp_path: Path) -> None:
    path = write(
        tmp_path / "Containerfile",
        "FROM debian@sha256:" + "a" * 64 + '\nCMD ["bash"]\n',
    )
    assert any("never sets USER" in problem for problem in checker.check(path))


def test_missing_entrypoint_is_rejected(checker: ModuleType, tmp_path: Path) -> None:
    path = write(
        tmp_path / "Containerfile",
        "FROM debian@sha256:" + "a" * 64 + "\nUSER 1000\nRUN true\n",
    )
    assert any("no ENTRYPOINT or CMD" in problem for problem in checker.check(path))


def test_credential_like_env_is_rejected(checker: ModuleType, tmp_path: Path) -> None:
    path = write(
        tmp_path / "Containerfile",
        "FROM debian@sha256:" + "a" * 64 + '\nENV GITHUB_TOKEN=abc\nUSER 1000\nCMD ["bash"]\n',
    )
    assert any("credential-like name" in problem for problem in checker.check(path))


def test_add_from_url_is_rejected(checker: ModuleType, tmp_path: Path) -> None:
    path = write(
        tmp_path / "Containerfile",
        "FROM debian@sha256:"
        + "a" * 64
        + '\nADD https://example.com/x /x\nUSER 1000\nCMD ["bash"]\n',
    )
    assert any("ADD from a URL" in problem for problem in checker.check(path))


def test_unknown_instruction_is_rejected(checker: ModuleType, tmp_path: Path) -> None:
    path = write(
        tmp_path / "Containerfile",
        "FROM debian@sha256:" + "a" * 64 + '\nBOGUS thing\nUSER 1000\nCMD ["bash"]\n',
    )
    assert any("not a Dockerfile instruction" in problem for problem in checker.check(path))


def test_multistage_only_final_stage_needs_user(checker: ModuleType, tmp_path: Path) -> None:
    path = write(
        tmp_path / "Containerfile",
        "\n".join(
            [
                "FROM debian@sha256:" + "a" * 64 + " AS builder",
                "RUN make",
                "FROM debian@sha256:" + "b" * 64,
                "COPY --from=builder /out /out",
                "USER 1000",
                'CMD ["/out/thing"]',
            ]
        )
        + "\n",
    )
    assert checker.check(path) == []


def test_line_continuations_are_joined(checker: ModuleType, tmp_path: Path) -> None:
    path = write(
        tmp_path / "Containerfile",
        "FROM debian@sha256:" + "a" * 64 + "\n"
        "RUN apt-get update \\\n"
        " && apt-get install -y curl \\\n"
        " && rm -rf /var/lib/apt/lists/*\n"
        "USER 1000\n"
        'CMD ["bash"]\n',
    )
    assert checker.check(path) == []


def test_cli_exit_codes(
    checker: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    good = write(
        tmp_path / "Containerfile",
        "FROM debian@sha256:" + "a" * 64 + '\nUSER 1000\nCMD ["bash"]\n',
    )
    assert checker.main([str(good)]) == 0
    assert "OK" in capsys.readouterr().out

    bad = write(tmp_path / "BadContainerfile", "FROM debian:latest\n")
    assert checker.main([str(bad)]) == 1
    assert "problem(s)" in capsys.readouterr().err

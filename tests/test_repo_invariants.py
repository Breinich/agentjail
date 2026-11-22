"""Repository invariants: schema copies, example profiles, docs, and neutrality.

These tests are what stop the scaffolding from drifting: the shipped schema copy
must match the canonical one, every example profile must validate, documented
paths must exist, and the product must stay free of harness-specific terms.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentjail.profile import load_profile_document, profile_schema
from agentjail.schema import SchemaValidator

REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_SCHEMA = REPO_ROOT / "schema" / "profile.schema.json"
PACKAGED_SCHEMA = REPO_ROOT / "src" / "agentjail" / "data" / "profile.schema.json"


def test_canonical_schema_exists_and_is_json() -> None:
    document = json.loads(CANONICAL_SCHEMA.read_text(encoding="utf-8"))
    assert document["type"] == "object"
    assert document["properties"]["version"]["const"] == 1


def test_packaged_schema_is_identical_to_canonical() -> None:
    assert PACKAGED_SCHEMA.is_file(), "run scripts/sync_schema.py"
    assert PACKAGED_SCHEMA.read_bytes() == CANONICAL_SCHEMA.read_bytes()


def test_schema_uses_only_supported_keywords() -> None:
    # Constructing the validator checks every keyword in the document.
    SchemaValidator(json.loads(CANONICAL_SCHEMA.read_text(encoding="utf-8")))


def test_schema_covers_every_required_area() -> None:
    document = json.loads(CANONICAL_SCHEMA.read_text(encoding="utf-8"))
    properties = document["properties"]
    for field in (
        "version",
        "image",
        "workdir",
        "home",
        "mounts",
        "env",
        "secrets",
        "network",
        "resources",
        "agent",
    ):
        assert field in properties, field
    assert set(document["required"]) >= {"version", "image", "workdir", "home", "network", "agent"}

    defs = document["$defs"]
    assert set(defs["image"]["required"]) == {"name", "digest"}
    assert set(defs["mount"]["required"]) == {"source", "target"}
    assert set(defs["secret"]["required"]) == {"source", "ref", "target"}
    assert defs["secret"]["additionalProperties"] is False
    assert set(defs["network"]["required"]) == {"mode", "dns"}
    assert defs["network"]["properties"]["mode"]["enum"] == ["none", "allowlist"]
    assert set(defs["egress"]["required"]) == {"host", "port"}
    assert "disk" in defs["resources"]["properties"]
    assert "tmpfs" in defs["resources"]["properties"]
    assert set(defs["agent"]["required"]) == {"command"}


def test_schema_profile_flag_default_is_no_egress() -> None:
    document = json.loads(CANONICAL_SCHEMA.read_text(encoding="utf-8"))
    egress = document["$defs"]["network"]["properties"]["egress"]
    assert egress["default"] == []


def test_profile_schema_loads_from_the_expected_location() -> None:
    document = profile_schema()
    assert document["$id"].endswith("schema/profile.schema.json")


@pytest.mark.parametrize("profile_path", sorted((REPO_ROOT / "profiles").glob("*.toml")))
def test_example_profiles_validate(profile_path: Path) -> None:
    profile = load_profile_document(profile_path)
    assert profile.document["image"]["digest"].startswith("sha256:")
    assert len(profile.document["image"]["digest"]) == len("sha256:") + 64


def test_example_profiles_cover_both_network_modes() -> None:
    modes = {
        load_profile_document(path).document["network"]["mode"]
        for path in (REPO_ROOT / "profiles").glob("*.toml")
    }
    assert {"none", "allowlist"} <= modes


@pytest.mark.parametrize(
    "relative_path",
    [
        "README.md",
        "docs/threat-model.md",
        "docs/profiles.md",
        "docs/adopting.md",
        "docs/cli.md",
        "images/README.md",
        "images/base/Containerfile",
        "images/base/entrypoint.sh",
        "schema/profile.schema.json",
        "profiles/minimal.toml",
        "profiles/allowlist.toml",
    ],
)
def test_documented_paths_exist(relative_path: str) -> None:
    assert (REPO_ROOT / relative_path).is_file(), relative_path


def test_readme_links_to_the_required_documents() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    for link in ("docs/threat-model.md", "docs/profiles.md", "docs/adopting.md"):
        assert link in readme, link


def test_product_sources_are_agent_and_harness_neutral() -> None:
    forbidden = ("ORCA_", "orca_session", "orca orchestration", "homelab", "bunkerweb")
    offenders: list[str] = []
    for path in sorted((REPO_ROOT / "src").rglob("*")):
        if path.is_file() and path.suffix in {".py", ".json"}:
            text = path.read_text(encoding="utf-8")
            for needle in forbidden:
                if needle in text:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {needle}")
    assert offenders == []


def test_example_profiles_are_agent_neutral() -> None:
    # Examples may mention any agent in a comment, but the actual command must
    # be a generic shell command, not a harness-specific invocation.
    for path in (REPO_ROOT / "profiles").glob("*.toml"):
        profile = load_profile_document(path).document
        assert profile["agent"]["command"] in {"bash", "sh"}


def test_no_real_credentials_in_repository() -> None:
    suspicious = ("ghp_", "github_pat_", "sk-ant-", "AKIA", "BEGIN OPENSSH PRIVATE KEY")
    offenders: list[str] = []
    for path in sorted(REPO_ROOT.rglob("*")):
        if not path.is_file() or ".git" in path.parts or ".venv" in path.parts:
            continue
        relative = path.relative_to(REPO_ROOT)
        if relative.parts[0] == "tests":
            continue
        if path.suffix not in {
            ".md",
            ".py",
            ".toml",
            ".json",
            ".yml",
            ".yaml",
            ".sh",
            "Containerfile",
            "",
        }:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for needle in suspicious:
            if needle in text:
                offenders.append(f"{relative}: {needle}")
    assert offenders == []


def test_sync_schema_check_passes() -> None:
    completed = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "sync_schema.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr

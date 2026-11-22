"""Shared fixtures: tiny, hermetic profile documents.

Every fixture writes to ``tmp_path`` so tests never depend on the repository
cwd or on the user's config directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FAKE_DIGEST = "sha256:" + "0" * 64

MINIMAL_PROFILE = f"""\
version = 1
description = "offline jail"

workdir = "/work"
home = "/home/agent"

[image]
name = "localhost/agentjail-base:1"
digest = "{FAKE_DIGEST}"

[network]
mode = "none"
dns = "none"

[agent]
command = "bash"
args = ["-l"]
"""

ALLOWLIST_PROFILE = f"""\
version = 1

workdir = "/work"
home = "/home/agent"

[image]
name = "localhost/agentjail-base:1"
digest = "{FAKE_DIGEST}"

[network]
mode = "allowlist"
dns = "gateway"

[[network.egress]]
host = "api.example.com"
port = 443

[[mounts]]
source = "/srv/src/project"
target = "/work/project"
read_only = true

[[secrets]]
name = "forge_token"
source = "env"
ref = "EXAMPLE_FORGE_TOKEN"
target = "EXAMPLE_FORGE_TOKEN"

[resources]
cpus = 2
memory = "2g"
pids = 512

[resources.tmpfs]
"/tmp" = "64m"

[agent]
command = "bash"
args = ["-lc", "true"]
"""


@pytest.fixture
def write_profile(tmp_path: Path):
    """Return a helper that writes a profile file and returns its path."""

    def _write(text: str, name: str = "test-profile.toml") -> Path:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path

    return _write


@pytest.fixture
def minimal_profile_path(write_profile) -> Path:
    return write_profile(MINIMAL_PROFILE, "minimal.toml")


@pytest.fixture
def allowlist_profile_path(write_profile) -> Path:
    return write_profile(ALLOWLIST_PROFILE, "allowlist.toml")

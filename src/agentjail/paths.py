"""Locations agentjail reads from or writes to.

Everything is derived from the XDG base directory specification, with explicit
environment overrides for tests and for unusual deployments. Nothing here
touches the filesystem, so it is safe to import anywhere.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

APP_NAME = "agentjail"

#: Environment variable that prepends an extra profile search directory.
PROFILE_DIR_ENV = "AGENTJAIL_PROFILE_DIR"
CONFIG_DIR_ENV = "AGENTJAIL_CONFIG_DIR"
DATA_DIR_ENV = "AGENTJAIL_DATA_DIR"
STATE_DIR_ENV = "AGENTJAIL_STATE_DIR"


def _home(env: Mapping[str, str]) -> Path:
    return Path(env.get("HOME") or Path.home())


def config_dir(env: Mapping[str, str] | None = None) -> Path:
    """Directory for user configuration, including profiles."""
    env = os.environ if env is None else env
    override = env.get(CONFIG_DIR_ENV)
    if override:
        return Path(override).expanduser()
    base = env.get("XDG_CONFIG_HOME") or str(_home(env) / ".config")
    return Path(base).expanduser() / APP_NAME


def data_dir(env: Mapping[str, str] | None = None) -> Path:
    """Directory for persistent data (images, build cache references)."""
    env = os.environ if env is None else env
    override = env.get(DATA_DIR_ENV)
    if override:
        return Path(override).expanduser()
    base = env.get("XDG_DATA_HOME") or str(_home(env) / ".local" / "share")
    return Path(base).expanduser() / APP_NAME


def state_dir(env: Mapping[str, str] | None = None) -> Path:
    """Directory for transient jail state (container names, pid files)."""
    env = os.environ if env is None else env
    override = env.get(STATE_DIR_ENV)
    if override:
        return Path(override).expanduser()
    base = env.get("XDG_STATE_HOME") or str(_home(env) / ".local" / "state")
    return Path(base).expanduser() / APP_NAME


def profile_search_dirs(
    env: Mapping[str, str] | None = None, *, cwd: Path | None = None
) -> list[Path]:
    """Ordered directories searched for ``<name>.toml`` profiles.

    ``AGENTJAIL_PROFILE_DIR`` wins, then ``./profiles`` (so a project can pin
    jails next to its code), then the user config directory.
    """
    env = os.environ if env is None else env
    cwd = Path.cwd() if cwd is None else cwd
    dirs: list[Path] = []
    override = env.get(PROFILE_DIR_ENV)
    if override:
        dirs.append(Path(override).expanduser())
    dirs.append(cwd / "profiles")
    dirs.append(config_dir(env) / "profiles")
    return dirs

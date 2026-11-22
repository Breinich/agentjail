"""Loading, normalising, and validating agentjail profiles.

A profile is a TOML document validated against ``schema/profile.schema.json``
(JSON Schema) and then against a small set of semantic rules that JSON Schema
cannot express well: unique jail paths, secret delivery targets that actually
exist, FUSE-backed mount sources that crun cannot bind, and so on.

Validation is the one behaviour that genuinely works in increment 1.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import paths
from .errors import ProfileError, ValidationFailed
from .schema import SchemaDefinitionError, SchemaValidator

__all__ = [
    "PROFILE_SUFFIX",
    "Profile",
    "load_profile",
    "load_profile_document",
    "profile_schema",
    "validate_profile_document",
]

PROFILE_SUFFIX = ".toml"

#: Keys that would smuggle an actual credential into a profile.
_INLINE_SECRET_KEYS = (
    "value",
    "values",
    "inline",
    "literal",
    "plaintext",
    "content",
    "contents",
    "data",
)

#: Environment variable names that look like credentials.
_SECRETISH_ENV = re.compile(
    r"(^|_)(PASS|PASSWD|PASSWORD|SECRET|SECRETS|TOKEN|TOKENS|APIKEY|API_KEY|"
    r"PRIVATE_KEY|ACCESS_KEY|SECRET_KEY|CREDENTIAL|CREDENTIALS|AUTH|BEARER)($|_)",
    re.IGNORECASE,
)

#: FUSE-backed mount sources: AppImage runtime mounts, gvfs, gio document
#: portals, sshfs/fuse mounts. crun fails on these with
#: ``cannot stat self/fd/N: Permission denied``.
_FUSE_PATH = re.compile(
    r"(^/tmp/\.mount_[A-Za-z0-9]+(/|$))"
    r"|(^/run/user/[0-9]+/(gvfs|doc)(/|$))"
    r"|(^/run/user/[0-9]+/\.?gvfsd-fuse)"
    r"|(\.AppImage$)"
    r"|(^/(dev|proc)/fuse)"
)

_ARG_PLACEHOLDERS = frozenset({"workdir", "home"})
_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")

_SIZE_LIMIT = re.compile(r"^[0-9]+[kKmMgG]?$")

#: Defaults applied to a profile after it has validated.
DEFAULT_RESOURCES: dict[str, Any] = {
    "cpus": 1,
    "memory": "1g",
    "pids": 256,
    "nofile": 1024,
    "tmpfs": {},
}


@dataclass(frozen=True)
class Profile:
    """A validated profile plus the defaults resolved for it."""

    name: str
    path: Path
    document: dict[str, Any]

    @property
    def image(self) -> str:
        image = self.document["image"]
        return f"{image['name']}@{image['digest']}"

    @property
    def mount_targets(self) -> list[str]:
        return [mount["target"] for mount in self.document["mounts"]]

    @property
    def secret_count(self) -> int:
        return len(self.document["secrets"])

    @property
    def egress(self) -> list[dict[str, Any]]:
        return list(self.document["network"]["egress"])

    def summary(self) -> str:
        network = self.document["network"]
        if network["mode"] == "none":
            egress = "no egress"
        else:
            egress = f"{len(network['egress'])} allowlisted destination(s), dns={network['dns']}"
        return (
            f"{len(self.document['mounts'])} mount(s), {self.secret_count} secret reference(s), "
            f"{egress}"
        )


# --------------------------------------------------------------------------
# Schema location
# --------------------------------------------------------------------------


def _schema_candidates() -> Iterable[Path]:
    override = os.environ.get("AGENTJAIL_SCHEMA")
    if override:
        yield Path(override).expanduser()
    yield _package_data_schema()
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "schema" / "profile.schema.json"
        if candidate.is_file():
            yield candidate
    yield Path("/usr/share/agentjail/profile.schema.json")


def _package_data_schema() -> Path:
    return Path(__file__).resolve().parent / "data" / "profile.schema.json"


def profile_schema() -> dict[str, Any]:
    """Load the machine-readable profile schema.

    ``schema/profile.schema.json`` in the repository is authoritative; the copy
    under ``src/agentjail/data/`` is what an installed wheel ships.
    ``scripts/sync_schema.py --check`` (run in CI) keeps them identical.
    """
    tried: list[str] = []
    for candidate in _schema_candidates():
        tried.append(str(candidate))
        if not candidate.is_file():
            continue
        try:
            with candidate.open("rb") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ProfileError(f"cannot read profile schema {candidate}: {exc}") from exc
    raise ProfileError(
        "profile schema not found; searched:\n" + "\n".join(f"  - {p}" for p in tried)
    )


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def load_profile(ref: str, *, search_dirs: Iterable[Path] | None = None) -> Profile:
    """Resolve ``ref`` to a profile file and validate it."""
    path = resolve_profile_path(ref, search_dirs=search_dirs)
    return load_profile_document(path)


def resolve_profile_path(ref: str, *, search_dirs: Iterable[Path] | None = None) -> Path:
    """Find a profile file.

    ``ref`` may be an explicit path (it contains a separator or ends in
    ``.toml``) or a bare profile name looked up in the search directories.
    """
    candidate = Path(ref).expanduser()
    looks_like_path = "/" in ref or ref.endswith(PROFILE_SUFFIX)
    if looks_like_path:
        if candidate.is_file():
            return candidate.resolve()
        raise ProfileError(f"profile not found: {candidate} (no such file)")

    dirs = list(paths.profile_search_dirs() if search_dirs is None else search_dirs)
    for directory in dirs:
        candidate = directory / f"{ref}{PROFILE_SUFFIX}"
        if candidate.is_file():
            return candidate.resolve()
    searched = "\n".join(f"  - {directory / (ref + PROFILE_SUFFIX)}" for directory in dirs)
    raise ProfileError(f"profile {ref!r} not found; searched:\n{searched}")


def load_profile_document(path: Path) -> Profile:
    """Read, parse, validate, and normalise a profile file."""
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise ProfileError(f"cannot read profile {path}: {exc}") from exc
    try:
        document = tomllib.loads(raw_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ProfileError(f"profile {path} is not valid UTF-8: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ProfileError(f"profile {path} is not valid TOML: {exc}") from exc

    validate_profile_document(document, source=str(path))
    return Profile(name=path.stem, path=path, document=normalise_profile_document(document))


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def validate_profile_document(document: Mapping[str, Any], *, source: str = "<profile>") -> None:
    """Validate a parsed profile document.

    Raises :class:`ValidationFailed` with every error found, so a user fixes
    one round of problems rather than one problem per run.
    """
    errors: list[str] = []
    errors.extend(_reject_inline_secrets(document))
    errors.extend(_schema_errors(document))
    # Semantic rules are defensive about shapes, so they add their more
    # specific messages even when the schema also complained. Users get one
    # complete list rather than a round trip per problem.
    errors.extend(_semantic_errors(document))
    if errors:
        raise ValidationFailed(
            f"profile {source} is invalid ({len(errors)} error(s)):", errors=errors
        )


def _schema_errors(document: Mapping[str, Any]) -> list[str]:
    try:
        validator = SchemaValidator(profile_schema())
    except SchemaDefinitionError as exc:
        raise ProfileError(f"profile schema is unusable: {exc}") from exc
    return validator.errors(dict(document))


def _reject_inline_secrets(document: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    secrets = document.get("secrets")
    if not isinstance(secrets, list):
        return errors
    for index, entry in enumerate(secrets):
        if not isinstance(entry, dict):
            continue
        for key in _INLINE_SECRET_KEYS:
            if key in entry:
                label = entry.get("name") or entry.get("target") or f"secrets[{index}]"
                errors.append(
                    f"secrets[{index}] ({label}): inline secret material is not allowed "
                    f'(found {key!r}); use source = "env" | "file" | "store" plus a '
                    f"ref that names where the secret already lives"
                )
    return errors


def _semantic_errors(document: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    resources = _mapping(document.get("resources"))
    tmpfs = _mapping(resources.get("tmpfs"))
    network = _mapping(document.get("network"))

    workdir = document.get("workdir")
    home = document.get("home")
    for field, value in (("workdir", workdir), ("home", home)):
        if value == "/":
            errors.append(f"{field}: must not be the jail root '/'; pick a dedicated directory")
    if workdir == home and workdir is not None:
        errors.append("workdir and home must differ")

    errors.extend(_mount_errors(document, home=home))
    errors.extend(_env_errors(document))
    errors.extend(_secret_errors(document, tmpfs=tmpfs))
    errors.extend(_network_errors(network))
    errors.extend(_resource_errors(resources))
    errors.extend(_agent_errors(document))
    return errors


def _mount_errors(document: Mapping[str, Any], *, home: Any) -> list[str]:
    errors: list[str] = []
    mounts = document.get("mounts") or []
    if not isinstance(mounts, list):
        return errors
    seen: dict[str, int] = {}
    for index, mount in enumerate(mounts):
        if not isinstance(mount, dict):
            continue
        target = mount.get("target")
        source = mount.get("source")
        if isinstance(target, str):
            if target in seen:
                errors.append(
                    f"mounts[{index}].target: {target!r} already mounted by mounts[{seen[target]}]"
                )
            else:
                seen[target] = index
            if target in {"/", "/proc", "/sys", "/dev", "/run"}:
                errors.append(
                    f"mounts[{index}].target: refusing to mount over {target!r}; it is part of "
                    f"the jail's own runtime surface"
                )
            if isinstance(home, str) and target == home:
                errors.append(f"mounts[{index}].target: {home!r} is the jail home; mount elsewhere")
        if isinstance(source, str) and _FUSE_PATH.search(source):
            remedy = (
                "copy the runtime into the image (images/base/Containerfile) or into a directory "
                "that is itself a normal bind mount, e.g. under {workdir}/.tools"
            )
            if source.endswith(".AppImage"):
                errors.append(
                    f"mounts[{index}].source: {source!r} is an AppImage; FUSE-backed paths cannot be "
                    f"bind-mounted into the jail (crun: cannot stat self/fd/N: Permission denied). "
                    f"{remedy}"
                )
            else:
                errors.append(
                    f"mounts[{index}].source: {source!r} is a FUSE-backed path; FUSE-backed paths "
                    f"cannot be bind-mounted into the jail (crun: cannot stat self/fd/N: Permission "
                    f"denied). {remedy}"
                )
    return errors


def _env_errors(document: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    env = document.get("env") or {}
    if not isinstance(env, dict):
        return errors
    for name, value in env.items():
        if _SECRETISH_ENV.search(name):
            errors.append(
                f"env.{name}: names that look like credentials are rejected; declare it under "
                f"[[secrets]] with a reference instead of a literal value"
            )
        # Heuristic safety net only; it must stay quiet for ordinary values
        # such as a path or a locale.
        if (
            isinstance(value, str)
            and re.fullmatch(r"[A-Za-z0-9_\-]{32,}", value)
            and any(char.isdigit() for char in value)
            and any(char.isalpha() for char in value)
        ):
            errors.append(
                f"env.{name}: value looks like a credential (long unbroken token); secrets must "
                f"be injected by reference, not written into a profile"
            )
    return errors


def _secret_errors(document: Mapping[str, Any], *, tmpfs: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    secrets = document.get("secrets") or []
    if not isinstance(secrets, list):
        return errors
    tmpfs_paths = [path for path in tmpfs if isinstance(path, str)]
    seen_targets: dict[str, int] = {}
    for index, secret in enumerate(secrets):
        if not isinstance(secret, dict):
            continue
        source = secret.get("source")
        ref = secret.get("ref")
        delivery = secret.get("delivery", "env")
        target = secret.get("target")

        if isinstance(target, str):
            if target in seen_targets:
                errors.append(
                    f"secrets[{index}].target: {target!r} already used by secrets[{seen_targets[target]}]"
                )
            else:
                seen_targets[target] = index

        if source == "env":
            if isinstance(ref, str) and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", ref):
                errors.append(
                    f"secrets[{index}].ref: {ref!r} is not a valid environment variable name"
                )
        elif source == "file":
            if isinstance(ref, str) and not ref.startswith("/"):
                errors.append(f"secrets[{index}].ref: host file reference must be an absolute path")
            if isinstance(ref, str) and _FUSE_PATH.search(ref):
                errors.append(
                    f"secrets[{index}].ref: {ref!r} is FUSE-backed and cannot be read reliably; "
                    f"stage it on a normal filesystem first"
                )
        elif (
            source == "store"
            and isinstance(ref, str)
            and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", ref)
        ):
            errors.append(
                f"secrets[{index}].ref: {ref!r} is not a valid credential-store reference"
            )

        if delivery == "file":
            if not isinstance(target, str) or not target.startswith("/"):
                errors.append(f"secrets[{index}].target: file delivery needs an absolute path")
            elif not any(
                target == path or target.startswith(path.rstrip("/") + "/") for path in tmpfs_paths
            ):
                declared = ", ".join(sorted(tmpfs_paths)) or "none"
                errors.append(
                    f"secrets[{index}].target: {target!r} is not inside a declared tmpfs "
                    f"(resources.tmpfs: {declared}); secret files must never touch a bind mount or "
                    f"the image filesystem"
                )
        elif "mode" in secret:
            errors.append(
                f'secrets[{index}].mode: only valid with delivery = "file"; environment delivery '
                f"has no file mode"
            )
    return errors


def _network_errors(network: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    egress = network.get("egress") or []
    if not isinstance(egress, list):
        return errors
    seen: dict[tuple[Any, Any, Any], int] = {}
    for index, entry in enumerate(egress):
        if not isinstance(entry, dict):
            continue
        host = entry.get("host")
        port = entry.get("port")
        protocol = entry.get("protocol", "tls")
        key = (host, port, protocol)
        if key in seen:
            errors.append(
                f"network.egress[{index}]: duplicate of network.egress[{seen[key]}] "
                f"({host}:{port}/{protocol})"
            )
        else:
            seen[key] = index
        if isinstance(host, str):
            if "*" in host:
                errors.append(
                    f"network.egress[{index}].host: wildcards are not allowed; list each "
                    f"destination explicitly"
                )
            if ":" in host or "/" in host:
                errors.append(
                    f"network.egress[{index}].host: give a bare DNS name; schemes, paths, and "
                    f"ports belong in other fields"
                )
        if protocol == "tcp" and isinstance(port, int) and port != 443:
            errors.append(
                f"network.egress[{index}]: raw tcp egress is not inspected by the gateway; only "
                f"tls (CONNECT with SNI pinning) and http are accepted for non-443 destinations"
            )
    return errors


def _resource_errors(resources: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    tmpfs = resources.get("tmpfs") or {}
    if isinstance(tmpfs, dict):
        for path, size in tmpfs.items():
            if not isinstance(path, str) or not path.startswith("/"):
                errors.append(f"resources.tmpfs: {path!r} is not an absolute in-jail path")
            if not isinstance(size, str) or not _SIZE_LIMIT.fullmatch(size):
                errors.append(f"resources.tmpfs.{path}: {size!r} is not a size such as 64m or 1g")
    cpus = resources.get("cpus")
    if isinstance(cpus, bool) or not isinstance(cpus, int | float):
        if cpus is not None:
            errors.append("resources.cpus: must be a number")
    elif cpus <= 0:
        errors.append("resources.cpus: must be greater than zero")
    for field in ("memory", "disk"):
        value = resources.get(field)
        if value is not None and (not isinstance(value, str) or not _SIZE_LIMIT.fullmatch(value)):
            errors.append(f"resources.{field}: {value!r} is not a size such as 512m or 4g")
    return errors


def _agent_errors(document: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    agent = document.get("agent")
    if not isinstance(agent, dict):
        return errors
    command = agent.get("command")
    if isinstance(command, str) and "/" in command and not command.startswith("/"):
        errors.append(
            f"agent.command: {command!r} is a relative path; use a bare executable name resolved "
            f"from PATH inside the jail, or an absolute in-jail path"
        )
    args = agent.get("args") or []
    if isinstance(args, list):
        for index, arg in enumerate(args):
            if not isinstance(arg, str):
                continue
            for placeholder in _PLACEHOLDER.findall(arg):
                if placeholder not in _ARG_PLACEHOLDERS:
                    errors.append(
                        f"agent.args[{index}]: unknown placeholder {{{placeholder}}}; supported "
                        f"placeholders are {', '.join('{' + p + '}' for p in sorted(_ARG_PLACEHOLDERS))}"
                    )
    return errors


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------


def normalise_profile_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """Return a fully-populated copy of a validated document.

    ``agentjail profile show`` prints this, so the defaults the launcher will
    apply are visible before anything runs.
    """
    normalised: dict[str, Any] = json.loads(json.dumps(dict(document)))

    normalised.setdefault("mounts", [])
    for mount in normalised["mounts"]:
        mount.setdefault("read_only", True)
        mount.setdefault("required", True)

    normalised.setdefault("env", {})
    normalised["env"] = {name: _stringify(value) for name, value in normalised["env"].items()}

    normalised.setdefault("secrets", [])
    for secret in normalised["secrets"]:
        delivery = secret.setdefault("delivery", "env")
        secret.setdefault("name", secret.get("target"))
        if delivery == "file":
            secret.setdefault("mode", "0400")
        else:
            secret.pop("mode", None)

    network = normalised.setdefault("network", {})
    network.setdefault("egress", [])
    for entry in network["egress"]:
        entry.setdefault("protocol", "tls")

    resources = normalised.setdefault("resources", {})
    for key, value in DEFAULT_RESOURCES.items():
        if isinstance(value, dict):
            resources.setdefault(key, {})
            for nested_key, nested_value in value.items():
                resources[key].setdefault(nested_key, nested_value)
        else:
            resources.setdefault(key, value)

    agent = normalised.setdefault("agent", {})
    agent.setdefault("args", [])
    return normalised


def _stringify(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}

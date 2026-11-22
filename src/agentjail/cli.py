"""Command line interface for agentjail.

Increment 1 wires every subcommand and implements profile validation, profile
display, and host diagnostics. ``run`` and ``selftest`` validate their inputs
and then stop with exit code 3 (``NOT_IMPLEMENTED``) instead of pretending.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__, doctor
from .errors import (
    EXIT_FAILURE,
    EXIT_OK,
    AgentjailError,
    NotImplementedYet,
)
from .paths import PROFILE_DIR_ENV, profile_search_dirs
from .profile import Profile, load_profile

PROGRAM = "agentjail"

LAUNCHER_CONTRACT = """\
Launcher contract (fixed now, implemented in a later increment):

  * stdio is pipes, not a TTY: stdin and stdout are a pair of pipes, so a
    JSON-RPC session over fd 0/1 works unchanged. stderr stays a separate
    stream and is never merged into stdout.
  * SIGINT, SIGTERM and SIGQUIT are forwarded to the agent process, terminal
    resize events are forwarded, and EOF on stdin is propagated.
  * agentjail exits with the agent's exit code; a signal-terminated agent maps
    to 128 + signal number.
  * The container is removed on every exit path, including signal and crash,
    so no jail is orphaned.

Exit codes: 0 success, 1 failure, 2 usage error, 3 not implemented yet. Once
launching is implemented, the agent's own exit code is passed through.
"""

SELFTEST_CONTRACT = """\
Selftest contract (fixed now, implemented in a later increment). Each check is
run twice in the same test file -- once against the pre-jail baseline and once
against the jailed build -- and must fail on the baseline while passing in the
jail:

  negative (must be denied)
    - no host secrets readable: a host-only credential path and a host
      environment variable are both unreachable
    - no host path writable by default
    - no unlisted destination reachable, and no DNS answer for an unlisted name
    - no podman/docker socket or host control socket reachable
    - no escape: no /proc/1/root, no host /proc mount, no CAP_SYS_ADMIN
    - two concurrent jails on distinct networks and homes cannot see each
      other's files, sockets, or credentials

  positive control
    - exactly one call to one allowlisted destination succeeds, and the
      response is well formed

  resource limits
    - cpu, memory, pids, open files, tmpfs size, and writable-layer size are
      each enforced, not merely declared
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=(
            "Run an AI coding agent inside a rootless Podman jail with no host secrets, "
            "no host network, its own home, and an egress allowlist."
        ),
        epilog=(
            "Profiles are TOML files validated against schema/profile.schema.json. "
            "See docs/profiles.md for the reference."
        ),
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")
    parser.add_argument(
        "--profile-dir",
        action="append",
        default=None,
        metavar="DIR",
        help=(
            "extra directory to search for <name>.toml profiles; may be repeated "
            f"(also settable with {PROFILE_DIR_ENV})"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>", required=True)

    run = subparsers.add_parser(
        "run",
        help="launch an agent inside the jail",
        description=LAUNCHER_CONTRACT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run.add_argument("profile", help="profile name or path to a .toml profile")
    run.add_argument(
        "--no-secrets",
        action="store_true",
        help=(
            "launch without injecting any secrets[] entries; the agent runs with the jail's "
            "environment only. Accepted before the profile or as the first token after it; "
            "option parsing stops at '--'"
        ),
    )
    run.add_argument(
        "agent_command",
        nargs=argparse.REMAINDER,
        metavar="-- <agent command...>",
        help=(
            "agent command and arguments after '--'; overrides agent.command/agent.args from "
            "the profile"
        ),
    )
    run.set_defaults(handler=_cmd_run)

    selftest = subparsers.add_parser(
        "selftest",
        help="prove the jail holds by trying to break out of it",
        description=SELFTEST_CONTRACT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    selftest.add_argument("profile", help="profile name or path to a .toml profile")
    selftest.set_defaults(handler=_cmd_selftest)

    profile = subparsers.add_parser("profile", help="inspect and validate profiles")
    profile_sub = profile.add_subparsers(dest="profile_command", metavar="<action>", required=True)
    for action, help_text in (
        ("validate", "validate a profile against the schema and semantic rules"),
        ("show", "print the effective profile with defaults resolved, as JSON"),
    ):
        sub = profile_sub.add_parser(action, help=help_text)
        sub.add_argument("profile", help="profile name or path to a .toml profile")
        sub.set_defaults(
            handler=_cmd_profile_validate if action == "validate" else _cmd_profile_show
        )

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="report podman version, rootless mode, SELinux state, and config paths",
        description=(
            "Read-only host diagnostics: podman binary and version, rootless mode, storage "
            "driver, cgroup version, SELinux state, and the config/data/state directories "
            "agentjail uses."
        ),
    )
    doctor_parser.add_argument("--json", action="store_true", help="machine-readable output")
    doctor_parser.set_defaults(handler=_cmd_doctor)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else list(argv))
    search_dirs = [Path(d).expanduser() for d in (args.profile_dir or [])]
    try:
        return int(args.handler(args, search_dirs=search_dirs))
    except AgentjailError as exc:
        print(f"{PROGRAM}: error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print(f"{PROGRAM}: interrupted", file=sys.stderr)
        return 130


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------


def _load(args: argparse.Namespace, search_dirs: list[Path]) -> Profile:
    dirs = [*search_dirs, *profile_search_dirs()] if search_dirs else None
    return load_profile(args.profile, search_dirs=dirs)


def _cmd_run(args: argparse.Namespace, search_dirs: list[Path] | None = None) -> int:
    profile = _load(args, list(search_dirs or []))
    command = _agent_argv(args.agent_command)
    # argparse's REMAINDER grabs everything after the profile, so tolerate
    # `run <profile> --no-secrets -- <cmd>` as well as the documented
    # `run --no-secrets <profile> -- <cmd>`. Silently passing the flag through
    # would run the agent without suppressing the secrets, which is the exact
    # failure mode we do not want.
    no_secrets = bool(args.no_secrets)
    if command[:1] == ["--no-secrets"]:
        no_secrets = True
        command = command[1:]
    if not command:
        command = [profile.document["agent"]["command"], *profile.document["agent"]["args"]]
    secret_note = (
        "all secrets suppressed (--no-secrets)"
        if no_secrets
        else f"{profile.secret_count} secret reference(s) would be injected"
    )
    raise NotImplementedYet(
        "agentjail run: launching a jail is not implemented in this increment.\n"
        f"profile {profile.name!r} validated: {profile.summary()}; {secret_note}\n"
        f"would exec {_quote(command)} inside {profile.image}\n"
        "The launcher contract (pipes not TTY, signal and resize forwarding, exit-code "
        "propagation, no orphaned containers) is documented in docs/cli.md."
    )


def _cmd_selftest(args: argparse.Namespace, search_dirs: list[Path] | None = None) -> int:
    profile = _load(args, list(search_dirs or []))
    raise NotImplementedYet(
        "agentjail selftest: the checks are not implemented in this increment.\n"
        f"profile {profile.name!r} validated: {profile.summary()}\n"
        "Planned negative set: host secrets unreadable, host paths read-only, unlisted "
        "destinations unreachable, container control sockets absent, no escape, concurrent "
        "jails isolated, resource limits enforced; positive control: one allowlisted "
        "destination answers. See docs/cli.md."
    )


def _cmd_profile_validate(args: argparse.Namespace, search_dirs: list[Path] | None = None) -> int:
    profile = _load(args, list(search_dirs or []))
    print(f"OK {profile.path}")
    print(f"   image: {profile.image}")
    print(f"   {profile.summary()}")
    return EXIT_OK


def _cmd_profile_show(args: argparse.Namespace, search_dirs: list[Path] | None = None) -> int:
    profile = _load(args, list(search_dirs or []))
    payload = {"name": profile.name, "source": str(profile.path), "profile": profile.document}
    print(json.dumps(payload, indent=2, sort_keys=True))
    return EXIT_OK


def _cmd_doctor(args: argparse.Namespace, search_dirs: list[Path] | None = None) -> int:
    report = doctor.collect()
    print(doctor.render_json(report) if args.json else doctor.render_human(report))
    return EXIT_OK if report.ok else EXIT_FAILURE


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _agent_argv(raw: Sequence[str]) -> list[str]:
    """Strip the leading ``--`` that argparse keeps in a REMAINDER list."""
    argv = list(raw)
    while argv and argv[0] == "--":
        argv.pop(0)
    return argv


def _quote(command: Sequence[str]) -> str:
    return " ".join(command)


__all__ = [
    "LAUNCHER_CONTRACT",
    "SELFTEST_CONTRACT",
    "build_parser",
    "main",
]

"""Errors and process exit codes shared by the CLI."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_NOT_IMPLEMENTED = 3


class AgentjailError(Exception):
    """Base class for errors that the CLI reports without a traceback."""

    exit_code = EXIT_FAILURE


class ProfileError(AgentjailError):
    """A profile could not be found, parsed, or validated."""

    def __init__(self, message: str, *, errors: Iterable[str] = ()) -> None:
        self.errors = list(errors)
        if self.errors:
            message = message.rstrip() + "\n" + "\n".join(f"  - {error}" for error in self.errors)
        super().__init__(message)


class ValidationFailed(ProfileError):
    """The profile parsed but violated the schema or a semantic rule."""


class NotImplementedYet(AgentjailError):
    """A wired-up subcommand whose implementation lands in a later increment."""

    exit_code = EXIT_NOT_IMPLEMENTED


@dataclass
class DoctorReport:
    """Result of ``agentjail doctor``.

    ``sections`` is an ordered mapping of section name to ``(key, value)``
    pairs so both the human and the JSON renderers stay in sync.
    """

    sections: dict[str, list[tuple[str, object]]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    ok: bool = True

    def add(self, section: str, key: str, value: object) -> None:
        self.sections.setdefault(section, []).append((key, value))

    def warn(self, message: str) -> None:
        self.warnings.append(message)

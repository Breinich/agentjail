#!/usr/bin/env python3
"""Static checks for every Containerfile under images/.

These are the rules a human reviewer would otherwise have to re-check on each
change, and the ones that matter for the threat model:

* a base image tag alone is not a pin -- every FROM needs a digest;
* the final stage must not run as root;
* build-time ENV must not carry credentials;
* no ADD from a URL, and an ENTRYPOINT/CMD must exist.

Parsing is line-oriented and handles backslash continuations. It is not a full
Dockerfile parser, and it does not try to be: it only needs to catch the
mistakes above. Exit code 0 means every file passed.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

DIGEST_PIN = re.compile(r"@sha256:[0-9a-f]{64}$")
SECRETISH_ENV = re.compile(
    r"(PASS|PASSWD|PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|ACCESS_KEY|"
    r"CREDENTIAL|AUTH)",
    re.IGNORECASE,
)
INSTRUCTIONS = frozenset(
    {
        "ADD",
        "ARG",
        "CMD",
        "COPY",
        "ENTRYPOINT",
        "ENV",
        "EXPOSE",
        "FROM",
        "HEALTHCHECK",
        "LABEL",
        "MAINTAINER",
        "ONBUILD",
        "RUN",
        "SHELL",
        "STOPSIGNAL",
        "USER",
        "VOLUME",
        "WORKDIR",
    }
)


@dataclass(frozen=True)
class Instruction:
    keyword: str
    argument: str
    line: int


def parse(text: str) -> tuple[list[Instruction], list[str]]:
    """Return (instructions, parse errors)."""
    instructions: list[Instruction] = []
    errors: list[str] = []
    buffer = ""
    buffer_line = 0
    for number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            buffer_line = number
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        buffer += stripped
        keyword, _, argument = buffer.partition(" ")
        keyword = keyword.upper()
        if keyword not in INSTRUCTIONS:
            errors.append(f"line {buffer_line}: not a Dockerfile instruction: {keyword!r}")
        else:
            instructions.append(Instruction(keyword, argument.strip(), buffer_line))
        buffer = ""
    if buffer.strip():
        keyword, _, argument = buffer.partition(" ")
        instructions.append(Instruction(keyword.upper(), argument.strip(), buffer_line))
    return instructions, errors


def check(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"{path}: cannot read: {exc}"]

    instructions, errors = parse(text)
    problems = [f"{path}: {error}" for error in errors]
    if not instructions:
        problems.append(f"{path}: no instructions found")
        return problems

    stages: list[list[Instruction]] = []
    for instruction in instructions:
        if instruction.keyword == "FROM":
            stages.append([instruction])
        elif stages:
            stages[-1].append(instruction)
        else:
            problems.append(f"{path}:{instruction.line}: instruction before the first FROM")

    for stage_index, stage in enumerate(stages):
        from_instruction = stage[0]
        image = from_instruction.argument.split()[0]
        if not DIGEST_PIN.search(image):
            problems.append(
                f"{path}:{from_instruction.line}: base image {image!r} is not pinned by digest "
                f"(expected @sha256:<64 hex>)"
            )
        if stage_index != len(stages) - 1:
            continue

        users = [i for i in stage if i.keyword == "USER"]
        if not users:
            problems.append(f"{path}: final stage never sets USER; it would run as root")
        else:
            user = users[-1].argument.split(":")[0].strip()
            if user in {"root", "0"}:
                problems.append(f"{path}:{users[-1].line}: final stage runs as root ({user})")

        if not any(i.keyword in {"ENTRYPOINT", "CMD"} for i in stage):
            problems.append(f"{path}: final stage has no ENTRYPOINT or CMD")

        for instruction in stage:
            if instruction.keyword == "ENV":
                for match in SECRETISH_ENV.finditer(instruction.argument):
                    problems.append(
                        f"{path}:{instruction.line}: ENV mentions a credential-like name "
                        f"({match.group(0)}); image builds must not carry secrets"
                    )
            if instruction.keyword == "ADD" and re.match(r"https?://", instruction.argument):
                problems.append(
                    f"{path}:{instruction.line}: ADD from a URL is not reproducible; use a "
                    f"digest-pinned COPY source"
                )
    return problems


def discover(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and (path.name == "Containerfile" or path.name.endswith(".Containerfile"))
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "roots",
        nargs="*",
        default=["images"],
        metavar="PATH",
        help="Containerfile or directory to check (default: images)",
    )
    args = parser.parse_args(argv)

    files: list[Path] = []
    for root in args.roots:
        files.extend(discover(Path(root)))
    if not files:
        print("check_containerfile: no Containerfiles found", file=sys.stderr)
        return 1

    problems: list[str] = []
    for path in files:
        problems.extend(check(path))
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print(f"check_containerfile: {len(problems)} problem(s)", file=sys.stderr)
        return 1
    print(f"check_containerfile: {len(files)} file(s) OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

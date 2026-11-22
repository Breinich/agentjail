#!/usr/bin/env python3
"""Keep the shipped copy of the profile schema in sync with the canonical one.

``schema/profile.schema.json`` is the reviewable, authoritative document.
An installed wheel cannot reach outside its package, so a byte-identical copy
lives at ``src/agentjail/data/profile.schema.json``.

Usage:
    python scripts/sync_schema.py           # copy canonical -> packaged
    python scripts/sync_schema.py --check   # exit 1 if they differ (CI)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CANONICAL = REPO_ROOT / "schema" / "profile.schema.json"
PACKAGED = REPO_ROOT / "src" / "agentjail" / "data" / "profile.schema.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify instead of writing")
    args = parser.parse_args(argv)

    if not CANONICAL.is_file():
        print(f"sync_schema: missing canonical schema {CANONICAL}", file=sys.stderr)
        return 1
    canonical = CANONICAL.read_bytes()

    if args.check:
        if not PACKAGED.is_file():
            print(f"sync_schema: missing packaged copy {PACKAGED}", file=sys.stderr)
            return 1
        if PACKAGED.read_bytes() != canonical:
            print(
                "sync_schema: packaged copy is stale; run `python scripts/sync_schema.py`",
                file=sys.stderr,
            )
            return 1
        print("sync_schema: packaged schema matches canonical schema")
        return 0

    PACKAGED.parent.mkdir(parents=True, exist_ok=True)
    PACKAGED.write_bytes(canonical)
    print(f"sync_schema: wrote {PACKAGED.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

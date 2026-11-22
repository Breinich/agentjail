"""Allow ``python -m agentjail`` as an equivalent of the console script."""

from __future__ import annotations

import sys

from agentjail.cli import main

if __name__ == "__main__":  # pragma: no cover - exercised through the CLI tests
    sys.exit(main())

"""agentjail: run an AI coding agent inside a rootless Podman jail.

The public surface of this package is the ``agentjail`` console script. The
package is intentionally agent-agnostic: an agent is just a process with a
command and arguments, and nothing here knows about any specific vendor,
harness, or session.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"

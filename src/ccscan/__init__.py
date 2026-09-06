"""ccscan: a static scanner for what a repository asks Claude Code to do.

It reads `.claude/` settings, hooks, agents, skills, commands, `.mcp.json`,
plugin manifests and `CLAUDE.md`, and reports the grants and instructions a
maintainer should see before trusting the checkout. No network, no execution.
"""

from ccscan.cli import main

__all__ = ["main"]
__version__ = "0.1.0"

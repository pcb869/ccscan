"""`ccscan [PATH ...]`: scan, print, exit 1 when something at or above --fail-on turned up."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ccscan.findings import SEVERITIES, at_least
from ccscan.report import render_json, render_text
from ccscan.scan import scan_path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ccscan",
        description="Static scanner for what a checkout asks Claude Code to do: "
        ".claude/ settings, hooks, agents, skills, .mcp.json, plugin manifests, CLAUDE.md.",
    )
    p.add_argument("paths", nargs="*", default=["."], help="directories or files (default: .)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="high",
        help="exit 1 when any finding is this severe or worse (default: high)",
    )
    p.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="low",
        help="lowest severity printed in text mode (default: low)",
    )
    p.add_argument("--all", action="store_true", help="print info findings too")
    p.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="RULE",
        help="drop findings for this rule id (repeatable)",
    )
    p.add_argument("--version", action="version", version="ccscan 0.1.0")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    results = []
    for raw in args.paths:
        path = Path(raw).expanduser()
        if not path.exists():
            print(f"ccscan: no such path: {raw}", file=sys.stderr)
            return 2
        result = scan_path(path)
        if args.ignore:
            result.findings = [f for f in result.findings if f.rule not in set(args.ignore)]
        results.append(result)
    min_severity = "info" if args.all else args.min_severity
    sys.stdout.write(render_json(results) if args.json else render_text(results, min_severity=min_severity))
    failed = any(at_least(f.severity, args.fail_on) for r in results for f in r.findings)
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

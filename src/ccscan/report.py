"""Text and JSON rendering of a scan."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ccscan.findings import SEVERITIES, Finding, at_least, sort_key


@dataclass
class ScanResult:
    root: str
    scanned: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = dict.fromkeys(SEVERITIES, 0)
        for f in self.findings:
            out[f.severity] += 1
        return out

    def worst(self) -> str | None:
        return min((f.severity for f in self.findings), key=SEVERITIES.index, default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "scanned": self.scanned,
            "summary": self.counts(),
            "findings": [f.to_dict() for f in sorted(self.findings, key=sort_key)],
            "errors": self.errors,
        }


def render_json(results: list[ScanResult]) -> str:
    payload = results[0].to_dict() if len(results) == 1 else [r.to_dict() for r in results]
    return json.dumps(payload, indent=2)


def render_text(results: list[ScanResult], *, min_severity: str) -> str:
    lines: list[str] = []
    for r in results:
        shown = [f for f in sorted(r.findings, key=sort_key) if at_least(f.severity, min_severity)]
        hidden = len(r.findings) - len(shown)
        files = ", ".join(f"{k} {v}" for k, v in sorted(r.scanned.items()) if v)
        lines.append(f"ccscan {r.root}")
        lines.append(f"  scanned: {files or 'nothing recognised'}")
        for err in r.errors:
            lines.append(f"  error: {err}")
        lines.append("")
        for f in shown:
            where = f"{f.file}:{f.line}" if f.line else f.file
            lines.append(f"{f.severity.upper():<8} {f.rule:<18} {where}")
            lines.append(f"         {f.message}")
            if f.evidence:
                lines.append(f"         > {f.evidence}")
        counts = r.counts()
        summary = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s]) or "no findings"
        tail = f" ({hidden} below {min_severity}; --all shows them)" if hidden else ""
        lines.append(f"summary: {summary}{tail}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"

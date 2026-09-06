"""One finding, and the order severities sort in."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    file: str
    line: int | None
    message: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]


def at_least(severity: str, threshold: str) -> bool:
    """True when `severity` is as bad as `threshold` or worse."""
    return SEVERITY_RANK[severity] <= SEVERITY_RANK[threshold]


def sort_key(f: Finding) -> tuple[int, str, int, str]:
    return (f.rank, f.file, f.line or 0, f.rule)

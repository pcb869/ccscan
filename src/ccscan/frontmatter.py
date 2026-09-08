"""YAML frontmatter and the tool-pattern grammar shared by skills, agents and settings."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml

_FM_RE = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.DOTALL)


@dataclass(frozen=True)
class Document:
    """A markdown file split into frontmatter (None when absent or invalid),
    body, the body's first line number (1-based), and a parse error if any."""

    meta: dict[str, Any] | None
    body: str
    body_line: int
    error: str | None = None


def split(text: str) -> Document:
    m = _FM_RE.match(text)
    if not m:
        return Document(None, text, 1)
    raw = m.group(1)
    body_line = text[: m.end()].count("\n") + 1
    try:
        loaded = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        # Claude Code loads plenty of skills whose frontmatter is not strict
        # YAML (a colon inside a description is the usual case), so fall
        # back to key: value lines rather than lose the allowed-tools grant.
        return Document(_lenient(raw), text[m.end() :], body_line, error=str(exc).splitlines()[0])
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        return Document(None, text[m.end() :], body_line, error="frontmatter is not a mapping")
    return Document(loaded, text[m.end() :], body_line)


def _lenient(raw: str) -> dict[str, Any]:
    """`key: value` lines, `- item` continuation lines, bracketed lists."""
    out: dict[str, Any] = {}
    key: str | None = None
    for line in raw.splitlines():
        m = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", line)
        if m:
            key, value = m.group(1), m.group(2).strip()
            out[key] = value if value else []
            continue
        item = re.match(r"^\s+-\s+(.*)$", line)
        if item and key is not None and isinstance(out.get(key), list):
            out[key].append(item.group(1).strip())
    return out


_TOKEN_RE = re.compile(r"[^\s,()]+\([^)]*\)|[^\s,()]+")


def tool_list(value: Any) -> list[str]:
    """`tools` / `allowed-tools` / `permissions.allow` in any of the accepted
    shapes: a comma- or space-separated string, a YAML list, or a bracketed
    string. `Bash(git add *)` stays one token."""
    if value is None:
        return []
    if isinstance(value, list):
        out: list[str] = []
        for v in value:
            out.extend(tool_list(v))
        return out
    s = str(value).strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    return [t.strip().strip("\"'") for t in _TOKEN_RE.findall(s) if t.strip()]


_NET_CMDS = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "ftp",
        "telnet",
        "socat",
        "http",
        "https",
    }
)
_INTERP_CMDS = frozenset(
    {
        "python",
        "python3",
        "node",
        "deno",
        "bun",
        "ruby",
        "perl",
        "php",
        "sh",
        "bash",
        "zsh",
        "fish",
        "eval",
        "source",
        "exec",
        "xargs",
        "env",
        "osascript",
        "npx",
        "bunx",
        "uvx",
        "pipx",
        "make",
        "docker",
    }
)
_DESTRUCTIVE_CMDS = frozenset(
    {
        "rm",
        "sudo",
        "chmod",
        "chown",
        "dd",
        "mkfs",
        "kill",
        "killall",
        "launchctl",
        "crontab",
        "shutdown",
        "reboot",
        "diskutil",
        "pkill",
    }
)
_SENSITIVE_PATH_RE = re.compile(
    r"(^|[\s/(])(~|\$HOME|/etc|/Users|/home|/root|/var|/private)\b|\.\./|"
    r"\.ssh|\.aws|\.gnupg|\.netrc|\.kube|\.claude\.json|\.env\b|keychain|credentials",
    re.IGNORECASE,
)
_TOOL_RE = re.compile(r"\s*([A-Za-z_][\w:*-]*|\*)\s*(?:\((.*)\))?\s*\Z", re.DOTALL)


def classify_tool(pattern: str) -> frozenset[str]:
    """Tags for one tool pattern. Empty for a plain, scoped grant.

    bash_any: unrestricted shell. bash_net / bash_interp / bash_destructive:
    a shell grant whose first word can reach the network, run arbitrary
    code, or destroy. read_secret / write_outside: file tools aimed at
    credential stores or outside the project. mcp_all: every MCP tool.
    all_tools: the `*` wildcard. web: WebFetch/WebSearch.
    """
    m = _TOOL_RE.match(pattern)
    if not m:
        return frozenset()
    name, arg = m.group(1), m.group(2)
    tags: set[str] = set()
    if name == "*":
        return frozenset({"all_tools"})
    if name in ("Bash", "PowerShell", "Shell"):
        spec = (arg or "").strip()
        if spec in ("", "*", "*:*", "**", ".*"):
            return frozenset({"bash_any"})
        first = spec.split()[0].strip("\"'")
        base = first.rsplit("/", 1)[-1]
        if first == "*" or base.startswith("*"):
            tags.add("bash_any")
        elif base in _NET_CMDS:
            tags.add("bash_net")
        elif base in _INTERP_CMDS:
            tags.add("bash_interp")
        elif base == "rm":
            # `rm one/file` is housekeeping; recursion, wildcards or a home/root path are not.
            if re.search(r"\s-[a-z]*[rf]|\*|(^|\s)(/|~|\$HOME)", spec[2:]):
                tags.add("bash_destructive")
        elif base in _DESTRUCTIVE_CMDS:
            tags.add("bash_destructive")
        elif spec.startswith("git push"):
            tags.add("bash_publish")
        return frozenset(tags)
    if name in ("Read", "Glob", "Grep", "Write", "Edit", "MultiEdit", "NotebookEdit"):
        if arg and _SENSITIVE_PATH_RE.search(arg):
            tags.add("read_secret" if name in ("Read", "Glob", "Grep") else "write_outside")
        return frozenset(tags)
    if name.startswith("mcp__"):
        if name in ("mcp__*", "mcp__") or name.endswith("__*"):
            tags.add("mcp_all")
        return frozenset(tags)
    if name in ("WebFetch", "WebSearch"):
        tags.add("web")
    return frozenset(tags)

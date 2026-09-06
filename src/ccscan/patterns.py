"""Text rules that apply to shell commands, handler scripts and markdown bodies.

A rule is a regex plus the contexts it is allowed to fire in: "shell" for
hook commands, MCP command lines, helper commands and the scripts they
point at; "markdown" for skill, agent, command and CLAUDE.md bodies. The
split keeps documentation that merely mentions curl from being flagged as
exfiltration, while a hook that pipes curl into sh still is.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

Context = str  # "shell" | "markdown"


@dataclass(frozen=True)
class TextRule:
    id: str
    severity: str
    title: str
    regex: re.Pattern[str]
    contexts: frozenset[str]
    accept: Callable[[re.Match[str]], bool] | None = None
    #: Markdown is an instruction to a model that still asks permission; a
    #: hook or MCP command line runs by itself. Same pattern, one notch lower.
    markdown_severity: str | None = None

    def severity_for(self, context: str) -> str:
        if context == "markdown" and self.markdown_severity:
            return self.markdown_severity
        return self.severity


@dataclass(frozen=True)
class TextHit:
    rule: TextRule
    line: int
    evidence: str


def _rule(
    id: str,
    severity: str,
    title: str,
    pattern: str,
    *contexts: str,
    flags: int = re.IGNORECASE,
    accept: Callable[[re.Match[str]], bool] | None = None,
    markdown: str | None = None,
) -> TextRule:
    return TextRule(id, severity, title, re.compile(pattern, flags), frozenset(contexts), accept, markdown)


def _line_text(m: re.Match[str]) -> str:
    text = m.string
    start = text.rfind("\n", 0, m.start()) + 1
    end = text.find("\n", m.end())
    return text[start : end if end != -1 else len(text)]


def _not_advice(m: re.Match[str]) -> bool:
    """A line that warns against a command, or documents a pattern, is not
    an instruction to run it."""
    line = _line_text(m)
    if re.search(r"\\[sdw.+*]", line):
        return False
    return not re.search(
        r"\b(?:don'?t|do\s+not|never|avoid|dangerous|risky|block|blocks|blocked|flag|flags|detect|warn|prevent)\b",
        line,
        re.IGNORECASE,
    )


_EMOJI_RE = re.compile("[\U0001f000-\U0001faff\u2600-\u27bf\ufe0f]")


def _hidden_not_emoji_joiner(m: re.Match[str]) -> bool:
    """U+200D joins emoji sequences; flag it only between ordinary text."""
    if m.group(0) != "\u200d":
        return True
    before = m.string[m.start() - 1 : m.start()]
    after = m.string[m.end() : m.end() + 1]
    return not (_EMOJI_RE.search(before) or _EMOJI_RE.search(after))


def _npm_pinned(pkg: str) -> bool:
    # @scope/name@1.2.3 or name@1.2.3 / name@latest counts as pinned-ish only with a digit.
    body = pkg[1:] if pkg.startswith("@") else pkg
    return bool(re.search(r"@\d", body))


def _unpinned(m: re.Match[str]) -> bool:
    runner, pkg = m.group(1).split()[0], m.group(2)
    if pkg.startswith("-"):
        return False
    if runner in ("npx", "bunx", "pnpm"):
        return not _npm_pinned(pkg)
    return "==" not in pkg and "@" not in pkg


def _not_hex(m: re.Match[str]) -> bool:
    return re.fullmatch(r"[0-9a-fA-F]+", m.group(0)) is None


_BOTH = ("shell", "markdown")

RULES: tuple[TextRule, ...] = (
    _rule(
        "T-REMOTE-EXEC",
        "critical",
        "remote content is piped into a shell or interpreter",
        r"(?:curl|wget|fetch)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|k|da|fi)?sh\b"
        r"|(?:ba|z)?sh\s+<\(\s*(?:curl|wget)"
        r"|(?:ba|z)?sh\s+-c\s+[\"']?\$\((?:curl|wget)"
        r"|\beval\s+[\"']?\$\((?:curl|wget)"
        r"|(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:python3?|node|perl|ruby|php)\b",
        *_BOTH,
        markdown="high",
    ),
    _rule(
        "T-EXFIL",
        "high",
        "sends local data to a remote host",
        r"\bcurl\b[^\n]*\s(?:-d|--data\S*|-F|--form|-T|--upload-file|-X\s*(?:POST|PUT))\b"
        r"|\bwget\b[^\n]*--post-(?:data|file)"
        r"|\bnc\b\s+(?:-\S+\s+)*[\w.-]+\s+\d{2,5}\b"
        r"|/dev/(?:tcp|udp)/"
        r"|\b(?:scp|rsync)\b[^\n]*\s\S+@\S+:"
        r"|requests\.(?:post|put)\(|urlopen\([^)]*data=|HTTPSConnection\("
        r"|\bfetch\([^)]*method:\s*[\"'](?:POST|PUT)"
        r"|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org"
        r"|webhook\.site|ngrok(?:-free)?\.(?:io|app)|requestbin|pipedream\.net"
        r"|burpcollaborator|oastify\.com|interact\.sh|\.free\.beeceptor\.com",
        *_BOTH,
    ),
    _rule(
        "T-SECRETS-READ",
        "high",
        "touches credential stores or secret files",
        r"~/\.ssh|\$HOME/\.ssh|\.ssh/(?:id_|authorized_keys|config)|\bid_(?:rsa|ed25519|ecdsa)\b"
        r"|~/\.aws|\.aws/credentials|~/\.gnupg|\.netrc\b|\.kube/config"
        r"|\.claude\.json\b|~/\.claude/(?:projects|sessions|history)|\.config/gh/hosts\.yml"
        r"|security\s+find-(?:generic|internet)-password|Library/Keychains"
        r"|\b(?:cat|source|grep|cp|scp|tar|zip|base64|head|less|more)\s+[^\n]*\.env\b"
        r"|\.env\.(?:local|production|prod)\b",
        *_BOTH,
        accept=_not_advice,
        markdown="medium",
    ),
    _rule(
        "T-ENV-DUMP",
        "medium",
        "dumps the process environment",
        r"\b(?:printenv|env)\b\s*(?:\||>|$)|\bset\s*\|\s*grep|os\.environ\b[^\n]*\b(?:post|send|dump|json)",
        "shell",
        flags=re.IGNORECASE | re.MULTILINE,
    ),
    _rule(
        "T-OBFUSCATION",
        "high",
        "decodes or evaluates an encoded payload",
        r"base64\s+(?:-d|--decode|-D)\b|\bxxd\s+-r|openssl\s+enc\s+-d|\beval\s+[\"'$(]"
        r"|python3?\s+-c\s+[\"']?(?:exec|eval)\b|\batob\(|(?:\\x[0-9a-f]{2}){4,}"
        r"|echo\s+[\"']?[A-Za-z0-9+/]{40,}={0,2}",
        *_BOTH,
    ),
    _rule(
        "T-DESTRUCTIVE",
        "high",
        "destructive or privileged command",
        r"\brm\s+-[a-z]*[rf][a-z]*\s+(?:/(?:\s|$|\*)|~(?:/\*|\s|$)|\$HOME(?:/\*|\s|$)|\*|\.\.(?:\s|$))"
        r"|\bsudo\b|chmod\s+(?:-R\s+)?[0-7]?77[0-7]?\b"
        r"|\bmkfs\b|\bdd\s+if=|git\s+push\b[^\n]*(?:--force\b|\s-f\b)|:\(\)\s*\{\s*:\|:&\s*\};:"
        r"|\bshutdown\b|\breboot\b|\bkillall\b",
        *_BOTH,
        accept=_not_advice,
        markdown="medium",
    ),
    _rule(
        "T-PERSISTENCE",
        "high",
        "persists beyond this session",
        r"\bcrontab\b|launchctl\s+(?:load|bootstrap|submit)|LaunchAgents|LaunchDaemons|systemctl\s+enable"
        r"|>>?\s*[\"']?~?/?[^\s\"']*\.(?:zshrc|bashrc|bash_profile|zprofile|profile)\b"
        r"|/etc/(?:profile|hosts|sudoers|cron)|~/\.claude/(?:settings\.json|CLAUDE\.md|agents|skills|hooks)"
        r"|\$HOME/\.claude/|\.git/hooks/",
        *_BOTH,
        accept=_not_advice,
        markdown="medium",
    ),
    _rule(
        "T-UNPINNED-EXEC",
        "medium",
        "runs an unpinned package straight from a registry",
        r"\b(npx|bunx|pnpm\s+dlx|uvx|pipx\s+run)\s+(?:-y\s+|--yes\s+|-q\s+)?(\S+)",
        "shell",
        accept=_unpinned,
    ),
    _rule(
        "T-INJECTION",
        "high",
        "instruction-override or concealment language",
        r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions|rules|guidance|prompts?)"
        r"|disregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|your)\s+\w*\s*(?:instructions|rules|guidelines)"
        r"|do\s+not\s+(?:tell|inform|mention|reveal|show|disclose|notify|alert|warn)\s+(?:this\s+to\s+)?(?:the\s+)?(?:user|human|operator)"
        r"|don'?t\s+(?:tell|inform|mention|reveal|show|disclose|notify|warn)\s+(?:the\s+)?(?:user|human)"
        r"|\b(?:run|execute|send|upload|post|proceed|continue|delete|install|do\s+(?:this|it|so))\b[^.\n]{0,60}"
        r"without\s+(?:telling|informing|asking|notifying|alerting|warning|consulting)\s+(?:the\s+)?(?:user|human)"
        r"|(?:hide|conceal|keep)\s+(?:this|it|these)\s+(?:from|hidden\s+from|secret\s+from)\s+(?:the\s+)?(?:user|human)"
        r"|never\s+(?:mention|reveal|disclose)\b"
        r"|new\s+system\s+prompt|\bsystem\s+prompt\s*:|\[system\]|<\s*system\s*>"
        r"|(?:bypass|disable|skip|override)\s+(?:all\s+|any\s+|the\s+)?(?:permission|safety|security|guardrail|confirmation)s?\b"
        r"|--dangerously-skip-permissions|\bbypassPermissions\b"
        r"|pretend\s+(?:that\s+)?(?:you|this)\b|you\s+are\s+now\s+(?:in\s+)?\w*\s*(?:mode|DAN)\b",
        "markdown",
    ),
    _rule(
        "T-COVERT",
        "medium",
        "covert-behaviour language",
        r"\b(?:secretly|covertly)\b|in\s+the\s+background\s+(?:send|upload|post|exfil)"
        r"|(?:before|prior\s+to)\s+(?:responding|answering|replying)[^.\n]{0,80}\b(?:run|execute|send|fetch|curl)\b",
        "markdown",
    ),
    _rule(
        "T-HIDDEN-TEXT",
        "high",
        "invisible or direction-override characters",
        "[​‌‍⁠﻿­⁡-⁤‪-‮⁦-⁩]",
        *_BOTH,
        flags=0,
        accept=_hidden_not_emoji_joiner,
    ),
    _rule(
        "T-HTML-COMMENT",
        "medium",
        "HTML comment carrying instructions",
        r"<!--(?:(?!-->).){12,}?\b(?:you\s+must|you\s+should|always|never|run|execute|send|ignore|do\s+not|don't)\b(?:(?!-->).)*-->",
        "markdown",
        flags=re.IGNORECASE | re.DOTALL,
    ),
    _rule(
        "T-BLOB",
        "medium",
        "long encoded blob",
        r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])",
        *_BOTH,
        flags=0,
        accept=_not_hex,
    ),
    _rule(
        "T-NETWORK",
        "info",
        "reaches the network",
        r"\b(?:curl|wget|nc|ncat|ssh|scp|sftp|ftp|telnet|socat)\b|https?://",
        "shell",
    ),
)


def scan_text(text: str, context: Context) -> Iterator[TextHit]:
    """Every rule hit in `text` for this context, at most once per rule per line."""
    seen: set[tuple[str, int]] = set()
    for rule in RULES:
        if context not in rule.contexts:
            continue
        for m in rule.regex.finditer(text):
            if rule.accept is not None and not rule.accept(m):
                continue
            line = text.count("\n", 0, m.start()) + 1
            if (rule.id, line) in seen:
                continue
            seen.add((rule.id, line))
            start = text.rfind("\n", 0, m.start()) + 1
            end = text.find("\n", m.end())
            snippet = text[start : end if end != -1 else len(text)].strip()
            yield TextHit(rule, line, snippet[:160])

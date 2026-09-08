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


_QUOTED_RE = re.compile("[\"'`\u201c\u201d\u2018\u2019]")


def _not_quoted_or_described(m: re.Match[str]) -> bool:
    """An instruction phrase inside quotes is being talked about, not given
    (`reject phrases like "ignore previous instructions"`); so is one on a
    line that detects, rejects or lists it as an example. The plain
    negation words stay: "do not tell the user" IS the finding."""
    line = _line_text(m)
    if re.search(r"\\[sdw.+*]", line):
        return False
    col = m.start() - (m.string.rfind("\n", 0, m.start()) + 1)
    before = line[:col]
    if len(_QUOTED_RE.findall(before)) % 2:
        return False
    return not re.search(
        r"\b(?:reject|phrases?\s+like|such\s+as|e\.g\.|for\s+example|examples?\s+of|detect|flag|flags|block|blocks|warn|prevent)\b"
        r"|\b(?:to|can|may|would|will|might|attempts?\s+to|trying\s+to|instructs?\s+\w+\s+to)\s*$",
        before,
        re.IGNORECASE,
    )


def _not_secret_setup(m: re.Match[str]) -> bool:
    """Creating an env file from its example, or listing it in .gitignore,
    is setup, not a read of a secret."""
    return _not_advice(m) and not re.search(
        r"\.env\.(?:example|sample|template)|\.gitignore|dotenv", _line_text(m), re.IGNORECASE
    )


def _not_package_install(m: re.Match[str]) -> bool:
    """`sudo apt-get install x` is setup, not destruction."""
    if not _not_advice(m):
        return False
    return not re.search(
        r"\bsudo\s+(?:-\S+\s+)*(?:apt|apt-get|yum|dnf|pacman|snap|zypper|brew|pip3?|npm|npx|systemctl\s+(?:start|restart|status|stop|enable|disable)|service|tee|mkdir|chown|cp|mv|ln|install|xcode-select|softwareupdate)\b",
        _line_text(m),
        re.IGNORECASE,
    )


def _is_write(m: re.Match[str]) -> bool:
    """A path under ~/.claude counts as persistence only when something is
    written there; naming the directory is documentation."""
    if not _not_advice(m):
        return False
    return bool(
        re.search(
            r"(?:>>?|\b(?:cp|mv|tee|install|write|append|echo|cat|touch|mkdir)\b)",
            _line_text(m),
            re.IGNORECASE,
        )
    )


_EMOJI_RE = re.compile("[\U0001f000-\U0001faff\u2600-\u27bf\ufe0f]")


def _hidden_not_script_joiner(m: re.Match[str]) -> bool:
    """Zero-width joiners and non-joiners are letters in Persian, Arabic and
    Indic scripts and glue emoji sequences; a BOM at offset 0 is a BOM. The
    finding is a zero-width character between ordinary ASCII text, or a bidi
    override anywhere."""
    ch = m.group(0)
    if "\u202a" <= ch <= "\u202e" or "\u2066" <= ch <= "\u2069":
        return True
    if ch == "\ufeff" and m.start() == 0:
        return False
    before = m.string[m.start() - 1 : m.start()]
    after = m.string[m.end() : m.end() + 1]
    # Next to any non-ASCII character it is script or emoji glue; anywhere
    # in ASCII text it has no reason to be there.
    return not ((before and ord(before) > 127) or (after and ord(after) > 127))


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
        accept=_not_advice,
        markdown="medium",
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
        r"|\bfetch\([^)]*method:\s*[\"'](?:POST|PUT)",
        "shell",
        accept=_not_advice,
    ),
    _rule(
        "T-EXFIL",
        "high",
        "sends local files, keys or environment to a remote host",
        r"\bcurl\b[^\n]*(?:-F\s*[\"']?\w+=@|(?:-d|--data\S*)\s*[\"']?@|-T\s|--upload-file|\$\((?:cat|env|printenv|base64|tar|security)\b|~/\.|\$HOME/\.|\.ssh|\.aws|\.env\b|\.netrc|id_rsa|\.claude\.json)"
        r"|\bnc\b\s+(?:-\S+\s+)*[\w.-]+\s+\d{2,5}\s*<"
        r"|/dev/(?:tcp|udp)/"
        r"|\b(?:scp|rsync)\b[^\n]*(?:~/\.|\$HOME/\.|\.ssh|\.aws|\.env\b)[^\n]*\S+@\S+:",
        "markdown",
        accept=_not_advice,
    ),
    _rule(
        "T-EXFIL-ENDPOINT",
        "high",
        "known exfiltration or callback endpoint",
        r"discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services|api\.telegram\.org/bot"
        r"|webhook\.site|ngrok(?:-free)?\.(?:io|app)|requestbin|pipedream\.net"
        r"|burpcollaborator|oastify\.com|interact\.sh|\.free\.beeceptor\.com|requestcatcher\.com",
        *_BOTH,
        accept=_not_advice,
        markdown="low",
    ),
    _rule(
        "T-SECRETS-READ",
        "high",
        "touches credential stores or secret files",
        r"~/\.ssh|\$HOME/\.ssh|\.ssh/(?:id_|authorized_keys|config)|\bid_(?:rsa|ed25519|ecdsa)\b"
        r"|~/\.aws|\.aws/credentials|~/\.gnupg|\.netrc\b|\.kube/config"
        r"|\.claude\.json\b|~/\.claude/(?:projects|sessions|history)|\.config/gh/hosts\.yml"
        r"|security\s+find-(?:generic|internet)-password|Library/Keychains"
        r"|\b(?:cat|source|grep|cp|scp|tar|zip|base64|head|less|more|xxd)\s+[^\n]*\.env\b(?!\.example)"
        r"|\.env\.(?:local|production|prod)\b(?!\.example)",
        "shell",
        accept=_not_advice,
    ),
    _rule(
        "T-SECRETS-READ",
        "medium",
        "reads or copies a credential store",
        r"\b(?:cat|source|grep|cp|scp|tar|zip|base64|head|less|more|xxd|open|read|upload|send|post|curl|python3?|node)\b[^\n]{0,60}"
        r"(?:~/\.ssh|\$HOME/\.ssh|\.ssh/(?:id_|authorized_keys)|\bid_(?:rsa|ed25519|ecdsa)\b|~/\.aws|\.aws/credentials|~/\.gnupg"
        r"|\.netrc\b|\.kube/config|~/\.claude\.json|\.config/gh/hosts\.yml|Library/Keychains)"
        r"|security\s+find-(?:generic|internet)-password",
        "markdown",
        accept=_not_secret_setup,
    ),
    _rule(
        "T-SUDO",
        "high",
        "runs as root",
        r"\bsudo\b",
        "shell",
        accept=_not_package_install,
    ),
    _rule(
        "T-EVAL",
        "high",
        "executes a program's output as shell",
        r"\beval\s+[\"']?\$\(|\beval\s+\"\$|\beval\s+\$\w",
        *_BOTH,
        accept=_not_advice,
        markdown="low",
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
        r"(?:base64\s+(?:-d|--decode|-D)|xxd\s+-r|openssl\s+enc\s+-d)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b"
        r"|(?:base64\s+(?:-d|--decode|-D)|xxd\s+-r)\b[^|\n]*\|\s*(?:python3?|node|perl|ruby|php)\b"
        r"|python3?\s+-c\s+[\"']?(?:exec|eval)\s*\(|\batob\([^)]*\)\s*\)?\s*(?:\(|;?\s*eval|;?\s*Function)"
        r"|(?:\\x[0-9a-f]{2}){4,}"
        r"|echo\s+[\"']?[A-Za-z0-9+/]{40,}={0,2}[\"']?\s*\|\s*base64",
        *_BOTH,
        accept=_not_advice,
    ),
    _rule(
        "T-DESTRUCTIVE",
        "high",
        "destructive or privileged command",
        r"\brm\s+-[a-z]*[rf][a-z]*\s+(?:/(?:\s|$|\*)|~(?:/\*|\s|$)|\$HOME(?:/\*|\s|$)|\*|\.\.(?:\s|$))"
        r"|chmod\s+(?:-R\s+)?[0-7]?77[0-7]?\b"
        r"|\bmkfs\b|\bdd\s+if=|git\s+push\b[^\n]*(?:--force\b|\s-f\b)|:\(\)\s*\{\s*:\|:&\s*\};:"
        r"|\b(?:shutdown|reboot|killall)\s+(?:-|now|\w+$)",
        *_BOTH,
        accept=_not_advice,
        markdown="medium",
    ),
    _rule(
        "T-PERSISTENCE",
        "high",
        "persists beyond this session",
        r"\bcrontab\s+(?:-|\S+\s*$)|launchctl\s+(?:load|bootstrap|submit)|LaunchAgents|LaunchDaemons|systemctl\s+enable"
        r"|>>?\s*[\"']?~?/?[^\s\"']*\.(?:zshrc|bashrc|bash_profile|zprofile|profile)\b"
        r"|/etc/(?:profile|hosts|sudoers|cron)|\.git/hooks/",
        *_BOTH,
        accept=_not_advice,
        markdown="medium",
    ),
    _rule(
        "T-PERSISTENCE",
        "high",
        "writes into the user's Claude Code configuration",
        r"~/\.claude/(?:settings\.json|CLAUDE\.md|agents|skills|hooks|commands)|\$HOME/\.claude/",
        *_BOTH,
        accept=_is_write,
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
        r"|do\s+not\s+(?:tell|inform|mention|reveal|show|disclose|notify|alert|warn)\s+(?:the\s+)?(?:user|human|operator)\s+(?:about|that|this|it|what|anything|of|when|if|\.|$)"
        r"|don'?t\s+(?:tell|inform|mention|reveal|show|disclose|notify|warn)\s+(?:the\s+)?(?:user|human)\s+(?:about|that|this|it|what|anything|of|when|if|\.|$)"
        r"|\b(?:run|execute|send|upload|post|proceed|continue|delete|install|do\s+(?:this|it|so))\b[^.\n]{0,60}"
        r"without\s+(?:telling|informing|asking|notifying|alerting|warning|consulting)\s+(?:the\s+)?(?:user|human)"
        r"|(?:hide|conceal|keep)\s+(?:this|it|these)\s+(?:from|hidden\s+from|secret\s+from)\s+(?:the\s+)?(?:user|human)"
        r"|never\s+(?:mention|reveal|disclose)\s+(?:this|these|that\s+you|the\s+(?:skill|instructions?|prompt|rule|hook|existence))"
        r"|new\s+system\s+prompt|^\s*\[system\]"
        r"|pretend\s+(?:that\s+)?(?:you|this)\b",
        "markdown",
        flags=re.IGNORECASE | re.MULTILINE,
        accept=_not_quoted_or_described,
    ),
    _rule(
        "T-BYPASS-FLAG",
        "medium",
        "instructs running with permission prompts off",
        r"\bclaude\b[^\n]*--dangerously-skip-permissions|\bbypassPermissions\b",
        "markdown",
        accept=_not_quoted_or_described,
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
        accept=_hidden_not_script_joiner,
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
        r"(?<![.\w/-])(?:curl|wget|nc|ncat|ssh|scp|sftp|ftp|telnet|socat)\b|https?://",
        "shell",
    ),
)


def scan_text(text: str, context: Context) -> Iterator[TextHit]:
    """Every rule hit in `text` for this context, at most once per rule per line."""
    seen: set[tuple[str, int]] = set()
    if context == "shell":
        # A comment line in a handler script never runs; keep the shebang line.
        text = "\n".join("" if re.match(r"\s*(?:#(?!!)|//)", ln) else ln for ln in text.split("\n"))
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

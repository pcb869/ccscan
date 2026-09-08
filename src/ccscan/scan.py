"""Walk a tree, recognise the files Claude Code reads, run the rules on each."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ccscan.findings import Finding
from ccscan.frontmatter import classify_tool, split, tool_list
from ccscan.patterns import TextHit, scan_text
from ccscan.report import ScanResult

SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        "site-packages",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".next",
        "target",
    }
)
MAX_BYTES = 2_000_000
SETTINGS_NAMES = frozenset({"settings.json", "settings.local.json", "managed-settings.json"})
#: settings keys whose value is a command Claude Code runs (settings reference, 2026-09).
COMMAND_KEYS = (
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "otelHeadersHelper",
    "fileSuggestion",
    "statusLine",
    "policyHelper",
)
REDIRECT_ENV = frozenset(
    {
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_API_KEY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    }
)
SECRET_NAME_RE = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(
    r"^(?:sk-|ghp_|gho_|ghu_|github_pat_|xox[abp]-|AKIA|AIza|ya29\.|glpat-|npm_|pypi-|sk_live_"
    r"|rk_live_|eyJ[A-Za-z0-9_-]{10,}\.)"
)
PLACEHOLDER_RE = re.compile(
    r"^\$\{?[A-Za-z_]\w*\}?$|^<[^>]+>$|^(?:your|my|xxx|changeme|replace|todo|example|placeholder|\.\.\.)",
    re.IGNORECASE,
)
INTERPRETERS = frozenset(
    {
        "python",
        "python3",
        "bash",
        "sh",
        "zsh",
        "node",
        "deno",
        "bun",
        "uv",
        "uvx",
        "npx",
        "ruby",
        "perl",
        "env",
        "exec",
        "nohup",
    }
)
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"})
SENSITIVE_DIR_RE = re.compile(r"^(~|/|\$HOME)(/)?$|^~/|^/(?!Users/[^/]+/[^/]+|home/[^/]+/[^/]+)|\.\.")


def mask(value: str) -> str:
    return f"{value[:4]}…({len(value)} chars)"


def _line_of(raw: str, needle: str) -> int | None:
    if not needle:
        return None
    for form in (json.dumps(needle)[1:-1], needle):
        idx = raw.find(form)
        if idx >= 0:
            return raw.count("\n", 0, idx) + 1
    return None


def plugin_root_of(path: Path) -> Path | None:
    """The nearest ancestor that is a plugin (has a `.claude-plugin/` dir)."""
    for parent in (path, *path.parents):
        if (parent / ".claude-plugin").is_dir():
            return parent
    return None


def kind_of(path: Path, root: Path | None = None) -> str | None:
    """Which Claude Code input this file is, or None. `.claude` counts only
    inside the scanned tree (or as the root itself): a marketplace cache
    under ~/.claude must not turn every README into instructions."""
    name, parent, parts = path.name, path.parent.name, path.parts
    if root is not None:
        try:
            rel_parts = path.resolve().relative_to(root.resolve()).parts
        except ValueError:
            rel_parts = parts
        in_claude = ".claude" in rel_parts or root.name == ".claude"
    else:
        in_claude = ".claude" in parts
    in_plugin = plugin_root_of(path.parent) is not None
    if name in SETTINGS_NAMES and (parent == ".claude" or name == "managed-settings.json"):
        return "settings"
    if name == "hooks.json":
        return "hooks"
    if name == ".mcp.json":
        return "mcp"
    if name == "plugin.json" and parent == ".claude-plugin":
        return "plugin"
    if name == "SKILL.md":
        return "skill"
    if name in ("CLAUDE.md", "CLAUDE.local.md"):
        return "markdown"
    if name.endswith(".md") and (in_claude or in_plugin):
        if "agents" in parts:
            return "agent"
        if "commands" in parts:
            return "skill"
        if in_claude and "skills" not in parts:
            return "markdown"  # .claude/rules, memory, CLAUDE.md variants: loaded as instructions
        return None  # a plugin's README, docs and a skill's reference files are not loaded by themselves
    return None


class Scanner:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.result = ScanResult(str(root))
        self._scripts_seen: set[Path] = set()

    # -- plumbing -----------------------------------------------------------
    def rel(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.root)) or "."
        except ValueError:
            return str(path)

    def add(
        self, severity: str, rule: str, file: Path, line: int | None, message: str, evidence: str = ""
    ) -> None:
        self.result.findings.append(Finding(severity, rule, self.rel(file), line, message, evidence))

    def read(self, path: Path) -> str | None:
        try:
            if path.stat().st_size > MAX_BYTES:
                self.result.errors.append(f"{self.rel(path)}: larger than {MAX_BYTES} bytes, skipped")
                return None
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self.result.errors.append(f"{self.rel(path)}: {exc.strerror or exc}")
            return None

    def load_json(self, path: Path) -> tuple[Any, str] | None:
        raw = self.read(path)
        if raw is None:
            return None
        try:
            return json.loads(raw), raw
        except ValueError as exc:
            self.add("low", "F-BAD-JSON", path, None, f"not valid JSON, Claude Code will ignore it: {exc}")
            return None

    def text_rules(self, text: str, context: str, file: Path, base_line: int = 0) -> list[TextHit]:
        hits = list(scan_text(text, context))
        for hit in hits:
            self.add(
                hit.rule.severity_for(context),
                hit.rule.id,
                file,
                base_line + hit.line,
                hit.rule.title,
                hit.evidence,
            )
        return hits

    # -- walking --------------------------------------------------------------
    def run(self) -> ScanResult:
        if self.root.is_file():
            kind = kind_of(self.root, self.root.parent) or self._kind_by_content(self.root)
            if kind:
                self.dispatch(self.root, kind)
            return self.result
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                path = Path(dirpath) / name
                kind = kind_of(path, self.root)
                if kind:
                    self.dispatch(path, kind)
        return self.result

    def _kind_by_content(self, path: Path) -> str | None:
        if path.suffix == ".md":
            return "markdown"
        if path.suffix == ".json":
            loaded = self.load_json(path)
            if loaded and isinstance(loaded[0], dict):
                data = loaded[0]
                if "mcpServers" in data:
                    return "mcp"
                if "hooks" in data or "permissions" in data:
                    return "settings"
        return None

    def dispatch(self, path: Path, kind: str) -> None:
        self.result.scanned[kind] = self.result.scanned.get(kind, 0) + 1
        handler = {
            "settings": self.scan_settings,
            "hooks": self.scan_hooks_file,
            "mcp": self.scan_mcp_file,
            "plugin": self.scan_plugin_manifest,
            "skill": self.scan_skill,
            "agent": self.scan_agent,
            "markdown": self.scan_markdown,
        }[kind]
        handler(path)

    # -- settings.json --------------------------------------------------------
    def _settings_scope(self, path: Path) -> str:
        if path.name == "managed-settings.json":
            return "managed"
        try:
            path.resolve().relative_to(Path.home() / ".claude")
            return "user"
        except ValueError:
            return "project"

    def scan_settings(self, path: Path) -> None:
        loaded = self.load_json(path)
        if not loaded or not isinstance(loaded[0], dict):
            return
        data, raw = loaded
        scope = self._settings_scope(path)
        perms = data.get("permissions")

        if not isinstance(perms, dict):
            perms = {}
        mode = perms.get("defaultMode")
        if mode == "bypassPermissions":
            effective = scope in ("user", "managed")
            self.add(
                "critical" if effective else "high",
                "P-BYPASS-DEFAULT",
                path,
                _line_of(raw, "defaultMode"),
                "every session starts with permission prompts switched off"
                if effective
                else "asks for bypassPermissions; project settings cannot set it, but the intent is declared",
                f"permissions.defaultMode = {mode} ({scope} settings)",
            )
        elif mode == "auto":
            self.add(
                "low",
                "P-AUTO-DEFAULT",
                path,
                _line_of(raw, "defaultMode"),
                "sessions start in auto mode: a classifier, not you, approves commands",
                f"permissions.defaultMode = auto ({scope} settings)",
            )
        for rule in tool_list(perms.get("allow")):
            self._grant_findings(
                rule, path, _line_of(raw, rule), prefix="P-ALLOW", what="permissions.allow pre-approves"
            )
        for entry in perms.get("additionalDirectories") or []:
            if isinstance(entry, str) and SENSITIVE_DIR_RE.search(entry.strip()):
                self.add(
                    "medium",
                    "P-EXTRA-DIRS",
                    path,
                    _line_of(raw, entry),
                    "file tools reach outside the project",
                    f"additionalDirectories: {entry}",
                )
        if data.get("enableAllProjectMcpServers") is True:
            self.add(
                "medium",
                "P-ALL-MCP",
                path,
                _line_of(raw, "enableAllProjectMcpServers"),
                "every server in any project .mcp.json starts without a prompt",
            )
        sandbox = data.get("sandbox")

        if not isinstance(sandbox, dict):
            sandbox = {}
        if sandbox.get("autoAllowBashIfSandboxed") is True:
            self.add(
                "low",
                "P-SANDBOX-AUTO",
                path,
                _line_of(raw, "autoAllowBashIfSandboxed"),
                "sandboxed shell commands run without a prompt",
            )
        env = data.get("env")

        if not isinstance(env, dict):
            env = {}
        for key, value in env.items():
            value_s = str(value)
            line = _line_of(raw, key)
            if key in REDIRECT_ENV:
                self.add(
                    "high",
                    "P-ENV-REDIRECT",
                    path,
                    line,
                    "redirects API traffic, credentials or TLS trust for every session",
                    f"env.{key} = {mask(value_s) if SECRET_NAME_RE.search(key) else value_s}",
                )
            elif SECRET_NAME_RE.search(key) and value_s and not PLACEHOLDER_RE.match(value_s):
                self.add(
                    "high",
                    "P-ENV-SECRET",
                    path,
                    line,
                    "a credential is committed in settings",
                    f"env.{key} = {mask(value_s)}",
                )
            else:
                self.add(
                    "info",
                    "P-ENV",
                    path,
                    line,
                    "sets an environment variable for every session",
                    f"env.{key} = {value_s[:80]}",
                )
        for key in COMMAND_KEYS:
            spec = data.get(key)
            command = (
                spec
                if isinstance(spec, str)
                else (spec.get("command") or spec.get("path") if isinstance(spec, dict) else None)
            )
            if isinstance(command, str) and command.strip():
                line = _line_of(raw, command)
                self.add(
                    "medium",
                    "P-HELPER-COMMAND",
                    path,
                    line,
                    f"{key} is a command Claude Code runs on its own",
                    command[:160],
                )
                self.text_rules(command, "shell", path, (line or 1) - 1)
                self.resolve_script(command, path, path.parent, None, line)
        if isinstance(data.get("hooks"), dict):
            self.scan_hooks_obj(data["hooks"], path, raw, path.parent, plugin_root_of(path))

    def _grant_findings(self, rule: str, path: Path, line: int | None, *, prefix: str, what: str) -> None:
        tags = classify_tool(rule)
        table = {
            "bash_any": ("high", "BASH-ANY", "an unrestricted shell"),
            "all_tools": ("high", "ALL-TOOLS", "every tool"),
            "bash_destructive": ("high", "DESTRUCTIVE", "a destructive or privileged command"),
            "read_secret": ("high", "SECRETS", "reads outside the project or from credential stores"),
            "bash_net": ("medium", "NET", "a command that reaches the network"),
            "bash_publish": ("medium", "PUBLISH", "pushing to a remote"),
            "bash_interp": ("medium", "INTERP", "an interpreter, which is any command"),
            "write_outside": ("medium", "WRITE-OUTSIDE", "writes outside the project"),
            "mcp_all": ("medium", "MCP-ALL", "every MCP tool"),
        }
        for tag in sorted(tags):
            if tag in table:
                sev, suffix, desc = table[tag]
                self.add(sev, f"{prefix}-{suffix}", path, line, f"{what} {desc}", rule)

    # -- hooks ----------------------------------------------------------------
    def scan_hooks_file(self, path: Path) -> None:
        loaded = self.load_json(path)
        if not loaded or not isinstance(loaded[0], dict):
            return
        data, raw = loaded
        hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else data
        self.scan_hooks_obj(hooks, path, raw, path.parent, plugin_root_of(path))

    def scan_hooks_obj(
        self, hooks: Any, file: Path, raw: str, origin: Path, plugin_root: Path | None, base_line: int = 0
    ) -> None:
        if isinstance(hooks, list):  # frontmatter list form: entries carry their own event
            hooks = {str(h.get("event", "?")): [h] for h in hooks if isinstance(h, dict)}
        if not isinstance(hooks, dict):
            return
        for event, entries in hooks.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                matcher = entry.get("matcher") or entry.get("if") or ""
                handlers = entry["hooks"] if isinstance(entry.get("hooks"), list) else [entry]
                for h in handlers:
                    if isinstance(h, dict):
                        self._hook_handler(
                            str(event), str(matcher), h, file, raw, origin, plugin_root, base_line
                        )

    def _hook_handler(
        self,
        event: str,
        matcher: str,
        h: dict[str, Any],
        file: Path,
        raw: str,
        origin: Path,
        plugin_root: Path | None,
        base_line: int,
    ) -> None:
        kind = str(h.get("type", "command"))
        where = f"{event}" + (f" [{matcher}]" if matcher else "")
        if kind == "command":
            command = str(h.get("command", ""))
            args = [str(a) for a in (h.get("args") or [])]
            full = " ".join([command, *args]).strip()
            line = _line_of(raw, command)
            line = (base_line + line) if line else None
            self.add("info", "H-COMMAND", file, line, f"{where} hook runs a command", full[:160])
            self.text_rules(full, "shell", file, (line or 1) - 1)
            if re.search(r"(^|[\s\"'=])(/tmp|/var/tmp|/private/tmp|~/Downloads)/", command):
                self.add(
                    "medium",
                    "H-TMP-PATH",
                    file,
                    line,
                    "hook runs a script from a world-writable or download location",
                    command[:160],
                )
            self.resolve_script(full, file, origin, plugin_root, line)
        elif kind == "http":
            url = str(h.get("url", ""))
            host = (urlparse(url).hostname or "").lower()
            line = _line_of(raw, url)
            line = (base_line + line) if line else None
            if host and host not in LOCAL_HOSTS:
                self.add(
                    "medium",
                    "H-HTTP",
                    file,
                    line,
                    f"{where} hook posts tool inputs and session details to a remote host",
                    url[:160],
                )
            headers = h.get("headers")

            if not isinstance(headers, dict):
                headers = {}
            for key, value in headers.items():
                value_s = str(value)
                if not PLACEHOLDER_RE.match(value_s) and "$" not in value_s and len(value_s) >= 16:
                    self.add(
                        "high",
                        "H-HTTP-TOKEN",
                        file,
                        line,
                        "a literal credential sits in a hook header",
                        f"{key}: {mask(value_s)}",
                    )
            if h.get("allowedEnvVars"):
                self.add(
                    "medium",
                    "H-HTTP-ENV",
                    file,
                    line,
                    "environment variables are interpolated into the request",
                    ", ".join(map(str, h["allowedEnvVars"]))[:160],
                )
        elif kind in ("prompt", "agent"):
            prompt = str(h.get("prompt", ""))
            line = _line_of(raw, prompt[:40])
            line = (base_line + line) if line else None
            self.add("info", "H-PROMPT", file, line, f"{where} hook runs a model prompt", prompt[:120])
            self.text_rules(prompt, "markdown", file, (line or 1) - 1)

    _SCRIPT_RE = re.compile(
        r"[\"']?((?:\$\{?[A-Z_]+\}?|~|\.{1,2}|/)?[\w./~${}-]*\.(?:sh|py|js|ts|rb|pl|zsh|bash|mjs|cjs))[\"']?"
    )

    def resolve_script(
        self, command: str, file: Path, origin: Path, plugin_root: Path | None, line: int | None
    ) -> None:
        """Find the script a command points at and scan its contents once."""
        # `node -e "<code>"` / `python -c "<code>"`: the argument is a program,
        # and any file name inside it is that program's business, not a path.
        if re.search(
            r"\b(?:node|python3?|ruby|perl|php|deno|bun)\s+(?:-\S+\s+)*(?:-e|-c|--eval|-p)\s", command
        ):
            self.add("info", "H-INLINE-CODE", file, line, "hook runs an inline program", command[:160])
            return
        m = self._SCRIPT_RE.search(command)
        if not m:
            return
        ref = m.group(1)
        resolved = (
            ref.replace("${CLAUDE_PLUGIN_ROOT}", str(plugin_root or origin))
            .replace("$CLAUDE_PLUGIN_ROOT", str(plugin_root or origin))
            .replace("${CLAUDE_PROJECT_DIR}", str(self.root))
            .replace("$CLAUDE_PROJECT_DIR", str(self.root))
        )
        if "$" in resolved:
            return
        candidates = (
            [Path(resolved).expanduser()]
            if resolved.startswith(("/", "~"))
            else [origin / resolved, (plugin_root or origin) / resolved, self.root / resolved]
        )
        for candidate in candidates:
            if candidate.is_file():
                target = candidate.resolve()
                if target in self._scripts_seen:
                    return
                self._scripts_seen.add(target)
                text = self.read(target)
                if text is not None:
                    self.result.scanned["scripts"] = self.result.scanned.get("scripts", 0) + 1
                    self.text_rules(text, "shell", target)
                return
        self.add(
            "low",
            "H-MISSING-SCRIPT",
            file,
            line,
            "the script this command points at is not in the checkout",
            ref,
        )

    # -- agents and skills ----------------------------------------------------
    def _frontmatter(self, path: Path) -> tuple[dict[str, Any], str, int] | None:
        text = self.read(path)
        if text is None:
            return None
        doc = split(text)
        if doc.error:
            self.add(
                "low",
                "F-BAD-FRONTMATTER",
                path,
                1,
                "frontmatter does not parse, Claude Code skips this file",
                doc.error[:160],
            )
        return (doc.meta or {}), doc.body, doc.body_line

    def scan_agent(self, path: Path) -> None:
        parsed = self._frontmatter(path)
        if parsed is None:
            return
        meta, body, body_line = parsed
        mode = meta.get("permissionMode")
        tools = tool_list(meta.get("tools"))
        if mode == "bypassPermissions":
            self.add(
                "critical",
                "A-BYPASS",
                path,
                1,
                "this agent runs with permission prompts switched off",
                f"permissionMode: {mode}; tools: {', '.join(tools) or 'all'}",
            )
        elif mode == "acceptEdits":
            self.add(
                "medium",
                "A-ACCEPT-EDITS",
                path,
                1,
                "file edits and filesystem commands need no approval",
                f"permissionMode: {mode}",
            )
        elif mode == "auto":
            self.add(
                "low",
                "A-AUTO",
                path,
                1,
                "a classifier, not you, approves this agent's commands",
                f"permissionMode: {mode}",
            )
        if not tools:
            self.add("info", "A-ALL-TOOLS", path, 1, "no tools list: inherits every tool of the session")
        for tool in tools:
            tags = classify_tool(tool)
            if "bash_any" in tags or "all_tools" in tags:
                self.add(
                    "low",
                    "A-BASH",
                    path,
                    1,
                    "may run shell commands (prompts still apply unless bypassed)",
                    tool,
                )
            elif tags & {"read_secret", "write_outside"}:
                self.add("medium", "A-FILE-SENSITIVE", path, 1, "file tools aimed outside the project", tool)
        if isinstance(meta.get("mcpServers"), dict):
            self.scan_mcp_obj(meta["mcpServers"], path, self.read(path) or "")
        if meta.get("hooks"):
            self.scan_hooks_obj(meta["hooks"], path, self.read(path) or "", path.parent, plugin_root_of(path))
        self.text_rules(body, "markdown", path, body_line - 1)

    _INLINE_SHELL_RE = re.compile(r"!`([^`\n]+)`|```!\s*\n(.*?)```", re.DOTALL)

    def scan_skill(self, path: Path) -> None:
        parsed = self._frontmatter(path)
        if parsed is None:
            return
        meta, body, body_line = parsed
        net = secrets = False
        for tool in tool_list(meta.get("allowed-tools")):
            tags = classify_tool(tool)
            self._grant_findings(tool, path, 1, prefix="S", what="allowed-tools pre-approves")
            net = net or bool(tags & {"bash_any", "bash_net", "bash_interp", "all_tools", "web"})
            secrets = secrets or "read_secret" in tags
        if meta.get("hooks"):
            self.scan_hooks_obj(meta["hooks"], path, self.read(path) or "", path.parent, plugin_root_of(path))
        for m in self._INLINE_SHELL_RE.finditer(body):
            command = (m.group(1) or m.group(2) or "").strip()
            line = body_line - 1 + body.count("\n", 0, m.start()) + 1
            self.add(
                "info",
                "S-INLINE-SHELL",
                path,
                line,
                "runs at invocation without a prompt (inline shell)",
                command[:160],
            )
            hits = self.text_rules(command, "shell", path, line - 1)
            net = net or any(h.rule.id in ("T-NETWORK", "T-EXFIL", "T-REMOTE-EXEC") for h in hits)
            secrets = secrets or any(h.rule.id == "T-SECRETS-READ" for h in hits)
        hits = self.text_rules(body, "markdown", path, body_line - 1)
        net = net or any(h.rule.id in ("T-EXFIL", "T-REMOTE-EXEC") for h in hits)
        secrets = secrets or any(h.rule.id == "T-SECRETS-READ" for h in hits)
        if net and secrets:
            self.add(
                "critical",
                "S-TRIFECTA",
                path,
                1,
                "reaches credentials and the network from one skill: the exfiltration shape",
            )

    # -- MCP ------------------------------------------------------------------
    def scan_mcp_file(self, path: Path) -> None:
        loaded = self.load_json(path)
        if not loaded or not isinstance(loaded[0], dict):
            return
        data, raw = loaded
        servers = data.get("mcpServers") if isinstance(data.get("mcpServers"), dict) else data
        self.scan_mcp_obj(servers, path, raw)

    def scan_mcp_obj(self, servers: Any, file: Path, raw: str) -> None:
        if not isinstance(servers, dict):
            return
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            line = _line_of(raw, f'"{name}"') or _line_of(raw, str(name))
            command, args = spec.get("command"), [str(a) for a in (spec.get("args") or [])]
            if isinstance(command, str) and command:
                full = " ".join([command, *args])
                self.add(
                    "info", "M-STDIO", file, line, f"MCP server '{name}' runs a local process", full[:160]
                )
                base = command.rsplit("/", 1)[-1]
                if base in ("sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh") and any(
                    a in ("-c", "/c", "-Command") for a in args
                ):
                    self.add(
                        "medium",
                        "M-SHELL",
                        file,
                        line,
                        f"MCP server '{name}' is an inline shell command",
                        full[:160],
                    )
                self.text_rules(full, "shell", file, (line or 1) - 1)
            url = spec.get("url")
            if isinstance(url, str) and url:
                parsed = urlparse(url)
                host = (parsed.hostname or "").lower()
                if parsed.scheme == "http" and host not in LOCAL_HOSTS:
                    self.add(
                        "high",
                        "M-HTTP-PLAIN",
                        file,
                        line,
                        f"MCP server '{name}' speaks plain HTTP to a remote host",
                        url[:160],
                    )
                else:
                    self.add("info", "M-REMOTE", file, line, f"MCP server '{name}' is remote", url[:160])
            env = spec.get("env")

            if not isinstance(env, dict):
                env = {}
            for key, value in env.items():
                value_s = str(value)
                if not value_s or PLACEHOLDER_RE.match(value_s):
                    continue
                if SECRET_VALUE_RE.match(value_s) or (SECRET_NAME_RE.search(key) and len(value_s) >= 12):
                    self.add(
                        "high",
                        "M-ENV-SECRET",
                        file,
                        line,
                        f"MCP server '{name}' carries a literal credential",
                        f"env.{key} = {mask(value_s)}",
                    )
            headers = spec.get("headers")

            if not isinstance(headers, dict):
                headers = {}
            for key, value in headers.items():
                value_s = str(value)
                if PLACEHOLDER_RE.match(value_s) or "${" in value_s:
                    continue
                if SECRET_VALUE_RE.search(value_s) or (
                    re.search(r"auth|token|key|secret", key, re.IGNORECASE) and len(value_s) >= 16
                ):
                    self.add(
                        "high",
                        "M-HEADER-TOKEN",
                        file,
                        line,
                        f"MCP server '{name}' carries a literal credential in a header",
                        f"{key}: {mask(value_s)}",
                    )

    # -- plugin manifest and markdown -----------------------------------------
    def scan_plugin_manifest(self, path: Path) -> None:
        loaded = self.load_json(path)
        if not loaded or not isinstance(loaded[0], dict):
            return
        data, raw = loaded
        root = path.parent.parent
        hooks = data.get("hooks")
        if isinstance(hooks, dict):
            self.scan_hooks_obj(hooks, path, raw, root, root)
        elif isinstance(hooks, str):
            target = root / hooks.replace("${CLAUDE_PLUGIN_ROOT}/", "")
            if target.is_file() and target.name != "hooks.json":  # hooks.json is walked on its own
                self.scan_hooks_file(target)
        servers = data.get("mcpServers")
        if isinstance(servers, dict):
            self.scan_mcp_obj(servers, path, raw)
        elif isinstance(servers, str):
            target = root / servers.replace("${CLAUDE_PLUGIN_ROOT}/", "")
            if target.is_file() and target.name != ".mcp.json":
                self.scan_mcp_file(target)

    def scan_markdown(self, path: Path) -> None:
        text = self.read(path)
        if text is None:
            return
        doc = split(text)
        self.text_rules(doc.body, "markdown", path, doc.body_line - 1)


def scan_path(path: Path) -> ScanResult:
    return Scanner(path).run()

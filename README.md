# ccscan

A static scanner for what a checkout asks Claude Code to do.

Clone a repo, install a plugin, or accept a marketplace, and Claude Code will read
its `.claude/` settings, hooks, agents, skills, commands, `.mcp.json`, plugin
manifest and `CLAUDE.md`. Some of that runs commands without asking. Some of it
pre-approves tools. Some of it is instructions to the model. `ccscan` reads the
same files and tells you, before you trust the folder.

No network, no execution: it parses and pattern-matches, then exits 1 when
anything at or above the threshold turned up.

## Install and run

```bash
uv tool install .            # or: uvx --from . ccscan
ccscan path/to/checkout      # text report, exit 1 on high or worse
ccscan . --json              # machine-readable
ccscan . --fail-on critical  # only stop the pipeline for critical
ccscan . --all               # include the info inventory
ccscan . --ignore T-NETWORK  # drop one rule
```

Point it at a repo, a plugin directory, a marketplace cache
(`~/.claude/plugins/marketplaces`), or a single file.

## What it reads

| Input | Where | What matters |
|---|---|---|
| `settings.json`, `settings.local.json`, `managed-settings.json` | `.claude/` | permission mode and grants, extra directories, MCP auto-approval, `env`, helper commands, hooks |
| `hooks.json` | plugin `hooks/` | every command hook, the script it points at, HTTP hooks and their headers |
| `*.md` | `agents/` | `permissionMode`, `tools`, inline `mcpServers` and `hooks`, the prompt body |
| `SKILL.md`, `commands/*.md` | skills | `allowed-tools` pre-approvals, inline `` !`shell` ``, frontmatter hooks, the body |
| `.mcp.json`, `plugin.json` | root, `.claude-plugin/` | stdio commands, unpinned registry packages, plain-HTTP servers, literal credentials |
| `CLAUDE.md`, `.claude/**/*.md` | root, `.claude/` | instruction text |

Hook handler scripts referenced by a hook (`${CLAUDE_PLUGIN_ROOT}/hooks/x.sh`) are
resolved and scanned too. Plugin READMEs and a skill's reference files are not
loaded by Claude Code on their own, so they are not scanned.

## Rules

Severity is the answer to one question: does this run on its own, or is it an
instruction to a model that still asks permission? The same `curl | sh` is
critical in a hook and high in a skill body.

**Grants** (settings `permissions.allow` → `P-ALLOW-*`, skill `allowed-tools` → `S-*`)

| Rule suffix | Severity | Trigger |
|---|---|---|
| `BASH-ANY`, `ALL-TOOLS` | high | `Bash`, `Bash(*)`, `*` |
| `DESTRUCTIVE` | high | `rm -r`/wildcards, `sudo`, `chmod`, `dd`, `crontab`, … |
| `SECRETS` | high | `Read(~/.ssh/*)`, `.env`, `.aws`, paths outside the project |
| `NET`, `INTERP`, `PUBLISH`, `WRITE-OUTSIDE`, `MCP-ALL` | medium | `curl`, `python`, `git push`, `Write(/etc/*)`, `mcp__*` |

**Settings**: `P-BYPASS-DEFAULT` (critical in user or managed settings, high in
project settings where it declares intent but cannot take effect), `P-EXTRA-DIRS`,
`P-ALL-MCP`, `P-ENV-REDIRECT` (`ANTHROPIC_BASE_URL`, proxies, TLS trust),
`P-ENV-SECRET`, `P-HELPER-COMMAND` (`apiKeyHelper`, `statusLine`, …).

**Agents**: `A-BYPASS` (critical), `A-ACCEPT-EDITS`, `A-AUTO`, `A-BASH`,
`A-FILE-SENSITIVE`, `A-ALL-TOOLS` (info).

**Skills**: the grants above, `S-INLINE-SHELL` (info, runs at invocation without a
prompt), `S-TRIFECTA` (critical: one skill reaches credentials and the network).

**Hooks**: `H-COMMAND` (info inventory), `H-HTTP`, `H-HTTP-TOKEN`, `H-HTTP-ENV`,
`H-TMP-PATH`, `H-MISSING-SCRIPT`, `H-PROMPT`.

**MCP**: `M-STDIO` (info), `M-SHELL`, `M-HTTP-PLAIN`, `M-ENV-SECRET`,
`M-HEADER-TOKEN`, `M-REMOTE` (info).

**Text**, on command lines and bodies: `T-REMOTE-EXEC` (`curl | sh`), `T-EXFIL`
(`curl -d`, webhooks, `/dev/tcp`), `T-SECRETS-READ`, `T-OBFUSCATION` (`base64 -d`,
`eval`), `T-DESTRUCTIVE`, `T-PERSISTENCE` (cron, launchd, shell rc files,
`~/.claude/`), `T-UNPINNED-EXEC` (`npx pkg` without a version, command lines
only), `T-INJECTION` ("ignore previous instructions", "do not tell the user"),
`T-COVERT`, `T-HIDDEN-TEXT` (zero-width and bidi characters), `T-HTML-COMMENT`,
`T-BLOB`, `T-NETWORK` (info).

Credential values are never printed; a finding shows `ghp_…(40 chars)`.

## Exit codes

`0` nothing at or above `--fail-on` (default `high`); `1` something was;
`2` a path did not exist.

## What it does not do

It does not run anything, fetch anything, or reason about intent. A skill that
documents `rm -rf` for a security audience reads the same as one that asks for
it, so the text rules skip lines that warn against a command or carry regex
escapes, and score markdown one notch below command lines. Treat the report as
a reading list, not a verdict. It knows nothing about MCP tool descriptions
(see mcp-scan for that) or about what a server does once connected.

## First run: the official plugin marketplace

Against the `claude-plugins-official` cache on 2026-09-06 (19 agents, 40
skills and commands, 16 MCP configs, 5 hook files, 8 handler scripts):

- 4 commands or skills pre-approve unrestricted `Bash` (`example-plugin`,
  `plugin-dev:create-plugin`, `pr-review-toolkit:review-pr`).
- 3 `.mcp.json` files run unpinned `npx` packages (`context7`, `firebase`,
  `playwright`).
- 1 command pre-approves `git push`.
- No hook pipes remote content into a shell, no config carries a credential.

## Design notes

- One `Finding` shape, one severity order, one renderer. Rules are data
  (`patterns.py`) plus a few predicates; the walker (`scan.py`) decides which
  file is which input and what context its text is in.
- Frontmatter goes through PyYAML; tool lists accept every shape the docs
  allow (comma string, space string, YAML list, bracketed string) and keep
  `Bash(git add *)` as one token.
- Field names come from the Claude Code docs for sub-agents, skills, hooks
  and the settings reference as of 2026-09.
- Tests are two fixture plugins, one malicious and one clean, plus unit cases
  for every parser and predicate, plus a smoke run over the local marketplace
  cache when present. `scripts/check.sh` is the gate: ruff, mypy strict, pytest.

# Skills

Task-specific playbooks for agents working in this repository. Each skill is a
folder with a `SKILL.md` that has YAML frontmatter (`name`, `description`) and a
body of rules, recipes, and validation commands.

The skills are ordinary Markdown. They do not add code or dependencies.

## Validate discovery

Run this after changing an entry point, skill, or mirror:

```sh
python3 scripts/validate-agent-setup.py
```

The check verifies skill frontmatter, the index, entry-point pointers, and the
Codex/OpenHands, Claude Code, and OpenCode skill symlinks. CI runs the same
command so missing or stale agent configuration is caught before merge.

## Loading a skill

Point your agent at the file, or place it where the agent discovers skills. The
canonical playbooks live in `skills/<name>/SKILL.md`; the agent-specific
directories are **relative symlinks** to the same folders, so there is only one
copy to maintain.

| Agent | Discovery path | Status |
| --- | --- | --- |
| Codex, OpenHands | `.agents/skills/<name>/SKILL.md` | Mirrored |
| OpenCode | `.opencode/skills/<name>/SKILL.md` | Mirrored |
| Claude Code | `.claude/skills/<name>/SKILL.md` | Mirrored |
| Codex, Devin CLI, Antigravity, OpenHands, Zed, Amp, Jules, Factory, Cursor | `AGENTS.md` | Supported directly |
| Claude Code, Gemini CLI, Aider, Copilot, Windsurf | root pointer file | See below |

Entry points for tools that use their own filenames or native rule directories
point back to `AGENTS.md`, so guidance does not drift:

| File | Tool |
| --- | --- |
| `CLAUDE.md` | Claude Code |
| `GEMINI.md` | Gemini CLI |
| `CONVENTIONS.md` | Aider |
| `.github/copilot-instructions.md` | GitHub Copilot |
| `.cursor/rules/oxsession.mdc` | Cursor rules |
| `.windsurfrules` | Windsurf |
| `.devin/rules/oxsession.md` | Devin CLI native rules |
| `.agents/rules/oxsession.md` | Antigravity native rules |
| `.clinerules/oxsession.md` | Cline |
| `.roo/rules/oxsession.md` | Roo Code |
| `.continue/rules/oxsession.md` | Continue |

DeepSeek provides code models rather than a documented repository-level agent
configuration format. For DeepSeek models used through an agent host, configure
that host to read `AGENTS.md`; compatible hosts can discover the shared
`.agents/skills/` mirrors. See the [provider integration notes](agents.md) for
the supported formats and upstream references.

Do not load every skill at once. Use the routing table in
[`../AGENTS.md`](../AGENTS.md) and load only what the task needs.

If a tool ignores symlinked skill directories, replace the symlinks with copies
or configure its skill path to point at `skills/`. Edit only `skills/`; the
mirrors are artifacts.

## Index

| Skill | Load when | Primary sources |
| --- | --- | --- |
| [`oxsession-core`](oxsession-core/SKILL.md) | Cookie parsing, `Set-Cookie`, `Bearer` vs cookie precedence, session model, core errors | `crates/oxsession-core/src/` |
| [`oxsession-sign`](oxsession-sign/SKILL.md) | HMAC cookies, key rotation, `os1.` wire format, signature failure behavior | `crates/oxsession-sign/src/` |
| [`oxsession-session`](oxsession-session/SKILL.md) | TTLs, sliding expiry, revocation, rotation, new `SessionStore` adapters | `crates/oxsession-session/src/` |
| [`oxsession-axum`](oxsession-axum/SKILL.md) | Axum extractors, request parts, 401/400 mapping, cookie header helpers | `crates/oxsession-axum/src/` |
| [`oxsession-server`](oxsession-server/SKILL.md) | Env configuration, routes, delivery modes, endpoint behavior | `crates/oxsession-server/src/` |
| [`oxsession-node`](oxsession-node/SKILL.md) | N-API implementation, JS façade, `.d.ts`, addon packaging | `crates/oxsession-node/` |
| [`oxsession-react`](oxsession-react/SKILL.md) | React/SPA integration, proxies, CORS, cookie vs token, deployment | `docs/react.md` |
| [`oxsession-devtool`](oxsession-devtool/SKILL.md) | Redacting CLI for cookie/credential/signature/id/policy inspection; debugging a 401; extending the CLI | `crates/oxsession-devtool/`, `docs/devtool.md` |
| [`oxsession-testing`](oxsession-testing/SKILL.md) | Choosing where a test belongs, adding regression tests, test commands | `crates/*/tests/`, `#[cfg(test)]` modules |

## Common combinations

- **Change a cookie rule:** `oxsession-core` → `oxsession-axum` → `oxsession-testing`.
- **Add a session store adapter:** `oxsession-session` → `oxsession-testing`, and
  read the conformance list in `docs/sessions.md`.
- **Change signature behavior:** `oxsession-sign` → `oxsession-server` (if the
  HTTP surface changes) → `oxsession-testing`.
- **Touch the HTTP surface:** `oxsession-server` → `oxsession-react` if a
  browser client consumes it → `oxsession-testing`.
- **Change the addon API:** `oxsession-node` → `oxsession-testing`.
- **Debug a bad credential or add an inspection command:** `oxsession-devtool` →
  `oxsession-core` or `oxsession-sign` if the underlying rule is wrong →
  `oxsession-testing`.

## Maintaining skills

When a change alters a workflow, a command, or a contract, update the matching
`SKILL.md` in the same change. Keep descriptions trigger-oriented: they are how
an agent decides whether to load the skill at all.

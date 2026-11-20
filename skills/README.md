# Skills

Task-specific playbooks for agents working in this repository. Each skill is a
folder with a `SKILL.md` that has YAML frontmatter (`name`, `description`) and a
body of rules, recipes, and validation commands.

The skills are ordinary Markdown. They do not add code or dependencies.

## Loading a skill

Point your agent at the file, or place it where the agent discovers skills:

- OpenCode: `.opencode/skills/<name>/SKILL.md` (project) or the global skills
  directory.
- Claude Code: `.claude/skills/<name>/SKILL.md`.
- Anything else: pass the path directly, or paste the body into the prompt.

Do not load every skill at once. Use the routing table in
[`../AGENTS.md`](../AGENTS.md) and load only what the task needs.

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

## Maintaining skills

When a change alters a workflow, a command, or a contract, update the matching
`SKILL.md` in the same change. Keep descriptions trigger-oriented: they are how
an agent decides whether to load the skill at all.

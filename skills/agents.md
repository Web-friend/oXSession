# Coding-agent integrations

The repository keeps shared engineering guidance in [`../AGENTS.md`](../AGENTS.md)
and task playbooks in [`README.md`](README.md) and its sibling skill folders.
Agent-specific files are short discovery adapters that point to those canonical
sources.

## Supported discovery paths

| Agent | Repository discovery |
| --- | --- |
| Codex | Root/nested `AGENTS.md`; skills in `.agents/skills/<name>/SKILL.md` |
| Devin CLI | `AGENTS.md`; native rule at `.devin/rules/oxsession.md` |
| Google Antigravity | `AGENTS.md`, `GEMINI.md`, `.agents/rules/oxsession.md`; skills in `.agents/skills/` |
| OpenHands | `AGENTS.md`; skills in `.agents/skills/<name>/SKILL.md` |
| Zed Agent | `AGENTS.md` |
| Claude Code | `CLAUDE.md`; skills in `.claude/skills/<name>/SKILL.md` |
| OpenCode | `AGENTS.md`; skills in `.opencode/skills/<name>/SKILL.md` |
| Cline | `AGENTS.md` and `.clinerules/oxsession.md` |
| Roo Code | `.roo/rules/oxsession.md` |
| Continue | `.continue/rules/oxsession.md` |
| Cursor | `.cursor/rules/oxsession.mdc` and `AGENTS.md` |
| Gemini CLI | `GEMINI.md` |
| Aider | `CONVENTIONS.md` |
| GitHub Copilot | `.github/copilot-instructions.md` |
| Windsurf | `.windsurfrules` |

Devin CLI, Antigravity, Cline, Roo Code, and Continue adapters contain no
independent policy; each directs the agent back to the canonical instructions
and skills. This keeps the tool-specific discovery mechanism without
duplicating the repository's rules.

### DeepSeek models

DeepSeek publishes code models, not a repository-aware coding-agent product
with its own documented instruction-file convention. Use `AGENTS.md` and
`.agents/skills/` when the selected host (for example, Codex or OpenHands)
supports them, or configure the host's own project instructions to load
`AGENTS.md`. Support depends on the host, not the model provider.

## Upstream documentation

- [OpenAI Codex: AGENTS.md discovery](https://developers.openai.com/codex/guides/agents-md)
- [OpenAI Codex: skills](https://developers.openai.com/codex/skills)
- [Devin CLI: rules and AGENTS.md](https://docs.devin.ai/cli/extensibility/rules.md)
- [Google Antigravity: rules and customization discovery](https://antigravity.google/docs/customization-discovery)
- [OpenHands: repository context](https://docs.openhands.dev/overview/skills/repo.md)
- [Zed: project instructions](https://zed.dev/docs/ai/instructions.md)
- [Claude Code: memory and rules](https://docs.anthropic.com/en/docs/claude-code/memory)
- [OpenCode: rules](https://opencode.ai/docs/rules/)
- [Cline: rules](https://docs.cline.bot/customization/cline-rules)
- [Roo Code: custom instructions](https://roocodeinc.github.io/Roo-Code/features/custom-instructions/)
- [Continue: rules](https://docs.continue.dev/customize/rules)
- [Cursor: project rules](https://docs.cursor.com/context/rules)
- [Gemini CLI: GEMINI.md context files](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/gemini-md.md)
- [Aider: CONVENTIONS.md](https://aider.chat/docs/usage/conventions.html)
- [GitHub Copilot: repository custom instructions](https://docs.github.com/en/copilot/customizing-copilot/adding-repository-custom-instructions-for-github-copilot)
- [Windsurf: rules](https://docs.windsurf.com/windsurf/cascade/memories#rules)
- [DeepSeek Coder](https://github.com/deepseek-ai/DeepSeek-Coder)

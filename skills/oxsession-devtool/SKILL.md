---
name: oxsession-devtool
description: Inspect oXSession cookies, credentials, signed values, session-id shape, and policy with the redacting `oxsession-devtool` CLI in crates/oxsession-devtool. Use when debugging a 401, checking an os1 signature, validating TTL/cookie configuration, extending the CLI, or deciding whether an agent should get an MCP tool instead.
---

# `oxsession-devtool`

A local, read-only inspector. It prints JSON, redacts credentials by default,
and never touches a session store.

Full command reference and examples: [`docs/devtool.md`](../../docs/devtool.md).

## When to use it

| Question | Command |
| --- | --- |
| Did the client send a cookie/bearer credential? | `resolve-credential` |
| Why did the header parser skip or drop pairs? | `parse-cookie` |
| Is this `os1.` value authentic, and under which key id? | `check-cookie` |
| Is this id the right length/alphabet? | `inspect-id` |
| Are these TTLs and this cookie name legal? | `policy` |
| Does the session exist/expire in the store? | **Not the devtool** — inspect the store or add a test |

Run it from the workspace:

```sh
cargo run -p oxsession-devtool -- <command> [options]
```

## Invariants to preserve

1. **Read-only.** No `mint`, `validate` (against a store), `refresh`, `rotate`,
   or `revoke`. If a request needs one of those, it is a library or server task,
   not a devtool task.
2. **Redaction is the default.** New output fields that can carry an id, token,
   key, or payload must be `null` unless an explicit `--reveal*` flag is set, and
   must carry a sibling `*_redacted: true`.
3. **Sanitized errors.** Use the library's `ErrorCategory` mapping. Never print
   which check failed beyond the category — no "bad mac" vs "unknown key id"
   split.
4. **No ambient secrets.** The tool reads keys only from `--key`/`--key-file`.
   Do not read `AUTH_COOKIE_KEYS`, dotenv files, or the process environment.
5. **Exit codes are API.** `0` positive, `1` negative answer, `2` usage, `3`
   configuration/IO. Do not return `1` for a crash or `0` for a negative answer.
6. **JSON on stdout, diagnostics on stderr.** One object per run, so callers can
   pipe to `jq` or assert in tests.

## Adding a command

1. Add the name and options to `USAGE` in `crates/oxsession-devtool/src/main.rs`.
2. Add the dispatch arm in `run`.
3. Validate options with `reject_unknown` before doing any work.
4. Keep computation in a pure helper that returns `(Value, bool)` or a typed
   result, so it is unit-testable without capturing stdout. `policy_report` is
   the model to copy.
5. Return `Ok(ExitCode::SUCCESS)` or `Ok(ExitCode::from(1))`; reserve
   `CliError::{Usage, Configuration}` for `2` and `3`.
6. Add unit tests in the `#[cfg(test)]` module for parsing, redaction, and the
   negative path.
7. Update `docs/devtool.md` and the `USAGE` text in the same change. Do not
   create a second source of truth for flags.

## Rules of thumb

- Reuse the library for behavior: `Pairs::parse`, `resolve`, `SessionId::new`,
  `Policy::new`, `CookieSigner::verify`. The devtool must not reimplement a
  parser or a signature check.
- A new dependency needs a reason. The crate intentionally avoids `clap` and
  `anyhow`; the hand-rolled parser is ~60 lines and testable.
- Prefer `--key-file` examples in docs over `--key`; argv leaks into shell
  history and the process list.
- If output grows a value that the model will see, ask whether it is
  credential-bearing. If yes, redact and document the flag that reveals it.

## Validation

```sh
cargo fmt --all -- --check
cargo test -p oxsession-devtool
cargo test --workspace
```

Because the binary has no library surface, `cargo doc` has nothing to check
there; run `cargo doc --workspace --no-deps` anyway when the workspace changed.

## MCP decision

Do not add an MCP server for this. See the "Why not MCP?" section of
`docs/devtool.md`. If a concrete non-shell client appears, mirror the read-only
operations over stdio with the same redaction and the same sanitized categories;
do not add mutating tools.

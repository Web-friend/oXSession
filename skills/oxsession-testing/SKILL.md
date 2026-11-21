---
name: oxsession-testing
description: Choose where an oXSession test belongs, add regression coverage, and run the validation suite. Use when writing tests for cookie parsing, signing, session expiry, HTTP endpoints, or preparing a change for review.
---

# Testing oXSession

Tests live at the lowest layer that can prove the rule, plus one end-to-end test
when the HTTP surface changes. Security properties are tested as behavior, not
as implementation details.

## Commands

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo doc --workspace --no-deps

cargo test -p oxsession-core
cargo test -p oxsession-sign
cargo test -p oxsession-session
cargo test -p oxsession-axum
cargo test -p oxsession-server

npm run build --prefix crates/oxsession-node
node --check crates/oxsession-node/index.js
```

`cargo clippy` is not installed. Do not claim it was run.

## Where a test belongs

| Rule under test | Crate | Location |
| --- | --- | --- |
| Cookie grammar, limits, quoting, duplicates | core | `#[cfg(test)] mod tests` in `src/cookies.rs` |
| Credential precedence, Bearer scheme rejection | core | `src/credentials.rs` |
| `Set-Cookie` attributes and prefix rules | core | `src/set_cookie.rs` |
| Session id shape and redaction | core | `src/session.rs` |
| `os1` format, tamper matrix, rotation, name binding | sign | `src/lib.rs` + `tests/interop.rs` |
| TTL sliding, absolute cap, revoke, rotate | session | `src/manager.rs` |
| Eviction, capacity, poisoning | session | `src/memory.rs` |
| Extractor behavior, signing helper | axum | `tests/credentials.rs`, `tests/signed.rs` |
| Status codes, headers, delivery modes, logout | server | `tests/sessions.rs` |
| Addon API and error codes | node | Playwright suite in sibling `React Demo Project`; build + `node --check` |

If a rule is observable through HTTP and also unit-testable, test it in both
places only when the mapping itself is the risk (for example, `Ambiguous` →
`400`).

## Patterns already in the repo

**In-file unit tests.** Every core/sign/session module has a private `tests`
module. Use it for rules that need private constructors or exact failure
variants.

**Explicit time.** Session tests pass `now: u64`; `short_config()` in the server
uses `Policy::new(2, 100)`. Sleep only when the wall clock is the subject
(the `/me` cookie-refresh tests sleep one second).

**Interop vector.** `crates/oxsession-sign/tests/interop.rs` is the authority for
wire compatibility. A format change must update the vector, the Python reference
in `docs/signing.md`, and the tamper matrix together.

**End-to-end with `oneshot`.** `crates/oxsession-server/tests/sessions.rs` calls
the router directly, no socket:

```rust
let reply = call(app, "POST", "/sessions", Some(r#"{"subject":"user-1"}"#), None).await;
assert_eq!(reply.status, StatusCode::CREATED);
assert!(reply.set_cookie.as_deref().unwrap().starts_with("session="));
```

Helpers available there:

- `call`, `call_bearer`, `call_both` — optional cookie and/or bearer token.
- `Reply` — status, `set-cookie`, `cache-control`, `pragma`, body.
- `short_config()`, `short_app()`, `short_app_with(delivery)`.
- `signed_app()` — deterministic key.
- `RevokeFailsStore` — injects a failing `delete`.
- `field(body, name)` / `field_u64(body, name)` — tiny JSON extraction.

**Failure injection.** Implement `SessionStore` in the test with an
`AtomicBool`/failing method. Do not add test hooks to production types.

## Security regression checklist

Add a test when a change touches any of these:

- Duplicate credential cookie → `400`, not last-one-wins.
- Non-`Bearer` authorization scheme → `401`, no cookie fallback.
- Signature failure variants → identical `401` body (no oracle).
- A value signed for `session` rejected as `admin`.
- Expired id deleted before the error (`get` afterwards returns `None`).
- Sliding expiry cannot pass `issued_at + absolute_ttl`.
- `touch` returning `false` becomes `NotFound`, not a resurrected session.
- Token mode does not parse cookies; a duplicate cookie stays `401`, not `400`.
- Every credential/session response is `Cache-Control: no-store` (including
  errors, `/logout`, and `/sessions`).
- `/logout` revokes a credential the mode rejects for `/me`.
- A signed cookie is not accepted as a bearer token.
- Session ids and key bytes never appear in `Display` output.

## Adding an endpoint test

1. Build the router with the narrowest config that proves the rule
   (`short_app_with(...)`, `signed_app()`, or a custom `AppState`).
2. Make the request through the helpers; do not bind a socket.
3. Assert status, the specific header(s), and the body shape.
4. Assert the negative case in the same test when it is cheap (for example,
   token mode: mint returns `session_id` **and** sets no cookie).
5. Keep the test independent: no shared mutable state outside the router.

## Adding a store conformance test

Write the seven rules from `docs/sessions.md` against your adapter and reuse the
`MemoryStore` tests as the template. The shared conformance suite does not exist
yet; do not claim your adapter is conformant without the equivalents.

## Known gaps

- No CI. Nothing runs these commands automatically.
- `oxsession-node` has no crate-local runtime suite. The sibling React demo
  exercises the addon through its Node HTTP API with Playwright and Podman.
- No fuzzing for `Pairs::parse` or the signed-value parser.
- No `cargo audit`/`cargo deny` configuration.
- No benchmarks.

## Pitfalls

- Do not assert on struct `Debug` for sessions; it is redacted on purpose.
- Do not hard-code a session id except as an obviously invalid short value.
- Do not use `unwrap()` on a `Result` whose failure is the behavior under test.
- Do not add a test-only method to a production trait.
- Do not update a test to match a regression. If a security assertion fails,
  fix the code or argue explicitly that the rule changed.

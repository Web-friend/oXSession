# AGENTS.md

Guidance for coding agents working in this repository. Read this first, then
load the skill that matches the task.

## What this repository is

`oxsession` is a Rust workspace that implements platform-agnostic
authentication primitives: Cookie header parsing, `Set-Cookie` serialization,
`Bearer`/cookie credential resolution, HMAC-signed cookie values, opaque
server-side sessions with a `SessionStore` trait, an Axum adapter, a standalone
HTTP server, and a Node.js N-API addon.

The point of the architecture is a hard dependency rule, not a folder layout.
Read it before editing anything:

```
oxsession-core      ← no dependencies, no frameworks, no I/O policy
  ↑
oxsession-sign      ← HMAC over core's cookie grammar
  ↑
oxsession-session   ← lifecycle + MemoryStore over core's SessionStore trait
  ↑
oxsession-axum      ← request parts → core types → HTTP responses
  ↑
oxsession-server    ← env config + routes + delivery policy
oxsession-node      ← N-API bindings over core/sign/session
```

`oxsession-core` must never gain a dependency on Axum, Tokio, SQL, or
`std::env`. If a change requires one of those, it belongs in an adapter, not in
core.

## Read order

1. `README.md` — contract, delivery modes, configuration, endpoints.
2. `docs/sessions.md` — session lifecycle, cookie attributes, store conformance.
3. `docs/signing.md` — signed-cookie wire format, test vector, Python reference.
4. `docs/react.md` — browser/React integration, proxy, deployment, pitfalls.
5. `logs.md` — current status and known gaps. Treat it as a status snapshot, not
   as truth about behavior: two entries are stale (see below).
6. `skills/<name>/SKILL.md` — the task-specific playbook.

## Repository map

| Path | Crate | Owns | Skill |
| --- | --- | --- | --- |
| `crates/oxsession-core` | `oxsession-core` | `Pairs`, `SetCookie`, `Credentials`, `Session` model, `SessionStore` trait, core errors | `oxsession-core` |
| `crates/oxsession-sign` | `oxsession-sign` | `CookieSigner`, key ring, `os1.` wire format | `oxsession-sign` |
| `crates/oxsession-session` | `oxsession-session` | `SessionManager`, `Policy`, `MemoryStore` | `oxsession-session` |
| `crates/oxsession-axum` | `oxsession-axum` | `CookieHeader`, `bearer`, `signed_cookie`, `AuthError`, cookie header helpers | `oxsession-axum` |
| `crates/oxsession-server` | `oxsession-server` | env `Config`, `AppState`, `/health`, `/me`, `/sessions`, `/logout` | `oxsession-server` |
| `crates/oxsession-node` | `oxsession-node` | N-API exports, CommonJS façade, `.d.ts`, package build | `oxsession-node` |
| `docs/` | — | Behavioral contracts and the React guide | — |
| `examples/` | — | `localstorage.js`, a token-mode browser client | `oxsession-react` |
| `skills/` | — | Agent playbooks | `skills/README.md` |

Tracked scratch files `src/cookies_rwx.rs` and `src/handler.rs` are **not** part
of the workspace and never compile. Do not extend, import, or copy them.

## Hard rules

1. **Keep the dependency direction.** Core stays dependency-free. Adapters map
   types; they do not re-implement parsing, signing, or storage rules.
2. **Wire formats are public contracts.** Cookie grammar, the 43-char base64url
   session id, and `os1.<keyid>.<payload>.<mac>` are consumed by non-Rust
   clients. A change needs tests, a version bump if the format changes, and a
   docs update.
3. **Never log or expose credentials.** Session ids and signing keys are bearer
   material. `Debug` for `SessionId` and `SecretKey` is redacted on purpose.
   Error categories are sanitized on purpose. Do not add a "helpful" detail that
   reveals which check failed.
4. **No verification oracle.** Every signature failure maps to the same client
   response (`401 authentication required`). `BadMac` and `UnknownKey` must stay
   indistinguishable over HTTP and over the Node API.
5. **Time is an argument, not a global.** Below the HTTP handler, lifecycle code
   takes `now: u64`. Do not call `SystemTime::now()` inside the store or manager
   except through the exported `now()` helper at the edge.
6. **Public items need docs.** Every crate sets `#![warn(missing_docs)]`. New
   public items need doc comments; `cargo doc --workspace --no-deps` must stay
   clean.
7. **Tests live at the lowest layer that can prove the rule**, plus an
   end-to-end test in `crates/oxsession-server/tests/sessions.rs` when the HTTP
   surface changes.
8. **Keep documentation in sync.** `README.md` config/endpoint tables,
   `docs/*.md`, and the relevant `SKILL.md` are part of the change, not
   follow-up work.

## Commands

```sh
# Formatting and tests (run both before claiming done)
cargo fmt --all -- --check
cargo test --workspace

# Documentation build
cargo doc --workspace --no-deps

# Run the server for manual checks
AUTH_DEV_LOGIN=1 AUTH_SESSION_DELIVERY=cookie AUTH_SESSION_COOKIE_SECURE=0 \
  cargo run -p oxsession-server

# Node addon build (Rust toolchain required) and syntax checks
npm run build --prefix crates/oxsession-node
node --check crates/oxsession-node/index.js

# Focused test runs
cargo test -p oxsession-core
cargo test -p oxsession-sign
cargo test -p oxsession-session
cargo test -p oxsession-axum
cargo test -p oxsession-server
```

`cargo clippy` is not installed in this project's dev toolchain and is not part
of any workflow. `cargo check`/`cargo test` are the available gates.

Generated artifacts (`target/`, `crates/oxsession-node/oxsession.node`,
`node_modules/`) are git-ignored. Do not commit them.

## Task routing

| Task | Start with | Then read |
| --- | --- | --- |
| Cookie parsing, `Set-Cookie`, credential precedence | `oxsession-core` | `docs/sessions.md` |
| HMAC format, key rotation, signature failures | `oxsession-sign` | `docs/signing.md` |
| Session TTLs, sliding expiry, a new `SessionStore` | `oxsession-session` | `docs/sessions.md` |
| Axum extractors, 401/400 mapping | `oxsession-axum` | `crates/oxsession-server/src/routes.rs` |
| Env vars, endpoints, delivery modes | `oxsession-server` | `README.md` |
| Browser/React client, CORS, proxies | `oxsession-react` | `docs/react.md` |
| N-API exports, JS façade, `.d.ts` | `oxsession-node` | `crates/oxsession-node/README.md` |
| Adding or fixing tests | `oxsession-testing` | the crate's existing test modules |

## Definition of done

- `cargo fmt --all -- --check` and `cargo test --workspace` pass.
- The rule is tested where it lives; HTTP-visible behavior has an endpoint test.
- Public Rust items are documented and `cargo doc` is clean.
- `README.md` is updated if configuration, endpoints, or delivery changed.
- `docs/*.md` is updated if a contract changed.
- The matching `SKILL.md` is updated if the workflow changed.
- No session ids, key bytes, or unsanitized error details appear in logs, error
  messages, tests, or fixtures.

## Known gaps and stale notes

`logs.md` is the status log. Keep it updated when you close a gap. Two entries
are already stale relative to the code:

- "Sliding expiry does not refresh the cookie" — **fixed**.
  `routes.rs` re-issues `Set-Cookie` on every cookie-authenticated `/me`.
- "`__Host-` / `__Secure-` names fail at request time" — **fixed**.
  `Config::from_env` rejects the prefix/`Secure` mismatch at startup.

Still true and worth remembering: no OIDC, no durable store, no CORS layer, no
TLS, no rate limiting, plain-text error bodies, unbuilt adapter conformance
suite, and `purge_expired` has no scheduler.

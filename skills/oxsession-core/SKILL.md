---
name: oxsession-core
description: Change or debug the framework-agnostic layer in crates/oxsession-core — Cookie header parsing, Set-Cookie serialization, Bearer/cookie credential resolution, the session model, the SessionStore trait, and core error categories. Use for any work in oxsession-core or for behavior every adapter must share.
---

# oXSession Core

`oxsession-core` is the contract every other crate depends on. It has **zero
dependencies** and deliberately knows nothing about Axum, Tokio, SQL, or
environment variables.

## Files

| File | Contents |
| --- | --- |
| `src/lib.rs` | Re-exports; the public surface |
| `src/cookies.rs` | `Pairs`, `Pair`, `Stats`, `Ambiguous`, parser limits |
| `src/credentials.rs` | `Credentials`, `resolve` |
| `src/set_cookie.rs` | `SetCookie`, `SetCookieBuilder`, `SameSite`, `Prefix` |
| `src/session.rs` | `Session`, `SessionId`, `SessionStore`, id limits |
| `src/error.rs` | `Error`, `ErrorCategory` |

## Non-negotiable invariants

- **Zero dependencies.** Do not add `axum`, `tokio`, `serde`, `base64`, or
  anything else. If a task seems to need one, the code belongs in another crate.
- **Parsing must never panic.** Input is attacker-controlled bytes. Index only
  after a length check; no `unwrap()`/slicing on untrusted offsets.
- **No percent-decoding.** Cookie values are raw cookie-octets. Tokens are
  expected to be base64url so no encoding layer exists.
- **Names are case-sensitive.** Do not normalize.
- **No silent resolution.** A duplicate credential cookie is an error
  (`Ambiguous`), never last-one-wins.
- **Bearer is explicit and wins.** When an `Authorization` header is present it
  is authoritative; a non-`Bearer` scheme is rejected, never downgraded to a
  cookie.

## Parser limits and rules

| Limit | Value |
| --- | --- |
| Header bytes | `MAX_COOKIE_HEADER_BYTES = 8 * 1024` |
| Pairs per header | `MAX_COOKIE_PAIRS = 128` |

`Pairs` is created from **one joined header**. Callers must join multiple
`Cookie` headers with `"; "` (RFC 6265 §5.4) before parsing; the Axum adapter
does this in `CookieHeader`.

Behavior to preserve:

- Quoted values are unquoted; surrounding optional whitespace is trimmed.
- Non-empty segments that are not valid `name=value` are skipped and counted in
  `Stats::skipped`.
- Reaching the pair limit sets `Stats::truncated`.
- Oversized headers set `Stats::too_long` and read nothing.
- `get_unique` returns `Ambiguous::Duplicate`, `Ambiguous::Truncated`, or
  `Ambiguous::HeaderTooLong` rather than guessing.

## API cheat sheet

```rust
use oxsession_core::{Pairs, SetCookie, SameSite, resolve};

let pairs = Pairs::parse(b"theme=dark; session=abc");
assert_eq!(pairs.get("session"), Some("abc"));
let stats = pairs.stats();                    // pairs / skipped / truncated / too_long

let credential = resolve(None, &pairs, "session")?; // Credentials::Cookie("abc")

let cookie = SetCookie::builder("session", "abc")?
    .path("/")
    .http_only()
    .same_site(SameSite::Lax)
    .max_age(604_800)
    .build()?;
let wire = cookie.encode();
```

`SetCookie::new` only handles attribute-less cookies. Anything with `Path`,
`Domain`, `Max-Age`, `Secure`, `HttpOnly`, or `SameSite` goes through
`SetCookie::builder`. `__Host-` names therefore always require the builder.

Enforced at build time:

- `__Host-` requires `Secure`, `Path=/`, and no `Domain`.
- `__Secure-` requires `Secure`.
- `SameSite=None` requires `Secure`.
- `Path` must be absolute.

## Session model

```rust
pub trait SessionStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn insert(&self, session: Session) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn get(&self, id: &SessionId) -> impl Future<Output = Result<Option<Session>, Self::Error>> + Send;
    fn touch(&self, id: &SessionId, expires_at: u64) -> impl Future<Output = Result<bool, Self::Error>> + Send;
    fn delete(&self, id: &SessionId) -> impl Future<Output = Result<bool, Self::Error>> + Send;
    fn delete_expired(&self, now: u64) -> impl Future<Output = Result<usize, Self::Error>> + Send;
}
```

- Return-position `impl Future`, no `async-trait`, no runtime dependency.
- `SessionId` is 16–128 bytes (`MIN_SESSION_ID_BYTES`/`MAX_SESSION_ID_BYTES`);
  generated ids are 32 random bytes as 43-char unpadded base64url.
- `SessionId` redacts itself in `Debug`. Do not add a way to print it.
- `Session::is_expired(now)` is inclusive: `now >= expires_at` is expired.

## Error categories

`Error::category()` gives language bindings a stable, sanitized class:

| Variant | Category |
| --- | --- |
| `Unauthenticated` | `MissingCredential` |
| `Ambiguous(_)` | `AmbiguousCredential` |
| everything else | `InvalidInput` |

Adding a variant means updating `category()`, `Display`, every adapter mapping,
and the Node addon's `OxsessionErrorCode` if it is reachable there.

## Recipes

**Add a parser rule or limit.** Change `cookies.rs`, extend the in-file
`#[cfg(test)] mod tests`, and check that `Stats` and `Ambiguous` still describe
the failure. Update `docs/sessions.md` if the wire contract changed.

**Add a `Set-Cookie` attribute.** Add the field and builder method, enforce the
rule in policy validation (not only at serialization), add tests for accept and
reject, and document the attribute in `docs/sessions.md`.

**Change credential precedence.** Edit `resolve` in `credentials.rs` and both
its unit tests and `crates/oxsession-axum/tests/credentials.rs`. Precedence is a
platform contract, so update `README.md` too.

**Extend the session model.** Add accessors, keep fields private, and check
`MemoryStore` and `SessionManager` still compile without new allocation in the
hot path.

## Validation

```sh
cargo test -p oxsession-core
cargo test --workspace          # adapters depend on this crate
cargo doc -p oxsession-core --no-deps
```

## Pitfalls

- Do not join headers here. `Pairs::parse` takes exactly one header value.
- Do not trim cookie names.
- Do not turn `Ambiguous` into `Unauthenticated`; adapters map them to different
  status codes (`400` vs `401`) on purpose.
- Do not add a `Domain` default. The absence of `Domain` is a security property.
- Do not introduce `String` allocations in the parser; it borrows from the
  request bytes.

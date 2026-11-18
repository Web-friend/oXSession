# logs

Running status log for oXSession. What is built, what is missing, and what is
known to be inconsistent.

Last updated: 2026-11-18, after `ba32011`.
All commits below are on `main`; the working tree is clean.

## Snapshot

| | |
| --- | --- |
| Crates | 5 — `core`, `sign`, `session`, `axum`, `server` |
| Framework/DB assumptions in core | none (zero dependencies) |
| Tests | 124 (122 unit/integration + 2 doctests), 0 warnings |
| Aux deps | `axum` only in the adapter and binary |
| Licence | MIT |
| Persistence | in-memory only |
| Identity provider | none (`POST /sessions` behind `AUTH_DEV_LOGIN`) |

```
cargo test --workspace      # 124 passed
cargo fmt --all --check     # clean
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps   # clean
```

## Done

### Transport layer — `oxsession-core`

- [x] `Cookie` header parsing that can never panic: 8 KiB per joined header,
      128 pairs, duplicate names reported rather than resolved.
- [x] Quoted values unquoted, optional whitespace trimmed, malformed pairs
      skipped, names case-sensitive.
- [x] `Set-Cookie` serialization with `__Host-` / `__Secure-` /
      `SameSite=None` prefix rules enforced at build time.
- [x] Credential resolution: `Authorization: Bearer` beats the cookie; a
      non-`Bearer` scheme is rejected, never downgraded to the cookie.
- [x] Values are not percent-encoded; a value must already be cookie-octets.
- [x] `is_valid_name` / `is_valid_value` exported for adapters.
- [x] Tested: 31 unit tests.

### Signed cookies — `oxsession-sign`

- [x] Wire format `os1.<keyid>.<payload>.<mac>`, HMAC-SHA256, unpadded
      base64url MAC (43 chars).
- [x] The **cookie name is inside the MAC**, so a `session` value cannot be
      replayed as `admin`.
- [x] `verify` is zero-copy, constant-time (`subtle`), and never falls back to
      the raw value on failure.
- [x] Key ring: one current key plus at most `MAX_PREVIOUS_KEYS = 2` retired
      keys; unknown key ids are rejected outright.
- [x] Keys are exactly 32 bytes, `Zeroizing`, redacted `Debug`,
      `SecretKey::from_base64url` for configuration.
- [x] Limits: 4096-byte wire value, key id `[A-Za-z0-9_-]{1,16}`, payload must
      be non-empty cookie-octets with no `.`.
- [x] Published interop vector + 6-line Python reference in
      [`docs/signing.md`](docs/signing.md).
- [x] Tested: 8 unit + 10 interop tests (vector, tamper matrix, rotation,
      name binding, size limits).

### Sessions — `oxsession-core` (model) + `oxsession-session` (policy/store)

- [x] Opaque, server-side sessions: 32 bytes from the OS RNG, 43-char
      base64url id, no claims in the credential.
- [x] `SessionId` redacts itself in `Debug` output.
- [x] `SessionStore` trait: `insert`, `get`, `touch`, `delete`, `delete_expired`
      — async via return-position `impl Future`, no `async-trait`, no tokio.
- [x] `SessionManager`: idle TTL refreshed on use, absolute cap that activity
      cannot extend, expired ids deleted *before* the `401`.
- [x] `revoke`, `rotate` (new id, old id killed), `purge_expired`.
- [x] Time passed in as `now: u64`; nothing reads the clock below the handler.
- [x] `Policy` rejects `ttl == 0` and `absolute_ttl < ttl`.
- [x] `MemoryStore` reference adapter: capacity-bounded, evicts the session
      closest to expiry, explicitly documented as not durable.
- [x] Tested: 17 manager/store tests + 4 model tests inside core.

### HTTP surface — `oxsession-axum` + `oxsession-server`

- [x] `CookieHeader` extractor; `signed_cookie`; `AuthError` enum for
      credential vs. signature failures.
- [x] One `401` for every signature failure — no verification oracle.
- [x] `GET /health`, `GET /me`, `POST /sessions` (dev only), `POST /logout`.
- [x] `POST /sessions` mints, sets `HttpOnly; SameSite=Lax; Path=/` and optional
      `Secure`, with `Max-Age` = idle TTL.
- [x] `POST /logout` revokes whatever credential it can identify (even one the
      current mode rejects for auth) and clears the cookie.
- [x] Delivery modes via `AUTH_SESSION_DELIVERY`:
      `cookie` (default), `token` (raw id in body, no cookie issued **and none
      accepted, cookie carrier not even parsed**), `both` (migration).
- [x] `Cache-Control: no-store` + `Pragma: no-cache` on mint, `/me` success,
      `/me` errors, and `/logout`.
- [x] Signed mode verifies the HMAC before the store lookup, so forged cookies
      cost a MAC, not a query.
- [x] Config validation for bind addr, port, cookie name, TTLs, key material,
      delivery mode; `AUTH_DEV_LOGIN` prints a startup warning.
- [x] Graceful shutdown on Ctrl+C / SIGTERM.
- [x] `lib.rs` + `AppState` so the router is testable without binding a socket.
- [x] Tested: 12 config/route unit tests, 26 end-to-end endpoint tests, 8 + 7
      adapter tests.

### Documentation

- [x] `README.md`: contract, layout, delivery matrix, configuration table,
      endpoints, roadmap.
- [x] [`docs/signing.md`](docs/signing.md): wire format, test vector, Python
      reference, rotation, "not encryption".
- [x] [`docs/sessions.md`](docs/sessions.md): lifecycle, cookie attributes,
      delivery, adapter conformance rules, non-goals.
- [x] [`examples/localstorage.js`](examples/localstorage.js): browser client
      using `localStorage` + Bearer.

## Missing

### Correctness / security gaps (fix before calling it production-ready)

- [ ] **Sliding expiry does not refresh the cookie.** `Max-Age` is fixed at
      mint time (`policy.ttl()`), while the stored `expires_at` slides forward
      on every `/me`. An active browser is logged out on day 7 even though the
      session row is still valid. `/me` should re-issue the cookie (and re-sign
      it) whenever `expires_at` moved.
- [ ] **`__Host-` / `__Secure-` names fail at request time, not startup.**
      `AUTH_SESSION_COOKIE=__Host-session` with `AUTH_SESSION_COOKIE_SECURE`
      unset validates as a name, then `SetCookie::build` fails inside
      `/sessions` and returns `500`. Config should reject the combination at
      load.
- [ ] **`Secure` is not enforced.** Default is off so `http://localhost` works,
      but nothing warns or refuses when the bind address is non-loopback. A
      deployment on a public address silently ships cookies in clear text.
- [ ] **No CSRF/origin check.** Cookie mode relies on `SameSite=Lax` and
      `no-store` only. Same-site subdomain attackers and clients that override
      `SameSite` are not covered.
- [ ] **`purge_expired` is never called.** `MemoryStore` is bounded by capacity,
      so nothing leaks today, but a durable adapter needs a sweep or a TTL
      index, and the manager exposes the hook with no scheduler.
- [ ] **`logout` swallows revocation failures.** A store error is logged and the
      cookie is still cleared, so the client believes it logged out while the
      server-side session survives until expiry.
- [ ] **`rotate` can leave two live sessions.** It creates the replacement
      *then* deletes the old id; a failed delete leaves both valid. Delete-first
      or unconditional replacement is safer.
- [ ] **Duplicate key ids are accepted in `AUTH_COOKIE_KEYS`.**
      `CookieSigner::with_previous` never checks the id against the current or
      retired keys, so `k1:new,k1:old` silently makes old cookies fail with
      `BadMac` instead of failing configuration.
- [ ] **Secrets live in environment variables.** `AUTH_COOKIE_KEYS` is visible
      in `/proc/<pid>/environ`, `docker inspect`, and shell history. No
      file/secret-manager loader.
- [ ] **No TLS.** The binary speaks plain HTTP and assumes a proxy. Nothing in
      the docs states that requirement.
- [ ] **No rate limiting.** `POST /sessions` (when dev-login is on) and
      `/logout` are unthrottled; `MemoryStore` eviction means a session flood
      can evict other users' sessions.
- [ ] **Unbounded subject length.** Only empty/whitespace subjects are rejected;
      a multi-megabyte subject is stored as-is.

### Platform breadth

- [ ] Durable `SessionStore` adapters: PostgreSQL (next), SQLite, Redis.
- [ ] Shared **adapter conformance suite** — `docs/sessions.md` lists seven
      rules every adapter must satisfy, but no test crate enforces them. Any new
      adapter is currently unverifiable.
- [ ] Generic OIDC provider with Google preset, PKCE, `state`/`nonce`, and
      callback routes. This is what makes `POST /sessions` unnecessary.
- [ ] JWT issuance with a JWKS endpoint and key rotation.
- [ ] Sealed (encrypted) cookies — `os2`. Signing is authenticity only; the
      payload is readable by the client.
- [ ] Additional adapters: Actix, Hyper, serverless.
- [ ] Runtime key rotation / secret reload without a restart.

### Observability and operations

- [ ] Structured logging. The server uses 7 `println!`/`eprintln!` sites;
      no `tracing`, no request ids, no session id redaction policy beyond
      `Debug`.
- [ ] `/health` is liveness only. No readiness probe that touches the store or
      the signer.
- [ ] Metrics: login, validation, expiry, signature-failure counters. Right now
      a spike in forged cookies is invisible.
- [ ] No graceful session drain on shutdown and no startup sweep.

### API polish

- [ ] Error responses are `text/plain`. Clients must branch on status codes;
      there is no JSON error envelope.
- [ ] `ApiError::Invalid` has no production constructor — dead until request
      validation exists.
- [ ] `SessionDelivery` is a public enum without `#[non_exhaustive]`, so adding
      a mode is a breaking change.
- [ ] `MemoryStore::len()` panics on a poisoned lock while the trait methods
      return `MemoryStoreError::Poisoned`. Pick one behaviour.
- [ ] No `Set-Cookie` re-issue path for key rotation, so clients only pick up a
      new key on re-login.

### Project hygiene

- [ ] No CI. Nothing runs `fmt`, `clippy`, `test`, `doc` on push.
- [ ] `cargo clippy` is not installed in the dev toolchain and is not part of any
      workflow; only rustc/build warnings are checked today.
- [ ] No fuzzing for `Pairs::parse` or `format::parse`; both are hand-written
      parsers over attacker-controlled bytes.
- [ ] No `cargo audit` / `cargo deny` configuration.
- [ ] Root `src/cookies_rwx.rs` and `src/handler.rs` are tracked scratch files.
      The workspace has no root package, so they never compile. Delete after
      confirming they are not wanted.
- [ ] Crate metadata lacks `repository`, `homepage`, `documentation`,
      `keywords`, `categories`, `readme` — `cargo publish` would produce sparse
      crates.io pages.
- [ ] No `CHANGELOG.md`, `SECURITY.md`, or `CONTRIBUTING.md`.
- [ ] No benchmarks for the parser or the manager.
- [ ] `base64` and `getrandom` are pinned inside `oxsession-session` instead of
      `[workspace.dependencies]`, unlike everything else.

## Known inconsistencies

| Symptom | Cause |
| --- | --- |
| `/me` returns a new `expires_at` but the browser cookie still expires on the original schedule | sliding expiry is store-side; `/me` never re-issues `Set-Cookie` |
| Config accepts `__Host-` names that cannot be serialized | prefix rules are checked in `SetCookie::build`, not in `Config::from_env` |
| `both` mode sets a cookie *and* a token that decode to the same id, but only the cookie is signed | signature wraps the carrier, not the id — by design |
| `AUTH_COOKIE_KEYS=k1:a,k1:b` loads successfully but rejects half the cookies | `with_previous` does not check id uniqueness |
| A failed logout still returns `204` and clears the cookie | revocation errors are logged, not surfaced |

## Next steps, in order

1. Fix the four correctness items that can bite in production: cookie
   re-issue on sliding expiry, startup validation of cookie prefixes and
   `Secure`, enforced `Secure` outside loopback, and delete-before-create in
   `rotate`.
2. Start the adapter conformance suite, then implement PostgreSQL against it.
3. Schedule `purge_expired` (or document that the adapter owns sweeping).
4. Replace `println!`/`eprintln!` with `tracing` and add request ids.
5. OIDC, so `POST /sessions` stops being the only way in.
6. CI (fmt, clippy, test, doc, audit) plus a fuzz target for both parsers.

## Verification log

```
$ cargo test --workspace
oxsession-axum     unit 3   credentials 8   signed 7
oxsession-core     unit 31
oxsession-server   unit 12  bin 0   sessions 26
oxsession-session  unit 17  doctest 1
oxsession-sign     unit 8   interop 10  doctest 1
                                     total 124 passed, 0 failed

$ cargo build --workspace          # 0 warnings
$ RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps   # clean
$ node --check examples/localstorage.js                        # ok
```

Live smoke checks that pass today:

```
token mode   create -> 201, session_id in body, no Set-Cookie, no-store
             /me bearer 200 | /me cookie 401 | duplicate cookie 401
             logout with cookie -> 204, then bearer 401
both mode    create -> 201 + signed Set-Cookie + session_id
cookie mode  create -> 201 + Set-Cookie, no session_id
             duplicate cookie -> 400 ambiguous
```

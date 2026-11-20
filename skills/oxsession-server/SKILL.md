---
name: oxsession-server
description: Modify or debug the standalone HTTP server in crates/oxsession-server — environment configuration, the /health /me /sessions /logout routes, credential delivery modes, cookie issuance, and endpoint error mapping. Use for server behavior, config validation, or HTTP-level tests.
---

# oXSession Server

The binary is a thin wrapper. `config.rs` reads the environment, `routes.rs`
builds the router, `state.rs` assembles state, and `main.rs` binds and serves.
Only this crate reads environment variables.

## Files

| File | Contents |
| --- | --- |
| `src/config.rs` | `Config`, `SessionDelivery`, env parsing and startup validation |
| `src/routes.rs` | Router, handlers, `ApiError`, cookie issuance |
| `src/state.rs` | `AppState<S>`, `MemoryAppState` |
| `src/lib.rs` | Module exports for tests and reuse |
| `src/main.rs` | Bind, graceful shutdown, startup warnings |
| `tests/sessions.rs` | End-to-end endpoint tests |

## Endpoints

| Route | Success | Notes |
| --- | --- | --- |
| `GET /health` | `200 {"status":"ok"}` | Public, no credential, no side effects |
| `POST /sessions` | `201` + body and/or `Set-Cookie` | `404` unless `AUTH_DEV_LOGIN`; `400` for an empty subject |
| `GET /me` | `200 {"subject","expires_at","source"}` | `source` is `"cookie"` or `"bearer"` |
| `POST /logout` | `204` + deletion cookie | Revokes any identifiable credential |

Every response that may carry a credential, or that describes a session, gets
`Cache-Control: no-store` and `Pragma: no-cache` — including `/me` errors,
`/logout`, and the mint response.

### `POST /sessions` body

```jsonc
// cookie mode (default)
{"subject":"user-1","expires_at":1763510400}

// token or both mode
{"subject":"user-1","expires_at":1763510400,"session_id":"<43-char raw id>"}
```

The body value is always the **raw id**, never the `os1.…` signed wire value.
Signing protects the cookie carrier only.

### Delivery modes

| `AUTH_SESSION_DELIVERY` | Sends `Set-Cookie` | Accepts cookie on read | Returns `session_id` |
| --- | --- | --- | --- |
| `cookie` (default) | yes | yes | no |
| `token` | no | **no** (cookie is not even parsed) | yes |
| `both` | yes | yes | yes |

`Bearer` is accepted in every mode. In token mode, a cookie presented to `/me`
is a `401`, not a downgrade, and its contents cannot change the status code.

### Cookie issuance

- `Path=/`, `HttpOnly`, `SameSite=Lax`, `Max-Age=<idle ttl>`, optional `Secure`.
- `Domain` is never set (host-only).
- `/me` re-issues `Set-Cookie` when `source == Cookie` **and** the mode sends
  cookies, with `Max-Age = expires_at - now`. This keeps the browser's deadline
  tracking sliding expiry. Bearer and token-mode requests do not re-issue.
- `/logout` always sends `session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`,
  even when no credential was identified.

### Logout semantics

- Revocation uses `credential()`, which ignores the delivery policy, so a cookie
  rejected by token-mode `/me` can still be killed.
- A revocation failure is surfaced as `500` and the cookie is **not** cleared,
  so the client can retry instead of believing it logged out.
- With no credential, logout still returns `204` and clears the cookie.

## Configuration

`Config` fields: `bind_address`, `session_cookie`, `policy`,
`session_cookie_secure`, `dev_login`, `session_delivery`, `signer`.

| Variable | Default | Validation |
| --- | --- | --- |
| `AUTH_BIND_ADDR` | `127.0.0.1` | Must parse as `IpAddr` |
| `AUTH_PORT` | `3000` | `1..=65535` |
| `AUTH_SESSION_COOKIE` | `session` | RFC 7230 token; `__Host-`/`__Secure-` require `Secure` |
| `AUTH_SESSION_TTL_SECONDS` | `604800` | `> 0` and `<= absolute` |
| `AUTH_SESSION_ABSOLUTE_TTL_SECONDS` | `2592000` | `>= ttl` |
| `AUTH_SESSION_COOKIE_SECURE` | off | Required for non-loopback binds and prefixed names |
| `AUTH_DEV_LOGIN` | off | Truthy: `1`, `true`, `yes` |
| `AUTH_SESSION_DELIVERY` | `cookie` | `cookie`, `token`, `both` (trimmed, case-insensitive) |
| `AUTH_COOKIE_KEYS` | unset | `keyid:base64url,...`; first signs, rest verify |

**No dotenv loading.** `Config::from_env` reads the process environment only.

Startup must fail for: unparsable bind/port, invalid cookie name, `ttl == 0`,
`absolute < ttl`, bad keys, bad delivery value, prefix without `Secure`, and a
non-loopback bind without `Secure`.

## Error mapping (`ApiError`)

| Case | Status | Body |
| --- | --- | --- |
| `AuthError` (missing/ambiguous/signature) | `401` or `400` | See `oxsession-axum` |
| `SessionError::NotFound` / `Expired` | `401` | `authentication required` |
| `SessionError::InvalidSubject` | `400` | `subject must not be empty` |
| `SessionError::SubjectTooLong` | `400` | `subject exceeds the 1024-byte limit` |
| `SessionError::Store` / `Entropy` | `500` | `internal server error` (detail logged) |
| `ApiError::NotFound` | `404` | `not found` |
| `ApiError::Invalid` | `400` | the message |
| `ApiError::Internal` | `500` | `internal server error` (detail logged) |

Bodies are `text/plain`, not JSON. Any JSON-extractor rejection is Axum's own:
`415` for a missing/wrong content type, `422` for a missing field, `400` for
invalid JSON.

## Recipes

**Add an environment variable.** Add a `Config` field, parse it in
`from_env` with a clear error, validate cross-field rules, add a test using the
`EnvVar` guard in `config.rs`, document it in `README.md`'s configuration table,
and mention it in `docs/react.md` if a browser client must set it.

**Add or change a route.** Update `router`, keep `no_store` on any response that
may carry a credential, map errors through `ApiError`, add an end-to-end test in
`tests/sessions.rs`, and update the endpoint table in `README.md`. If a browser
consumes it, update `docs/react.md` and the `oxsession-react` skill.

**Change delivery behavior.** Update `SessionDelivery::{sends_cookie,
sends_token, accepts_cookie}`, the handlers, the delivery matrix in `README.md`
and `docs/sessions.md`, and the mode-specific endpoint tests.

**Swap the store.** `AppState<S: SessionStore>` is already generic. Build with
`router_with_state(AppState::new(config, my_store))`; add an endpoint test.

## Testing

`tests/sessions.rs` drives the router with `tower::ServiceExt::oneshot`, no
socket. Helpers:

- `call`, `call_bearer`, `call_both` — build requests with optional cookie and
  bearer token.
- `Reply` — captures status, `set-cookie`, `cache-control`, `pragma`, body.
- `short_config()` — `Policy::new(2, 100)` for expiry tests.
- `signed_app()` — config with a deterministic signer.
- `RevokeFailsStore` — injects a failing `delete` to test logout error handling.

When adding a test, prefer asserting the observable contract: status, headers,
cookie prefix (`session=` / `session=os1.k1.`), and the presence or absence of
`session_id` in the body.

## Run manually

```sh
AUTH_DEV_LOGIN=1 \
AUTH_SESSION_DELIVERY=cookie \
AUTH_SESSION_COOKIE=session \
AUTH_SESSION_COOKIE_SECURE=0 \
cargo run -p oxsession-server
```

## Known limits

No CORS/`OPTIONS`, no static file serving, no TLS, no rate limiting, no
structured logging, no readiness check against the store, no JSON error
envelope. `MemoryStore` is process-local and lost on restart. Do not document
these as available; `logs.md` tracks them.

## Pitfalls

- Do not read `env::var` in a handler or in any crate below the server.
- Do not let token mode parse the cookie; the "not even parsed" property is
  deliberate and tested.
- Do not clear the cookie when revocation fails.
- Do not drop `no_store` from an error path.
- Do not add a `Vary: Cookie`-only defense; cookie-authenticated responses are
  uncacheable precisely because a shared cache could ignore `Vary`.
- Do not log `SessionId`; log the error category instead.

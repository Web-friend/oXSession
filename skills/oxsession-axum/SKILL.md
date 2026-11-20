---
name: oxsession-axum
description: Modify the Axum integration in crates/oxsession-axum — CookieHeader extraction, Bearer helpers, signed_cookie verification, and AuthError to HTTP status mapping. Use for extractor work, request-part plumbing, or adapter-level error responses.
---

# oXSession Axum Adapter

This crate is deliberately thin. It turns request parts into `oxsession-core`
types and maps errors back into HTTP responses. Parsing, signing, and storage
rules do **not** belong here.

## Files

| File | Contents |
| --- | --- |
| `src/lib.rs` | `CookieHeader`, `bearer`, `signed_cookie`, `AuthError`, `set_cookie`, `append_set_cookie` |
| `tests/credentials.rs` | Extractor and credential-precedence coverage |
| `tests/signed.rs` | Signed-cookie verification coverage |

## Public API

```rust
use oxsession_axum::{CookieHeader, AuthError, bearer, signed_cookie, append_set_cookie};

// Never fails: a missing Cookie header becomes an empty value.
async fn handler(cookies: CookieHeader, headers: HeaderMap) -> Result<Response, AuthError> {
    let pairs = cookies.pairs();                       // borrowed view
    let credentials = cookies.credentials(&headers, "session")?;
    let token = credentials.token();

    // Only when signing is configured:
    let payload = signed_cookie(&cookies, &signer, "session")?; // Option<&str>
    // …
}
```

- `CookieHeader::from_headers(&HeaderMap)` joins **all** `Cookie` headers with
  `"; "` before parsing.
- `CookieHeader::credentials(&HeaderMap, name)` delegates to
  `oxsession_core::resolve`, so `Bearer` precedence and duplicate-cookie
  detection are identical everywhere.
- `bearer(&HeaderMap)` returns the raw `Authorization` value only if it is
  visible ASCII. It does not parse the scheme.
- `signed_cookie` returns `Ok(None)` when the cookie is absent; ambiguous or
  invalid signatures are errors, never a raw fallback.
- `set_cookie` / `append_set_cookie` serialize a validated `SetCookie`.

## Error mapping (contract)

| Failure | Status | Body |
| --- | --- | --- |
| `Error::Unauthenticated` | `401` | `authentication required` |
| any `SignError` (unknown key, bad MAC, malformed) | `401` | `authentication required` |
| `Error::Ambiguous(_)` | `400` | `ambiguous credential cookie` |
| any other core error | `400` | `malformed credentials` |

Two rules:

1. **Signature failures share one response.** `BadMac` and `UnknownKey` must be
   indistinguishable to clients. Never add a diagnostic body.
2. **`Ambiguous` stays distinct from `Unauthenticated`.** A duplicate credential
   cookie is the client's fault (`400`), not a missing login (`401`).

`AuthError::reason()` exists for server-side logging; never return it to a
client.

## What belongs elsewhere

- Environment variables and `Config` → `oxsession-server`.
- Session creation/validation policy → `oxsession-session`.
- Cookie grammar and `Set-Cookie` rules → `oxsession-core`.
- Endpoint routing and response bodies → `oxsession-server`.

If you find yourself parsing a cookie string here, stop and use `Pairs`.

## Recipes

**Add an extractor or helper.** Keep it a pure mapping over request parts. Add a
doctest or a test in `tests/credentials.rs`, and check the same behavior is
covered end-to-end in the server when it affects status codes.

**Change a status mapping.** Update `AuthError::into_response`, the table above,
the server's `ApiError`, `docs/react.md` (the client branches on status), and the
endpoint tests in `crates/oxsession-server/tests/sessions.rs`.

**Support a new framing detail (for example, a trusted header from a proxy).**
Do it in the server, not here, unless it is a general request-part mapping.
Do not accept a credential from a header the browser can spoof.

## Validation

```sh
cargo test -p oxsession-axum
cargo test -p oxsession-server      # status mapping is exercised end-to-end
```

## Pitfalls

- Do not add a `FromRequestParts` impl that can panic on malformed input.
- Do not read only the first `Cookie` header; join them.
- Do not lowercase cookie names.
- Do not expose `AuthError::reason()` in a response body.
- Do not implement signing verification inline; use `signed_cookie`.
- Do not turn `400` cases into `401` for "simplicity"; clients rely on the
  distinction.

# oXSession

A platform-agnostic authentication toolkit for Rust: sessions, cookies, and
credentials behind interfaces that do not assume a framework, a database, or a
deployment model.

The project is at the transport layer today. Cookie parsing, `Set-Cookie`
serialization, and credential resolution are implemented and tested; storage,
OIDC providers, and JWT issuance are next.

## Layout

| Crate | Knows about | Must not know about |
| --- | --- | --- |
| [`oxsession-core`](crates/oxsession-core) | `Cookie`/`Set-Cookie` wire format, credential resolution, errors | Axum, tokio, SQL, environment variables |
| [`oxsession-sign`](crates/oxsession-sign) | HMAC-SHA256 signatures, key ids, rotation | Axum, storage, environment variables |
| [`oxsession-axum`](crates/oxsession-axum) | Request parts, HTTP status mapping | Parsing and signing rules (delegates to core/sign) |
| [`oxsession-server`](crates/oxsession-server) | Environment configuration, serving | Anything below the adapter |

The rule that keeps this honest: **core never sees a `HeaderMap`, a `Router`, a
`Pool`, or `env::var`.** Every framework, database, and provider is an adapter,
so a second integration cannot drift away from the first.

## The credential contract

Every integration — Rust or not — follows the same rules, which is what makes
this a platform rather than one application's auth code.

**Reading a request**

- A client presents either `Authorization: Bearer <token>` or a session cookie.
- `Authorization` wins when present. A non-`Bearer` scheme is rejected, never
  silently downgraded to the cookie.
- All `Cookie` headers are joined with `"; "` before parsing (RFC 6265 §5.4).
- A credential cookie name appearing more than once is an error, not a
  last-one-wins coin flip.
- Names are case-sensitive; quoted values are unquoted; surrounding optional
  whitespace is trimmed; pairs that break the grammar are skipped.
- Limits: 8 KiB per header, 128 pairs per header.

**Writing a cookie**

- Values are not percent-encoded. A value must already consist of
  cookie-octets, so tokens should be base64url — the same bytes are then valid
  in every language that talks to the service.
- `__Host-` names require `Secure`, `Path=/`, and no `Domain`.
- `__Secure-` names require `Secure`.
- `SameSite=None` requires `Secure`.
- `Path` must be absolute.

## Signed cookies (opt-in)

Signing is a policy decision, not a transport rule: preferences stay unsigned,
session cookies can be signed. Pass the cookies that matter through a signer.

```rust
use oxsession_sign::{CookieSigner, KeyId, SecretKey};

let signer = CookieSigner::new(
    KeyId::new("k1")?,
    SecretKey::from_slice(&key_bytes)?,      // exactly 32 bytes, zeroized on drop
);

let wire = signer.sign("session", "dXNlcj00Mg")?;   // "os1.k1.dXNlcj00Mg.<mac>"
let payload = signer.verify("session", &wire)?;     // bound to the cookie name
```

On Axum, read and verify in one step:

```rust
let payload = oxsession_axum::signed_cookie(&cookies, &signer, "session")?;
```

| Property | Detail |
| --- | --- |
| Format | `os1.<keyid>.<payload>.<mac>`, HMAC-SHA256 |
| Binding | The cookie **name** is signed, so a `session` value cannot be replayed as `admin` |
| Rotation | Key id travels in the value; up to 2 retired keys keep verifying |
| Failure | Unsigned, tampered, foreign-name, and unknown-key values are all rejected |
| Limits | 4096-byte signed value, payload must be cookie-octets with no `.` |

Signing is **not encryption**: the payload is readable by the client. The wire
format, a test vector, and a 6-line Python reference implementation live in
[`docs/signing.md`](docs/signing.md).

## Run

```sh
cargo run -p oxsession-server
```

The server listens on `127.0.0.1:3000` by default.

```sh
curl http://127.0.0.1:3000/health
curl -H 'Cookie: session=abc123' http://127.0.0.1:3000/me
curl -H 'Authorization: Bearer tok_123' http://127.0.0.1:3000/me
```

| Endpoint | Response |
| --- | --- |
| `GET /health` | `200 {"status":"ok"}` |
| `GET /me` | `200 {"source":"cookie"\|"bearer"}`, `401` without credentials, `400` with an ambiguous cookie |

`/me` proves the transport contract only: it reports *which* credential the
client presented and never echoes the token. Resolving the token to a session is
the next slice.

## Configuration

The library is configured programmatically. Only the optional server binary
reads the environment:

| Variable | Default | Description |
| --- | --- | --- |
| `AUTH_BIND_ADDR` | `127.0.0.1` | IP address to bind to |
| `AUTH_PORT` | `3000` | TCP port to listen on (1–65535) |
| `AUTH_SESSION_COOKIE` | `session` | Cookie name holding the session token |
| `AUTH_COOKIE_KEYS` | unset | `keyid:base64url,keyid:base64url,...`, first entry signs, the rest verify. Unset means session cookies are read as opaque tokens |

No dotenv files are loaded.

## Test

```sh
cargo test --workspace
```

35 tests cover the parser's edge cases (quoted values, malformed pairs, duplicate
names, size and pair limits), prefix rules, credential precedence, and the
adapter end-to-end through a real router. The signing suite adds the published
wire vector, tampering matrix, name-binding and rotation cases.

## Roadmap

1. Session model and storage traits (`Store`, `SessionStore`) with a
   conformance suite every adapter must pass.
2. PostgreSQL adapter, then SQLite, behind the same traits.
3. Generic OIDC with Google as a preset, including PKCE and `state` handling.
4. JWT issuance with a JWKS endpoint and key rotation.
5. Sealed (encrypted) cookies — signed cookies already ship in `oxsession-sign`.
6. Additional adapters (Actix, Hyper, serverless).

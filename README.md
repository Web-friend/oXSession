# oXSession

A platform-agnostic authentication toolkit for Rust: sessions, cookies, and
credentials behind interfaces that do not assume a framework, a database, or a
deployment model.

The project has working sessions today: cookie and credential handling, HMAC
signing, a session store contract with an in-memory adapter, and a server that
mints and validates real sessions. OIDC providers and JWT issuance come next.

## Layout

| Crate | Knows about | Must not know about |
| --- | --- | --- |
| [`oxsession-core`](crates/oxsession-core) | `Cookie`/`Set-Cookie` wire format, credentials, session model and `SessionStore` trait, errors | Axum, tokio, SQL, environment variables |
| [`oxsession-sign`](crates/oxsession-sign) | HMAC-SHA256 signatures, key ids, rotation | Axum, storage, environment variables |
| [`oxsession-session`](crates/oxsession-session) | Session lifecycle policy, the in-memory store | Axum, HTTP, environment variables |
| [`oxsession-axum`](crates/oxsession-axum) | Request parts, HTTP status mapping | Parsing, signing, and storage rules |
| [`oxsession-server`](crates/oxsession-server) | Environment configuration, routes, session delivery, serving | Anything below the adapter |

The rule that keeps this honest: **core never sees a `HeaderMap`, a `Router`, a
`Pool`, or `env::var`.** Every framework, database, and provider is an adapter,
so a second integration cannot drift away from the first.

## The credential contract

Every integration — Rust or not — follows the same rules, which is what makes
this a platform rather than one application's auth code.

**Reading a request**

- A client presents either `Authorization: Bearer <session-id>` or a session cookie.
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

## Sessions

Sessions are **opaque and server-side**: the client holds a random id, the
server holds the subject. No claims travel in the cookie, so revocation is
immediate and there is nothing to decrypt.

| Property | Detail |
| --- | --- |
| Id | 32 random bytes, unpadded base64url (43 chars), generated via the OS RNG |
| Lookup | `SessionStore::get`, with the manager enforcing expiry |
| Idle lifetime | 7 days by default, refreshed on every valid use |
| Absolute lifetime | 30 days by default, never extended by activity |
| Expiry handling | An expired id is deleted before `401` is returned, so it cannot be kept alive by retries |
| Logout | `SessionStore::delete`; the cookie is cleared in the same response |
| Rotation | `SessionManager::rotate` mints a new id and kills the old one (use after privilege changes) |

The storage contract is a trait, so the store is swappable:

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

`oxsession-session` ships `MemoryStore`, the reference adapter: complete,
dependency-free, process-local, and explicitly **not** durable. When full it
evicts the session closest to expiry, so memory is bounded; a production
deployment needs a durable adapter with the same contract.

`SessionId` is a credential, so its `Debug` output is redacted — leaking a
session id into a log line is a login.
Subjects are limited to 1,024 UTF-8 bytes. The session error categories expose
invalid input, missing or expired sessions, entropy failure, and storage failure
without including backend details in public error text.

### Future Node.js addon

The planned N-API wrapper (with `napi-rs` as the default binding approach) will
expose cookie parsing, credential resolution, signing and verification, and
session create, validate, revoke, and rotate. Its first version will own a Rust
`MemoryStore`, which is process-local and non-durable: sessions are lost on
restart and are not shared across processes. Persistent stores and JavaScript
store callbacks are outside this initial boundary. See
[`docs/sessions.md`](docs/sessions.md) for the operation and error contract.

### Delivering the credential

The session id is a bearer credential either way; delivery only decides which
carrier the client should look at.

| `AUTH_SESSION_DELIVERY` | `POST /sessions` returns | Cookie accepted on read? | Use when |
| --- | --- | --- | --- |
| `cookie` (default) | `Set-Cookie` only | yes | Server-rendered apps, or any client that can hold a cookie. Scripts cannot read the id |
| `token` | `{"session_id":"…"}` in the body, `Cache-Control: no-store`, no cookie | no | Browser apps keeping the id in `localStorage`, mobile apps, CLIs |
| `both` | both carriers | yes | Migrating one client type at a time |

`token` is a token-only deployment: it issues no cookie **and accepts none**, so
no ambient credential can ride along on a cross-site request. A cookie presented
in that mode is a `401`, not a downgrade, and the cookie is never even parsed —
a duplicate or malformed one cannot change the status code or cost a signature
check. Bearer is accepted in every mode, because it is a credential the caller
chooses to send rather than one a browser attaches on its own.

Logout is the exception: it revokes whatever credential is presented, including a
cookie that token mode would refuse to authenticate, so an id can always be
killed instead of lingering until it expires. The client must still drop its own
`localStorage` entry; the server cannot reach it.

Responses that may carry a credential or describe a session — `/me` success and
error alike, `/logout`, and the mint response — are sent with
`Cache-Control: no-store` and `Pragma: no-cache`. A cookie-authenticated response
has no `Vary: Cookie`, so a shared cache storing it would hand one user's subject
to another, and HTTP/1.0 intermediaries ignore `Cache-Control`.

Putting the id in `localStorage` means JavaScript can read it, so an XSS bug is
a session theft — the exact thing an `HttpOnly` cookie prevents. The trade is
that nothing is sent automatically, so cross-site requests carry no ambient
credential. See [`examples/localstorage.js`](examples/localstorage.js) for a
working client:

```js
const session = await (await fetch("/sessions", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ subject: "user-1" }),
})).json();

localStorage.setItem("oxsession.session", session.session_id);

await fetch("/me", {
  headers: { authorization: `Bearer ${localStorage.getItem("oxsession.session")}` },
});
```

The bearer channel is also why signed cookies protect less than they appear to:
a client holding the raw id bypasses the signature check entirely, because the
id is the credential. Signing defends the cookie carrier against forgery and
name replay, not the token.

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

Signing the session id makes tampering detectable before a store lookup, which
turns most forged cookies into a cheap `401` instead of a database query. It is
not a replacement for server-side validation: a valid signature is not a valid
session.

Signing is **not encryption**: the payload is readable by the client. The wire
format, a test vector, and a 6-line Python reference implementation live in
[`docs/signing.md`](docs/signing.md).

## Run

```sh
AUTH_DEV_LOGIN=1 cargo run -p oxsession-server
```

The server listens on `127.0.0.1:3000` by default. To serve browser clients that
use `localStorage`, add `AUTH_SESSION_DELIVERY=token` and read `session_id` from
the `POST /sessions` body.

```sh
curl http://127.0.0.1:3000/health

# Mint a session (development only; requires AUTH_DEV_LOGIN=1)
curl -c jar.txt -H 'content-type: application/json' \
     -d '{"subject":"user-1"}' http://127.0.0.1:3000/sessions

curl -b jar.txt http://127.0.0.1:3000/me
curl -b jar.txt -X POST http://127.0.0.1:3000/logout

# Bearer clients use the same session id
curl -H 'Authorization: Bearer <session-id>' http://127.0.0.1:3000/me
```

| Endpoint | Response |
| --- | --- |
| `GET /health` | `200 {"status":"ok"}` |
| `GET /me` | `200 {"subject":"...","expires_at":...,"source":"cookie"\|"bearer"}`, `401` for a missing, unknown, expired, or forged session |
| `POST /sessions` | `201` + `Set-Cookie` (cookie delivery) or `201 {"session_id":"…"}` (token delivery); `404` unless `AUTH_DEV_LOGIN=1`; `400` for an empty subject |
| `POST /logout` | `204` + cookie deletion; revokes the session when it can be identified |

`/sessions` exists because there is no identity provider yet. It trusts any
subject and is therefore off by default.

## Configuration

The library is configured programmatically. Only the optional server binary
reads the environment:

| Variable | Default | Description |
| --- | --- | --- |
| `AUTH_BIND_ADDR` | `127.0.0.1` | IP address to bind to |
| `AUTH_PORT` | `3000` | TCP port to listen on (1–65535) |
| `AUTH_SESSION_COOKIE` | `session` | Cookie name holding the session id |
| `AUTH_SESSION_TTL_SECONDS` | `604800` | Idle lifetime, refreshed on use |
| `AUTH_SESSION_ABSOLUTE_TTL_SECONDS` | `2592000` | Lifetime cap from creation |
| `AUTH_SESSION_COOKIE_SECURE` | off | Send the cookie with `Secure`. Required outside `localhost` |
| `AUTH_DEV_LOGIN` | off | Enables `POST /sessions` |
| `AUTH_SESSION_DELIVERY` | `cookie` | `cookie`, `token`, or `both`; see [Delivering the credential](#delivering-the-credential) |
| `AUTH_COOKIE_KEYS` | unset | `keyid:base64url,keyid:base64url,...`; first entry signs, the rest verify. Unset means the session id travels unsigned |

Generate a signing key:

```sh
python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))"
```

No dotenv files are loaded.

## Test

```sh
cargo test --workspace
```

124 tests cover the parser's edge cases (quoted values, malformed pairs,
duplicate names, size and pair limits), prefix rules, credential precedence,
the published signing vector and tampering matrix, session expiry and sliding,
store eviction, every delivery mode, and the endpoints end-to-end through a real
router.

## Roadmap

1. ~~Session model and `SessionStore` trait~~ — done, with an in-memory adapter.
2. PostgreSQL adapter, then SQLite, behind the same trait. Adapters must pass a
   shared conformance suite.
3. Generic OIDC with Google as a preset, including PKCE and `state` handling.
4. JWT issuance with a JWKS endpoint and key rotation.
5. Sealed (encrypted) cookies — signed cookies already ship in `oxsession-sign`.
6. Additional adapters (Actix, Hyper, serverless).

Current status, known gaps, and inconsistencies are tracked in
[`logs.md`](logs.md).

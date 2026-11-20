# Sessions

## Model

A session is an opaque id plus the subject it belongs to. Nothing else travels
to the client: no claims, no role, no expiry timestamp. That keeps revocation
immediate — the server's word is the only word.

```rust
pub struct Session {
    id: SessionId,     // 32 random bytes, base64url, 43 chars
    subject: String,   // caller-defined, e.g. a user id
    issued_at: u64,    // Unix seconds
    expires_at: u64,   // Unix seconds, refreshed on use
}
```

`SessionId` redacts itself in `Debug` output. Treat `as_str()` as a credential:
it is exactly what a client presents.

## Lifecycle

| Step | Rule |
| --- | --- |
| Create | 32 bytes from the OS RNG; empty subjects and subjects over 1,024 UTF-8 bytes rejected |
| Validate | Unknown → `NotFound`; past idle or absolute deadline → delete, then `Expired` |
| Refresh | On valid use, `expires_at = min(now + ttl, issued_at + absolute_ttl)` |
| Revoke | `delete`; the cookie is cleared in the same response |
| Rotate | Validate, delete the old id, then create a replacement |
| Purge | `delete_expired(now)` for periodic cleanup; the manager never sweeps |

Time is passed in explicitly (`now: u64`) instead of read inside the store or
manager. Tests, batch jobs, and clock-skew handling all need that.

Defaults: 7 days idle, 30 days absolute. Both are configurable per deployment;
`Policy` rejects `ttl == 0` and `absolute_ttl < ttl`.

## Rust and Node.js addon boundary

The `oxsession-node` N-API package exposes `Pairs::parse` for cookie parsing,
`resolve` for credential resolution, `CookieSigner::sign` and `verify` for
cookie signing, and `SessionManager::{create, validate, revoke, rotate}` for
session lifecycle. It owns a Rust `MemoryStore` that is process-local and
non-durable; sessions disappear on restart, and separate addon processes do
not share sessions. Persistent storage and JavaScript store callbacks are
outside the initial wrapper contract.

Rust callers can use the sanitized `ErrorCategory` types; Node callers receive
the corresponding stable string on `error.code`. Empty and oversized subjects,
missing and expired sessions, signature failures, entropy failures, and storage
failures remain distinguishable. Store error display does not include adapter
details; detailed sources are available only for internal Rust diagnostics.
Session ids and signing secrets are never included in categories or public
messages.

## Cookie attributes

| Attribute | Value | Why |
| --- | --- | --- |
| `Path` | `/` | Required for `__Host-` names and for app-wide sessions |
| `HttpOnly` | always | The id is not for JavaScript |
| `SameSite` | `Lax` | Sent on top-level navigation, blocked on cross-site subrequests |
| `Max-Age` | idle TTL | The browser drops it when the server would also reject it |
| `Secure` | configured | Off only for `http://localhost`; everything else must set it |
| Name | `session`, configurable | Use `__Host-session` with `Secure` on for the strongest binding |

## Delivery

`POST /sessions` mints the id; `AUTH_SESSION_DELIVERY` decides how the client
learns it.

| Mode | Body | `Set-Cookie` | Cookie accepted | Bearer accepted |
| --- | --- | --- | --- | --- |
| `cookie` | `subject`, `expires_at` | yes, signed when `AUTH_COOKIE_KEYS` is set | yes | yes |
| `token` | `subject`, `expires_at`, `session_id` | none | **no** (not parsed) | yes |
| `both` | both | yes | yes | yes |

Details that matter:

* **The body always carries the raw id, never the `os1.…` wire value.** A bearer
  token is the credential itself; a signed cookie is one carrier for it. Sending
  the wire value would make bearer clients fail the id shape check.
* **`Cache-Control: no-store` + `Pragma: no-cache` on every response that may
  contain an id, on `/me` (success and error), and on `/logout`.** A
  cookie-authenticated response carries no `Vary: Cookie`, so a shared cache
  that stored it would serve one user's subject to another; `Pragma` covers
  HTTP/1.0 intermediaries that ignore `Cache-Control`.
* **`token` is token-only on both sides.** Issuing no cookie while still
  accepting one would leave the ambient credential in place, so a cookie
  presented in that mode is rejected. The cookie is not parsed at all: a
  duplicate would otherwise answer `400 ambiguous` and a signed value would cost
  an HMAC before the `401`. `both` exists to keep cookies working during a
  migration.
* **Bearer is accepted in every mode.** It is explicit — a caller chooses to
  send it — so it adds no ambient attack surface.
* **Logout revokes any credential it can identify**, including a cookie that
  token mode refuses to authenticate for `/me`. Otherwise switching modes would
  leave live ids that no client can kill. Logout still always sends the deletion
  cookie, clearing a stale one from an earlier configuration; the client must
  also drop its own `localStorage` entry, which the server cannot reach.

### `localStorage` vs cookie

| | `HttpOnly` cookie | `localStorage` + bearer |
| --- | --- | --- |
| Readable by scripts | no | yes — XSS becomes session theft |
| Sent automatically | yes, to every same-site request | no |
| CSRF exposure | needs `SameSite`/token defenses | none (no ambient credential) |
| Non-browser clients | awkward | natural |
| Server-side revocation | immediate | immediate |

Neither is strictly better; the cookie default is safer for browsers, and the
token mode exists because a browser app cannot read an `HttpOnly` cookie at all.
`examples/localstorage.js` is a complete client.

## Store conformance

Any adapter must satisfy these before it is useful:

1. `get` returns `None` for unknown ids, never an error.
2. `touch` returns `false` for a missing session, so a concurrent revoke is
   treated as a miss rather than resurrected.
3. `delete` is idempotent and reports whether the session existed.
4. `delete_expired(now)` removes every session with `expires_at <= now` and
   returns the count.
5. `insert` never silently drops an existing id.
6. Errors are adapter-specific and box into the manager's `Error::Store`.
7. Ids are never logged. Session ids are bearer credentials.

`MemoryStore` implements all of the above and is the reference for new
adapters. It is process-local and lost on restart, so it is a development and
single-node adapter only. When full, it evicts the session closest to expiry so
memory stays bounded.

## Non-goals for this layer

- **JWT sessions.** Signed claims in a cookie are a different design with
  different trade-offs (no revocation without a denylist). Not this layer.
- **Session metadata.** IP address, user agent, and device are deliberately not
  stored yet; adding them is an adapter concern, not a model change.

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
| Create | 32 bytes from the OS RNG; empty subjects rejected |
| Validate | Unknown → `NotFound`; past idle or absolute deadline → delete, then `Expired` |
| Refresh | On valid use, `expires_at = min(now + ttl, issued_at + absolute_ttl)` |
| Revoke | `delete`; the cookie is cleared in the same response |
| Rotate | Validate, create a replacement, delete the old id |
| Purge | `delete_expired(now)` for periodic cleanup; the manager never sweeps |

Time is passed in explicitly (`now: u64`) instead of read inside the store or
manager. Tests, batch jobs, and clock-skew handling all need that.

Defaults: 7 days idle, 30 days absolute. Both are configurable per deployment;
`Policy` rejects `ttl == 0` and `absolute_ttl < ttl`.

## Cookie attributes

| Attribute | Value | Why |
| --- | --- | --- |
| `Path` | `/` | Required for `__Host-` names and for app-wide sessions |
| `HttpOnly` | always | The id is not for JavaScript |
| `SameSite` | `Lax` | Sent on top-level navigation, blocked on cross-site subrequests |
| `Max-Age` | idle TTL | The browser drops it when the server would also reject it |
| `Secure` | configured | Off only for `http://localhost`; everything else must set it |
| Name | `session`, configurable | Use `__Host-session` with `Secure` on for the strongest binding |

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

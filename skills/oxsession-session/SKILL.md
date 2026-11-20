---
name: oxsession-session
description: Work on session lifecycle and storage in crates/oxsession-session — Policy and TTLs, sliding expiry, validate/revoke/rotate, MemoryStore behavior, and implementing a new SessionStore adapter. Use for session timing bugs, eviction, persistence work, or store conformance.
---

# oXSession Session Lifecycle

`SessionManager` owns the rules; the store owns persistence. Time is always
passed in as `now: u64`, never read inside the manager or adapter.

## Files

| File | Contents |
| --- | --- |
| `src/manager.rs` | `SessionManager`, `Policy`, `now()`, TTL constants |
| `src/memory.rs` | `MemoryStore`, `MemoryStoreError`, capacity/eviction |
| `src/error.rs` | `Error`, `ErrorCategory` |
| `src/lib.rs` | Re-exports and the crate-level example |

## Constants and defaults

| Item | Value |
| --- | --- |
| `DEFAULT_TTL_SECONDS` | `604_800` (7 days, idle) |
| `DEFAULT_ABSOLUTE_TTL_SECONDS` | `2_592_000` (30 days, from creation) |
| `MAX_SUBJECT_BYTES` | `1024` UTF-8 bytes |
| `DEFAULT_CAPACITY` | `10_000` sessions |
| Generated id | 32 bytes OS RNG → 43-char unpadded base64url |

`Policy::new(ttl, absolute_ttl)` rejects `ttl == 0` and `absolute_ttl < ttl`.

## Lifecycle rules (exact)

| Step | Behavior |
| --- | --- |
| `create(subject, now)` | Trimmed-empty → `InvalidSubject`; `subject.len() > 1024` → `SubjectTooLong`; stores `expires_at = now + min(ttl, absolute_ttl)` |
| `validate(id, now)` | Unknown → `NotFound`; `now >= expires_at` or `now >= issued_at + absolute_ttl` → `delete` then `Expired`; otherwise slide if `now + ttl` is later |
| `revoke(id)` | `delete`, returns whether it existed; idempotent |
| `rotate(id, now)` | `validate` → `delete` old → `create` replacement for the same subject |
| `purge_expired(now)` | `delete_expired`, returns the count; **not scheduled anywhere** |

Details that matter:

- Sliding uses `refreshed = min(now + ttl, issued_at + absolute_ttl)`. Activity
  can never extend past the absolute deadline.
- `validate` only calls `touch` when the deadline actually moves. A `false`
  return from `touch` means the session was revoked between read and touch →
  `NotFound`.
- Expired ids are deleted *before* the error is returned, so retries cannot keep
  a dead id alive.
- `rotate` deletes before creating, so a failure cannot leave two live ids.
- `create` stores the subject as given (interior/leading whitespace is kept);
  only an all-whitespace subject is rejected.

## Store contract

Implement `oxsession_core::SessionStore` using return-position `impl Future`:

```rust
impl SessionStore for MyStore {
    type Error = MyError;

    async fn insert(&self, session: Session) -> Result<(), Self::Error> { /* … */ }
    async fn get(&self, id: &SessionId) -> Result<Option<Session>, Self::Error> { /* … */ }
    async fn touch(&self, id: &SessionId, expires_at: u64) -> Result<bool, Self::Error> { /* … */ }
    async fn delete(&self, id: &SessionId) -> Result<bool, Self::Error> { /* … */ }
    async fn delete_expired(&self, now: u64) -> Result<usize, Self::Error> { /* … */ }
}
```

Conformance rules (from `docs/sessions.md`; the suite is not built yet):

1. `get` returns `None` for unknown ids, never an error.
2. `touch` returns `false` for a missing session (do not resurrect it).
3. `delete` is idempotent and reports whether the session existed.
4. `delete_expired(now)` removes every `expires_at <= now` row and returns the
   count.
5. `insert` never silently drops an existing id.
6. Errors are adapter-specific and box into `Error::Store`; `Display` must not
   include connection strings or backend detail.
7. Ids are never logged.

When adding an adapter, mirror `MemoryStore`'s tests. `MemoryStore` is the
reference implementation, not a production store.

## MemoryStore behavior

- `MemoryStore::new()` = 10,000 sessions; `with_capacity(0)` is treated as `1`.
- At capacity, `insert` evicts the session with the smallest `expires_at` to
  bound memory. A login flood can therefore evict legitimate users.
- Data is process-local and lost on restart. Two processes do not share it.
- Lock poisoning: trait methods return `MemoryStoreError::Poisoned`, but
  `len()`/`is_empty()` **panic** on a poisoned lock. This inconsistency is known
  (see `logs.md`); pick one behavior if you touch it.

## Recipes

**Change a TTL or policy rule.** Update `Policy` validation, the constants, the
manager tests, `docs/sessions.md`, and the server's config validation plus its
`Config::from_env` tests.

**Add a durable adapter.** Implement the trait, satisfy all seven conformance
rules, keep `touch` atomic (`UPDATE … WHERE id = ?` returning row count), add an
index on `expires_at` for `delete_expired`, and never log ids. Wire it into
`AppState<S>` (the server is already generic) and add an endpoint test with the
new store.

**Add a scheduler for `purge_expired`.** Put it at the server edge, not in the
manager: a Tokio interval that calls `purge_expired(now())`. Keep the manager
free of runtime dependencies.

**Investigate "users are logged out too early".** Check, in order: `Policy`
values from env, whether the client is bearer (no cookie re-issue), the absolute
deadline, and `MemoryStore` eviction. Then check that `/me` re-issues the cookie
in the server layer.

## Validation

```sh
cargo test -p oxsession-session
cargo test --workspace
```

Tests pass explicit times; do not introduce sleeps unless you are testing the
wall-clock boundary itself.

## Pitfalls

- Do not read the clock inside `validate`, `touch`, or a store.
- Do not extend a session past `issued_at + absolute_ttl`.
- Do not make `get` return an expired session as `Some`; expiry is the manager's
  decision, so the manager must still see the deadline.
- Do not return `Ok(false)` from `touch` for an existing session; it signals
  revocation to the manager.
- Do not store the raw subject without the 1,024-byte check; oversized subjects
  are a memory/abuse vector.

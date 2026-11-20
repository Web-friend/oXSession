---
name: oxsession-sign
description: Implement, debug, or extend HMAC-signed cookie values in crates/oxsession-sign — the os1 wire format, key ids, secret handling, constant-time verification, and key rotation. Use for signing behavior, signature failures, or interop with non-Rust clients.
---

# oXSession Signing

Opt-in HMAC-SHA256 signing for cookie values. Signing is a policy decision, not
a transport rule: not every cookie needs it, and the session id is the
credential whether or not the carrier is signed.

## Files

| File | Contents |
| --- | --- |
| `src/lib.rs` | `CookieSigner`, key ring, MAC computation, verification |
| `src/format.rs` | Wire format parse/render, version, size limit |
| `src/key.rs` | `KeyId`, `SecretKey`, key validation and zeroization |
| `src/error.rs` | `Error`, `ErrorCategory` |
| `tests/interop.rs` | Published vector, tamper matrix, rotation, name binding |

## Wire format

```text
os1.<keyid>.<payload>.<mac>
```

- `os1` — format version.
- `<keyid>` — `[A-Za-z0-9_-]{1,16}`.
- `<payload>` — caller value; must be non-empty cookie-octets and contain no `.`.
- `<mac>` — 43-char unpadded base64url of
  `HMAC-SHA256(key, "os1." + keyid + "." + name + "." + payload)`.

Two properties are easy to break by accident:

1. **The cookie name is inside the MAC.** A value signed for `session` must fail
   when verified as `admin`. Never remove the name from the MAC input.
2. **The MAC is compared in constant time** using `subtle::ConstantTimeEq`.
   Never replace it with `==`.

## Key rules

- Secrets are exactly 32 bytes (`KEY_BYTES`), `Zeroizing`, and redacted in
  `Debug`. Never print, log, or return key bytes.
- `KeyId::new` enforces `[A-Za-z0-9_-]{1,16}`.
- `MAX_PREVIOUS_KEYS = 2`. At most two retired keys verify.
- Key ids are unique across current and retired keys; collisions return
  `DuplicateKeyId` and leave the ring unchanged.
- `rotate` promotes a new current key, retires the old one, and truncates to the
  two most recent retired keys.
- Generated config uses `SecretKey::from_base64url` (unpadded, 32 bytes).

Generate a key:

```sh
python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))"
```

## API

```rust
use oxsession_sign::{CookieSigner, KeyId, SecretKey};

let signer = CookieSigner::from_parts("k1", &[7; 32])?;
let wire = signer.sign("session", "dXNlcj00Mg")?;
let payload = signer.verify("session", &wire)?;

let rotated = CookieSigner::from_parts("k2", &new_key)?
    .with_previous(KeyId::new("k1")?, SecretKey::from_slice(&old_key)?)?;
```

Signing rejects: invalid cookie name, empty payload, payload containing `.`,
non-cookie-octet bytes, and results over 4096 bytes (`TooLong`). Verification
rejects: malformed shape, unsupported version, unknown key id, and bad MAC — with
no fallback to the raw value.

## Failure policy (security-critical)

`verify` distinguishes `UnknownKey` and `BadMac` internally for diagnostics.
**Clients must not see that difference.** Over HTTP, every signature failure is
`401 authentication required`; over the Node addon, every one is
`SIGNATURE_FAILURE`. A distinguishable failure is a verification oracle.

## Recipes

**Rotate keys without invalidating live sessions.** Construct with the new key
as current and pass old keys with `with_previous`, newest first. The server
re-signs cookie values on each cookie-authenticated `/me`, so active clients
migrate automatically; idle clients fail only after the retired key is dropped.

**Change the wire format.** This is a breaking contract. Bump the version
constant to `os2`, keep the parser strict per version (do not accept both
loosely), update `docs/signing.md` including the test vector and Python
reference, and add interop tests for both the new vector and rejected old
shapes. Do not silently reinterpret `os1` values.

**Add an error variant.** Add it to `Error`, map it in `ErrorCategory`
(`InvalidInput`, `Configuration`, or `SignatureFailure`), update the Node
`OxsessionErrorCode`, and add a test that the client-visible text does not leak
key material.

## Validation

```sh
cargo test -p oxsession-sign
cargo test --workspace
```

The interop suite is the authority on wire compatibility. If you touch format
code, run it first and read `docs/signing.md` before editing.

## Pitfalls

- Signing is **not encryption**. The payload is readable. Do not put secrets in
  it.
- A valid signature is **not** a valid session. Always validate the id against
  the store; signing only rejects tampering early.
- A raw id is still a valid bearer credential. Signing protects the cookie
  carrier, not the token.
- Do not add a "legacy unsigned accepted" path. Verification has no fallback.
- Do not allow `.` in payloads; it is the field separator.

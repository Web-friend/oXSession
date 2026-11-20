# Signed cookies

Signing is opt-in and per cookie. `oxsession-sign` ships the only implementation
of this format; a client in another language can verify the same bytes with a
standard HMAC library.

## Format

```
os1.<keyid>.<payload>.<mac>
```

| Field | Encoding |
| --- | --- |
| `os1` | Literal version prefix |
| `keyid` | `[A-Za-z0-9_-]{1,16}` |
| `payload` | Non-empty cookie-octets (RFC 6265bis), no `.` |
| `mac` | 32 bytes, unpadded base64url (43 characters) |

The MAC is computed over the ASCII bytes of:

```
os1.<keyid>.<name>.<payload>
```

where `<name>` is the **cookie name** supplied by the caller, not part of the
wire value. HMAC-SHA256 is used. Verification must be a constant-time comparison.

Why the name is signed: a value issued for `session` must not be replayable as
`admin`. Omitting the name (as a plain value-only HMAC does) allows cookie
substitution between cookie names.

## Test vector

```
key (hex)   000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
key (b64u)  AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
keyid       k1
name        session
payload     dXNlcj00Mg
mac input   os1.k1.session.dXNlcj00Mg
wire        os1.k1.dXNlcj00Mg.jFXRwvjzXLIZFL-SyIwwPuGKD5ehMEcrvK6D8A4SNtY
```

An implementation is compatible when it produces exactly that `wire`.

## Reference implementation

Python 3, standard library only:

```python
import base64, hmac, hashlib

def sign(key: bytes, keyid: str, name: str, payload: str) -> str:
    msg = f"os1.{keyid}.{name}.{payload}".encode()
    mac = hmac.new(key, msg, hashlib.sha256).digest()
    return f"os1.{keyid}.{payload}." + base64.urlsafe_b64encode(mac).decode().rstrip("=")
```

## Rotation

* Each cookie names the key that produced it, so a rotation does not log anyone
  out.
* The signer holds one current key and at most `MAX_PREVIOUS_KEYS` (2) retired
  keys. Retired keys still verify but are never chosen for new signatures.
* An unknown key id is rejected outright — there is no "try every key" fallback,
  which would let an attacker keep a long-dead key usable.
* Retention is bounded on purpose: every retained key authenticates cookies, so
  rotate and then let the old cookie lifetime expire.
* The current id and every retained id must be unique. `with_previous` and
  `rotate` return `DuplicateKeyId` on collisions without changing the signer.
* Wrapper-facing `ErrorCategory` values group malformed input, configuration,
  and signature failures. Unknown key and bad MAC share the signature category.

## Not encryption

The payload travels in clear and is readable by the browser. Signing answers
"was this minted by us for this cookie name?", not "can anyone read it?". A
sealed (AEAD) format would be `os2` and is not implemented yet.

## Failure handling

Never expose the difference between an unknown key id and a bad MAC: that turns
the endpoint into a signature-check oracle. Log the reason server-side and
return one response for every verification failure.

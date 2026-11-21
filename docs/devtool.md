# `oxsession-devtool`

A local, read-only inspector for the values oXSession puts on the wire:
`Cookie` headers, resolved credentials, `os1.` signed values, session-id shape,
and session policy. It runs on your machine, prints JSON, and redacts
credential-bearing values by default.

The tool exists so that an agent or a human can answer questions like *"why is
this request unauthenticated?"* without opening a REPL, writing a throwaway
script, or pasting a live session id into logs.

```sh
cargo run -p oxsession-devtool -- parse-cookie --header 'theme=dark; session=abc'
```

`cargo install --path crates/oxsession-devtool` puts `oxsession-devtool` on your
`PATH` if you prefer the short form.

## What it does not do

The tool never touches a session store and never mutates state. It cannot mint,
validate against storage, refresh, rotate, or revoke a session. Adding
`--reveal` changes what is printed, not what is possible.

That is deliberate. An inspector that can mint sessions is a login bypass with
a CLI wrapper, and an inspector that silently prints raw ids leaks bearer
material into transcripts.

| Operation | Supported |
| --- | --- |
| Parse a `Cookie` header, report parser stats | Yes |
| Resolve `Bearer`/cookie precedence | Yes, token redacted |
| Verify an `os1` value with keys you supply | Yes, payload redacted |
| Check session-id length/characters | Yes, no store lookup |
| Validate TTLs and cookie-name/prefix rules | Yes |
| Look up, mint, refresh, or revoke a session | **No** |
| Read keys or ids from server configuration | **No** |

## Output and exit codes

Every command writes a single JSON object to stdout. Diagnostics go to stderr.
Keys are serialized alphabetically, so output is stable enough to diff in tests.

| Exit code | Meaning |
| --- | --- |
| `0` | Success, or the answer is positive (`valid: true`) |
| `1` | The answer is negative (`valid: false`, no credential, bad MAC) |
| `2` | Usage error: unknown command, missing option, bad value |
| `3` | Configuration/IO error: unreadable key file, bad key encoding |

Exit code `1` is a normal answer, not a crash. A script can branch on the code
without parsing the body:

```sh
if oxsession-devtool check-cookie --name session --value "$WIRE" --key-file ring.txt >/dev/null; then
  echo "signature ok"
else
  echo "signature failed"
fi
```

## `parse-cookie`

Parses a `Cookie` header exactly as the adapters do, including the size and pair
limits. The credential cookie is redacted by default.

```sh
oxsession-devtool parse-cookie \
  --header 'theme=dark; session=abc123; trailing' \
  --session-cookie session
```

```json
{
  "limits": { "max_header_bytes": 8192, "max_pairs": 128 },
  "pairs": [
    { "name": "theme",   "redacted": false, "value": "dark",   "value_len": 4 },
    { "name": "session", "redacted": true,  "value": null,     "value_len": 6 }
  ],
  "stats": { "pairs": 2, "skipped": 1, "too_long": false, "truncated": false }
}
```

| Option | Meaning |
| --- | --- |
| `--header <value>` | Header to parse. Repeatable; values are joined with `"; "` as RFC 6265 §5.4 requires |
| `--session-cookie <name>` | Credential cookie name (default `session`) |
| `--redact <name>` | Additional name to redact. Repeatable |
| `--reveal-name <name>` | Reveal this name. Repeatable; wins over redaction |

`stats.skipped` counts non-empty segments that are not `name=value`.
`truncated` and `too_long` map to the parser's limits; when `too_long` is true
nothing was read and `pairs` is empty.

## `resolve-credential`

Reproduces the `Authorization`-wins-over-cookie rule. The resolved token is
redacted unless you pass `--reveal`.

```sh
oxsession-devtool resolve-credential \
  --authorization 'Bearer 4f9c…' --cookie 'session=ignored'
```

```json
{
  "resolved": true,
  "source": "bearer",
  "token_present": true,
  "token": null,
  "token_len": 36,
  "token_redacted": true
}
```

A missing or unusable credential is exit `1`:

```json
{
  "resolved": false,
  "source": null,
  "token_present": false,
  "category": "MISSING_CREDENTIAL",
  "error": "authentication required"
}
```

`category` is the sanitized category from `oxsession-core`; it tells you
`INVALID_INPUT`, `MISSING_CREDENTIAL`, or `AMBIGUOUS_CREDENTIAL` without naming
which check failed.

| Option | Meaning |
| --- | --- |
| `--authorization <value>` | Raw `Authorization` header |
| `--cookie <value>` | Raw `Cookie` header (default empty) |
| `--cookie-name <name>` | Credential cookie name (default `session`) |
| `--reveal` | Include the token in the output |

## `check-cookie`

Verifies an `os1.<keyid>.<payload>.<mac>` value against a key ring. The first
key is treated as current; the rest are previous keys used for verification
only. Missing, unknown, or wrong keys all produce the same negative answer, which
matches the library's no-oracle rule.

```sh
oxsession-devtool check-cookie \
  --name session \
  --value 'os1.k1.dXNlcj00Mg.…' \
  --key-file ~/.config/oxsession/keys.txt
```

```json
{
  "valid": true,
  "name": "session",
  "version": "os1",
  "key_id": "k1",
  "payload_len": 10,
  "payload": null,
  "payload_redacted": true
}
```

A failure prints the sanitized category instead:

```json
{
  "valid": false,
  "name": "session",
  "category": "SIGNATURE_FAILURE",
  "error": "signature verification failed"
}
```

| Option | Meaning |
| --- | --- |
| `--name <name>` | Cookie name the value was signed for. Required |
| `--value <wire>` | Signed value. Required |
| `--key <keyid:base64url>` | Key spec. Repeatable; first signs, rest verify |
| `--key-file <path>` | File of `keyid:base64url` lines; `#` comments and blanks ignored |
| `--reveal-payload` | Print the verified payload |

Keys from `--key` are used before keys from `--key-file`.

### Handling key material

`--key` puts the secret in your shell history and in the process list. Use a
`0600` key file for anything resembling a real key:

```sh
install -m 600 /dev/null ~/.config/oxsession/keys.txt
printf 'k2:%s\nk1:%s\n' "$CURRENT" "$PREVIOUS" > ~/.config/oxsession/keys.txt
```

The file order is the rotation order: current key first. A key is 32 bytes,
unpadded base64url, the same encoding the server accepts in `AUTH_COOKIE_KEYS`.
Generate one with:

```sh
python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))"
```

The tool reads keys only from the arguments or the file you name. It does not
read `AUTH_COOKIE_KEYS`, dotenv files, or the server's environment, so a devtool
run cannot accidentally print a production key.

## `inspect-id`

Checks the shape of a session id: length bounds and the base64url alphabet.
There is no store lookup, so `valid: true` means *well-formed*, not *exists*.

```sh
oxsession-devtool inspect-id --id 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
```

```json
{
  "valid": true,
  "length": 43,
  "min_length": 16,
  "max_length": 128
}
```

An over-long or non-base64url value returns exit `1` with the same fields plus
`error`.

## `policy`

Validates a TTL pair and, optionally, a cookie name against the prefix rules
that `Config::from_env` enforces at startup.

```sh
oxsession-devtool policy --ttl 604800 --absolute 2592000 \
  --cookie-name __Host-session --secure
```

```json
{
  "ttl_seconds": 604800,
  "ttl_human": "7d",
  "absolute_seconds": 2592000,
  "absolute_human": "30d",
  "valid": true,
  "cookie_name_valid": true,
  "prefix": "host",
  "requires_secure": true,
  "secure": true,
  "cookie_configuration_valid": true,
  "configuration_valid": true
}
```

`valid` is the `Policy::new` answer: `ttl` must be non-zero and `absolute` must
be at least `ttl`. `configuration_valid` combines that with the cookie check, so
scripts should branch on `configuration_valid`.

| Option | Meaning |
| --- | --- |
| `--ttl <seconds>` | Idle lifetime. Required |
| `--absolute <seconds>` | Absolute lifetime. Required |
| `--cookie-name <name>` | Cookie name to validate. Optional |
| `--secure` | Treat the deployment as HTTPS/`Secure` |

Without `--cookie-name`, the cookie fields are absent and
`configuration_valid` equals `valid`.

## Worked example: why is `/me` returning 401?

1. Capture the request headers from the failing client, with the id replaced by
   a placeholder if you plan to share the output.
2. Check the credential actually arrived:

   ```sh
   oxsession-devtool resolve-credential --authorization "$AUTH" --cookie "$COOKIE"
   ```

   `MISSING_CREDENTIAL` means the client sent neither, or sent a non-`Bearer`
   scheme. `AMBIGUOUS_CREDENTIAL` means the cookie name appeared twice — treat
   that as an attack, not a client bug.

3. If `AUTH_COOKIE_KEYS` is set, verify the signature before blaming the store:

   ```sh
   oxsession-devtool check-cookie --name "$COOKIE_NAME" --value "$VALUE" --key-file ring.txt
   ```

   `SIGNATURE_FAILURE` covers unknown key id and bad MAC on purpose. Check the
   `key_id` field against your ring; an old key may have been retired more than
   `MAX_PREVIOUS_KEYS` rotations ago.

4. Confirm the id is well-formed:

   ```sh
   oxsession-devtool inspect-id --id "$TOKEN"
   ```

5. If all three pass, the credential is authentic and well-formed but unknown or
   expired in the store. That is a server-side question the devtool cannot
   answer, which is the point.

## Why not MCP?

MCP is useful when a client has no filesystem or shell. A coding agent working
in this repository has both, and `cargo test` is a better interface than a tool
call that wraps it. More importantly, MCP tool results land in model context
and often in transcripts — the wrong place for bearer material.

If a non-shell client eventually needs this, expose the same read-only
operations over stdio, keep redaction on by default, and disable anything that
mutates a store. The CLI is the reference implementation for those semantics:
JSON out, sanitized categories, exit codes instead of prose.

## Source layout

`crates/oxsession-devtool` is a binary crate with no public library surface. It
depends on `oxsession-core` for parsing/credential/session-id rules,
`oxsession-sign` for verification, and `oxsession-session` for `Policy`, so it
cannot drift from the library it inspects.

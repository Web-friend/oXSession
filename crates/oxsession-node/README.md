# oxsession-node

Node.js N-API bindings for oXSession's cookie, credential, signing, and session
primitives. The addon uses `napi-rs` and keeps session data in a Rust-owned
`MemoryStore` inside each Node process. Data is not durable or shared between
processes.

## Build

From this directory, run:

```sh
npm run build
```

This builds the Rust cdylib in release mode and copies it to `oxsession.node`.
Node.js 18 or later and the Rust toolchain are required.

## API

```js
const { CookieSigner, SessionManager, parseCookies, resolveCredential } = require('oxsession-node')

const cookies = parseCookies('theme=dark; session=abc')
const credential = resolveCredential(null, 'session=abc')

const signer = new CookieSigner('k1', process.env.OXSESSION_KEY)
const signed = signer.sign('session', credential.token)
const verified = signer.verify('session', signed)

const sessions = new SessionManager()
const session = await sessions.create('user-42')
const valid = await sessions.validate(session.id)
await sessions.revoke(valid.id)
```

Signing keys are 32 bytes encoded as unpadded base64url. Session ids are bearer
credentials; protect them like passwords and do not log them.

Errors reject or throw with a stable `.code` such as `SUBJECT_TOO_LONG`,
`SIGNATURE_FAILURE`, or `STORAGE_FAILURE`. Signature failures do not disclose
whether a key id was unknown or the MAC was invalid.

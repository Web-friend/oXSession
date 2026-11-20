---
name: oxsession-node
description: Implement, debug, or document this repository's Node.js N-API addon and its Rust authentication bindings. Use for work in crates/oxsession-node or changes to its exported API.
---

# oXSession Node.js Addon

Use this skill for changes to the `oxsession-node` N-API package in this
repository. The Rust implementation is in `crates/oxsession-node/src/lib.rs`;
the CommonJS API, declarations, and package build live beside it.

## API and constraints

- The package exports `parseCookies`, `resolveCredential`, `CookieSigner`, and
  `SessionManager`. Keep the Rust N-API exports, `index.js` façade,
  `index.d.ts`, and package README in sync when changing public behavior.
- `SessionManager` owns a Rust `MemoryStore` per instance. Sessions are
  process-local, non-durable, and disappear on restart. Do not add persistent
  storage or JavaScript store callbacks unless the task explicitly changes this
  boundary.
- Session IDs are bearer credentials. Never log them or include them in error
  messages. Subjects are capped at 1,024 UTF-8 bytes.
- Signing keys are 32-byte unpadded base64url strings. Never expose key bytes.
  Map unknown-key and bad-MAC verification errors to the same
  `SIGNATURE_FAILURE` code and message.
- The JS façade converts the native `OXSESSION_<CODE>:` error prefix into
  `error.code`. Preserve stable codes and sanitized messages when adding
  failures. Current codes are declared as `OxsessionErrorCode` in
  `index.d.ts` and mapped in `src/lib.rs`.
- N-API object and method names use camelCase in JavaScript (for example,
  `keyId`, `issuedAt`, and `expiresAt`); keep declarations aligned with
  `napi-rs` name conversion.

## Build and validation

From the repository root, build the local platform addon with:

```sh
npm run build --prefix crates/oxsession-node
```

The script compiles the release cdylib and copies it to
`crates/oxsession-node/oxsession.node`. That binary is platform-specific and
git-ignored; do not add it to source changes. For Rust changes, also use
`cargo fmt --all -- --check` and the relevant Cargo checks or tests. For JS
façade changes, run `node --check` on the changed JavaScript files. Update the
TypeScript declarations and package documentation whenever the JS API changes.

## Useful references

- `crates/oxsession-node/README.md` — package usage and storage contract.
- `crates/oxsession-node/index.d.ts` — public TypeScript API and error codes.
- `docs/sessions.md` and `docs/signing.md` — Rust behavior and shared contracts.

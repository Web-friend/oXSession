---
name: oxsession-react
description: Integrate oXSession with a React or other browser SPA — same-origin HttpOnly cookie via a proxy, or bearer tokens in localStorage; typed fetch client, auth provider, 401 handling, Vite/nginx setup, CORS gaps, and deployment constraints. Use for any frontend work against oxsession-server.
---

# oXSession in React

There is no browser npm package. React talks to `oxsession-server` over HTTP.
The Node addon (`oxsession-node`) is native Node code and must never be bundled
for the browser.

`docs/react.md` is the full guide and the source of truth for client code. This
skill is the short version.

## Two supported shapes

| Shape | Server mode | Client storage | Trade-off |
| --- | --- | --- | --- |
| **Same-origin cookie (recommended)** | `cookie` (default) | `HttpOnly` cookie, invisible to JS | Safe from XSS exfiltration; requires one origin (proxy) |
| Bearer token | `token` or `both` | `localStorage` | Portable, but XSS becomes session theft |

Do not mix carriers casually. `both` exists only for migrations.

## Non-negotiables

- **No CORS layer exists.** A browser calling `http://127.0.0.1:3000` from
  `http://localhost:5173` fails. Use a Vite proxy (`/api` → `:3000`) or add a
  `tower-http` `CorsLayer` to the server. Never use `allow_origin(Any)` with
  credentials.
- **Errors are `text/plain`.** Branch on status codes, not a JSON envelope.
  `401` = no usable credential; `400` = malformed/ambiguous; `404` on
  `/sessions` = dev login disabled.
- **The server is the source of truth.** No claims in the cookie. Call `/me` to
  learn identity. A `401` means clear local state and redirect to login.
- **`/me` re-issues the cookie** on cookie-authenticated requests, so don't
  build a second expiry timer; rely on `expires_at` and `401`.
- **`POST /sessions` is a dev stub.** It mints a session for any subject and is
  `404` unless `AUTH_DEV_LOGIN=1`. Never enable it in production.
- **Do not poll `/me` aggressively.** Every call slides the idle deadline and
  writes through the store. Refresh on focus, after login, and after mutations.
- **Signing is transparent.** `AUTH_COOKIE_KEYS` turns the cookie into
  `os1.…`, but it stays `HttpOnly`; React code does not change.

## Canonical client

```ts
const BASE = "/api"; // Vite/nginx proxy strips the prefix

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("accept", "application/json");

  const response = await fetch(`${BASE}${path}`, {
    ...init,
    headers,
    credentials: "include",
    cache: "no-store",
  });

  if (!response.ok) throw new Error(`${response.status} ${await response.text()}`);
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
}

export const oxsession = {
  login: (subject: string) =>
    request("/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject }),
    }),
  me: () => request<{ subject: string; expires_at: number; source: string }>("/me"),
  logout: () => request<void>("/logout", { method: "POST" }),
};
```

In cookie mode `login` returns no id; call `me()` afterwards. `expires_at` is
Unix **seconds**.

## Recommended server env for local development

```sh
AUTH_DEV_LOGIN=1
AUTH_SESSION_DELIVERY=cookie
AUTH_SESSION_COOKIE=session
AUTH_SESSION_COOKIE_SECURE=0     # http://localhost only
AUTH_SESSION_TTL_SECONDS=604800
AUTH_SESSION_ABSOLUTE_TTL_SECONDS=2592000
AUTH_BIND_ADDR=127.0.0.1
AUTH_PORT=3000
```

Non-loopback binds require `AUTH_SESSION_COOKIE_SECURE=1`; startup fails
otherwise. No dotenv files are loaded — export real environment variables.

## Vite proxy

```ts
server: {
  proxy: {
    "/api": {
      target: "http://127.0.0.1:3000",
      changeOrigin: false,
      rewrite: (path) => path.replace(/^\/api/, ""),
    },
  },
}
```

`vite preview` has no proxy by default; either add `preview.proxy` or serve the
build behind nginx with the four exact routes proxied.

## Token mode (only when needed)

- `AUTH_SESSION_DELIVERY=token`; read `session_id` from the `POST /sessions`
  body (raw id, never the signed wire value).
- Send `Authorization: Bearer <id>`, use `credentials: "omit"`, and remove the
  stored id on logout even if the request fails.
- Cookie mode ignores cookies entirely in this mode: a cookie is a `401`, not a
  fallback.
- Still needs the proxy or a CORS layer.

## If you change the HTTP surface

Update all of these together:

1. `crates/oxsession-server/src/routes.rs` and its endpoint tests.
2. `README.md` endpoint/config tables.
3. `docs/react.md` (status codes, bodies, client snippet).
4. This skill, if the client workflow changes.

## Pitfalls

- `credentials: "omit"` in cookie mode guarantees `401`.
- Mixing `localhost` and `127.0.0.1` splits the cookie jar (host-only cookies).
- `AUTH_SESSION_COOKIE_SECURE=1` over plain HTTP loses the cookie.
- Duplicate `session` cookies produce `400 ambiguous credential cookie`; clear
  stale cookies after a deployment change.
- `MemoryStore` restarts log everyone out; do not treat it as a bug in the SPA.
- `HttpOnly` prevents reading the id, not using it. XSS can still act as the
  user; CSP and input handling still matter.
- `SameSite=Lax` is hard-coded, so cross-site iframes cannot authenticate.

## Validation

There is no frontend test harness in this repository. For docs or contract
changes, verify with `curl` against a running server and check response headers
in DevTools. See `docs/react.md` §16 for an MSW/Vitest setup you can copy into
an app. The sibling `React Demo Project` includes Playwright coverage for its
React UI and Node addon HTTP API; run `npm run verify:container` there to build
and exercise the Podman API container and print the informational benchmark.

# Using oXSession with React

This guide wires a React single-page app to `oxsession-server`, the HTTP surface
that ships with this workspace. It assumes the **cookie + Vite proxy** setup:
the browser talks to one origin, the dev server forwards `/api/*` to the Rust
server, and the session id stays in an `HttpOnly` cookie that JavaScript cannot
read.

It is written against the code in this repository, not against a hypothetical
future version. Where the code and [`logs.md`](../logs.md) disagree, the code
wins and the difference is called out.

## Contents

1. [What this library is (and is not)](#1-what-this-library-is-and-is-not)
2. [Architecture and request flow](#2-architecture-and-request-flow)
3. [Choosing a credential carrier](#3-choosing-a-credential-carrier)
4. [Prerequisites](#4-prerequisites)
5. [Running the server for development](#5-running-the-server-for-development)
6. [Vite proxy configuration](#6-vite-proxy-configuration)
7. [A small typed client](#7-a-small-typed-client)
8. [React wiring: provider, hooks, guards](#8-react-wiring-provider-hooks-guards)
9. [Login, logout, and expiry](#9-login-logout-and-expiry)
10. [Endpoint reference](#10-endpoint-reference)
11. [Signed cookies and key rotation](#11-signed-cookies-and-key-rotation)
12. [Token mode and `localStorage`](#12-token-mode-and-localstorage)
13. [Why direct cross-origin calls fail](#13-why-direct-cross-origin-calls-fail)
14. [Production deployment](#14-production-deployment)
15. [Next.js and server-side rendering](#15-nextjs-and-server-side-rendering)
16. [Testing with MSW and Vitest](#16-testing-with-msw-and-vitest)
17. [Security checklist](#17-security-checklist)
18. [Troubleshooting](#18-troubleshooting)
19. [What this library does not do yet](#19-what-this-library-does-not-do-yet)

---

## 1. What this library is (and is not)

oXSession is a Rust workspace. There is no npm package that a browser can
import.

| Crate | Role | Usable from React? |
| --- | --- | --- |
| `oxsession-core` | Cookie parsing/serialization, credential resolution, session model, `SessionStore` trait | No |
| `oxsession-sign` | HMAC-SHA256 signed cookie values (`os1.<keyid>.<payload>.<mac>`) | No |
| `oxsession-session` | Session lifecycle policy, `MemoryStore` | No |
| `oxsession-axum` | Axum extractors and HTTP error mapping | No |
| `oxsession-server` | Binary exposing `GET /health`, `GET /me`, `POST /sessions`, `POST /logout` | Yes, over HTTP |
| `oxsession-node` | N-API native addon (`oxsession.node`) | No, Node.js only |

Two consequences follow:

* React integration means **calling the HTTP endpoints**. The unit of
  integration is a `fetch` wrapper, not a library import.
* The Node addon is a **server-side** package. It loads a compiled `.node`
  binary through `require`, so Vite, Webpack, and CRA cannot bundle it for the
  browser. It belongs in a BFF (backend-for-frontend), never in `src/`.

There is also no login system yet. `POST /sessions` mints a session for any
subject and is disabled unless `AUTH_DEV_LOGIN=1` is set. Treat it as a
development stub that stands in for the OIDC work on the roadmap.

### Version assumptions

* oXSession `0.1.0`, Rust `1.85`, edition 2024, Axum `0.8`.
* React 18 or 19, TypeScript 5, Vite 5/6/7.
* React Router v6 or v7 for the guard examples. Nothing in the client depends
  on it; swap in TanStack Router or a hand-rolled switch if you prefer.

---

## 2. Architecture and request flow

```
Browser  http://localhost:5173
   │  fetch("/api/me")            same-origin, cookie attached by the browser
   ▼
Vite dev server
   │  GET /me                      /api stripped by the proxy rewrite
   │  Cookie: session=<43-char id>
   ▼
oxsession-server  http://127.0.0.1:3000
   ├─ if AUTH_COOKIE_KEYS is set: verify HMAC before any store lookup
   ├─ SessionManager::validate → MemoryStore
   ├─ sliding expiry: expires_at = min(now + ttl, issued_at + absolute_ttl)
   └─ 200 {"subject":"user-1","expires_at":…,"source":"cookie"}
        Cache-Control: no-store
        Set-Cookie: session=…; Path=/; Max-Age=…; HttpOnly; SameSite=Lax
```

Three properties of this diagram drive everything else in the guide:

* **One origin.** The browser only ever sees `localhost:5173`. Cookies are
  host-scoped and `Path=/`, so they are sent to every request the SPA makes,
  including the proxied ones.
* **The server is the source of truth.** There are no claims in the cookie.
  Every page load that needs identity calls `GET /me`; a `401` means the stored
  credential is dead and the client should drop its state.
* **`/me` refreshes the cookie.** `routes.rs` re-issues `Set-Cookie` on every
  cookie-authenticated `/me` with a fresh `Max-Age`, so the browser's expiry
  tracks the server's sliding deadline. (This was an open item in `logs.md`;
  the request path now implements it.)

---

## 3. Choosing a credential carrier

| | `HttpOnly` cookie (this guide) | Bearer token in `localStorage` |
| --- | --- | --- |
| Readable by page scripts | No | **Yes** — XSS becomes session theft |
| Sent automatically | Yes, same-site only (`SameSite=Lax`) | No |
| CSRF exposure | Needs `SameSite`/origin defenses | None, no ambient credential |
| Works with the Vite proxy | Yes | Yes |
| Server mode | `AUTH_SESSION_DELIVERY=cookie` (default) | `token` or `both` |
| React knows the id | No, only via `/me` | Yes, from the login response |

Use the cookie path unless you have a requirement the cookie cannot meet (a
native/mobile client, a CLI, or a BFF that must forward tokens). The rest of
this document is the cookie path; §12 covers token mode.

`both` exists to migrate one client type at a time. It issues and accepts both
carriers. Do not leave it on: it widens the attack surface for no benefit once
the migration is done.

---

## 4. Prerequisites

```sh
rustc --version     # 1.85 or newer
cargo --version
node --version      # 18+ for the app; 20/22 recommended
npm --version
```

The front end is a standard Vite app:

```sh
npm create vite@latest my-app -- --template react-ts
cd my-app
npm install
npm install react-router-dom
```

No dependency is added for oXSession. The client is plain `fetch`.

---

## 5. Running the server for development

### 5.1 Start the Rust server

From the repository root:

```sh
AUTH_DEV_LOGIN=1 \
AUTH_SESSION_DELIVERY=cookie \
AUTH_SESSION_COOKIE=session \
AUTH_SESSION_COOKIE_SECURE=0 \
AUTH_SESSION_TTL_SECONDS=604800 \
AUTH_SESSION_ABSOLUTE_TTL_SECONDS=2592000 \
AUTH_BIND_ADDR=127.0.0.1 \
AUTH_PORT=3000 \
cargo run -p oxsession-server
```

Expected output:

```
oXSession server listening on 127.0.0.1:3000
warning: AUTH_DEV_LOGIN is enabled; POST /sessions mints sessions for any subject
```

**No dotenv files are loaded.** `Config::from_env` reads the process
environment only. A `.env` file next to the binary does nothing. Use your
shell's `export`, a `direnv`/`just` wrapper, or:

```sh
env $(grep -v '^#' .env | xargs) cargo run -p oxsession-server
```

### 5.2 Verify it is alive

```sh
curl -s http://127.0.0.1:3000/health
# {"status":"ok"}
```

Mint a session and use it:

```sh
curl -s -c /tmp/ox.jar -H 'content-type: application/json' \
     -d '{"subject":"user-1"}' http://127.0.0.1:3000/sessions
# {"subject":"user-1","expires_at":1763...}   ← no session_id, no source in cookie mode

curl -s -b /tmp/ox.jar http://127.0.0.1:3000/me
# {"subject":"user-1","expires_at":1763...,"source":"cookie"}

curl -s -b /tmp/ox.jar -X POST http://127.0.0.1:3000/logout -i | head -5
# HTTP/1.1 204 No Content
# set-cookie: session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
```

If `/sessions` returns `404`, `AUTH_DEV_LOGIN` is not set. If it returns `400`,
the subject is empty or whitespace-only.

### 5.3 Configuration that matters to a browser client

| Variable | Dev value | Why it matters to the SPA |
| --- | --- | --- |
| `AUTH_DEV_LOGIN` | `1` | Without it `POST /sessions` is `404` and there is no way to log in |
| `AUTH_SESSION_DELIVERY` | `cookie` | `token` returns the id in the body and **rejects cookies**; the cookie client then gets `401` |
| `AUTH_SESSION_COOKIE` | `session` | Must match what the browser holds. Changing it orphans existing cookies |
| `AUTH_SESSION_COOKIE_SECURE` | `0` for `http://localhost` | `1` over plain HTTP makes the browser refuse the cookie (some browsers exempt `localhost`, but do not rely on it) |
| `AUTH_SESSION_TTL_SECONDS` | `604800` | Idle lifetime; refreshed on every cookie-authenticated `/me` |
| `AUTH_SESSION_ABSOLUTE_TTL_SECONDS` | `2592000` | Hard cap from creation; activity cannot extend it |
| `AUTH_COOKIE_KEYS` | unset | When set, the cookie value is `os1.…` and tampering costs an HMAC, not a store lookup |
| `AUTH_BIND_ADDR` | `127.0.0.1` | Non-loopback addresses **require** `AUTH_SESSION_COOKIE_SECURE=1` or startup fails |

Startup validation you can rely on:

* `AUTH_PORT` must be 1–65535.
* `AUTH_SESSION_TTL_SECONDS > 0` and `<= AUTH_SESSION_ABSOLUTE_TTL_SECONDS`.
* `__Host-*` and `__Secure-*` cookie names require `AUTH_SESSION_COOKIE_SECURE=1`.
* A non-loopback bind requires `AUTH_SESSION_COOKIE_SECURE=1`.

Note the loopback exemption: `127.0.0.1` and `::1` are allowed to run without
`Secure` so `http://localhost` works. Everything else is refused at startup,
which is stricter than `logs.md` describes.

---

## 6. Vite proxy configuration

Create or edit `vite.config.ts`:

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      // The SPA calls /api/*; the Rust server owns /me, /sessions, /logout, /health.
      // Keeping the /api prefix avoids colliding with React routes of the same name.
      "/api": {
        target: "http://127.0.0.1:3000",
        changeOrigin: false,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
  preview: {
    port: 4173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:3000",
        changeOrigin: false,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
```

Why `changeOrigin: false`? The Rust server does not inspect the `Host` header,
so rewriting it buys nothing. Leaving it alone keeps the request looking like
what the browser sent, which makes proxy logs easier to read against DevTools.

Why a proxy at all? Because the server has **no CORS layer** (see §13). A
same-origin proxy avoids the problem entirely instead of asking you to patch
the server.

`strictPort: true` is deliberate: if 5173 is taken, Vite moving to 5174 would
still work for the proxy, but any absolute origin you hard-code elsewhere
breaks silently.

### 6.1 Typing the base path

`src/vite-env.d.ts`:

```ts
/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_OXSESSION_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
```

Default to `/api` in code. Only override `VITE_OXSESSION_BASE` if you mount the
proxy somewhere else, and remember it is a **browser** base path — not the Rust
server's address. Do not put `http://127.0.0.1:3000` there.

---

## 7. A small typed client

`src/lib/oxsession.ts`:

```ts
/**
 * Minimal client for oxsession-server.
 *
 * Cookie delivery: the browser holds an HttpOnly cookie and this module never
 * sees the session id. Every call goes through the Vite proxy, so it is always
 * same-origin.
 */

export interface SessionInfo {
  subject: string;
  /** Unix seconds. */
  expires_at: number;
  source: "cookie" | "bearer";
}

export interface CreatedSession {
  subject: string;
  /** Unix seconds. */
  expires_at: number;
  /** Only present when AUTH_SESSION_DELIVERY is `token` or `both`. */
  session_id?: string;
}

/** Error responses are text/plain, so branch on `status`, not on a JSON envelope. */
export class OxsessionError extends Error {
  readonly status: number;
  readonly body: string;

  constructor(status: number, body: string) {
    super(`oxsession: ${status}${body ? ` ${body}` : ""}`);
    this.name = "OxsessionError";
    this.status = status;
    this.body = body;
  }

  get isUnauthenticated(): boolean {
    return this.status === 401;
  }

  get isDevLoginDisabled(): boolean {
    return this.status === 404;
  }
}

const BASE = import.meta.env.VITE_OXSESSION_BASE ?? "/api";

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  // `new Headers` accepts a plain object, an array, or a Headers instance,
  // so callers can pass any of them without this helper flattening them.
  const headers = new Headers(init.headers);
  if (!headers.has("accept")) headers.set("accept", "application/json");

  const response = await fetch(`${BASE}${path}`, {
    ...init,
    // Through the proxy this is same-origin, where the default already sends
    // cookies. `include` keeps it working if BASE ever becomes absolute.
    credentials: "include",
    // The server already sends no-store; this keeps an intermediate
    // service worker from serving a stale identity.
    cache: "no-store",
    headers,
  });

  if (!response.ok) {
    // Consume the body so the connection is reusable, then discard it.
    const body = await response.text();
    throw new OxsessionError(response.status, body);
  }

  // 204 No Content has no body.
  if (response.status === 204) return undefined as T;

  return (await response.json()) as T;
}

export const oxsession = {
  /** Creates a session. Development only; `subject` is trusted as-is. */
  login(subject: string): Promise<CreatedSession> {
    return request<CreatedSession>("/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject }),
    });
  },

  /** Resolves the caller's identity. `401` means no usable credential. */
  me(signal?: AbortSignal): Promise<SessionInfo> {
    return request<SessionInfo>("/me", { signal });
  },

  /** Revokes the session and clears the cookie. */
  logout(): Promise<void> {
    return request<void>("/logout", { method: "POST" });
  },

  /** Public liveness probe. */
  health(): Promise<{ status: string }> {
    return request<{ status: string }>("/health");
  },
};
```

Deliberate details:

* `credentials: "include"` is redundant same-origin but harmless and correct if
  you later point `BASE` at another host. Never use `"omit"` in cookie mode.
* `cache: "no-store"` is belt-and-braces. The server sets
  `Cache-Control: no-store` and `Pragma: no-cache` on `/me`, `/sessions`, and
  `/logout`, including error responses.
* Errors are typed by status because the server returns `text/plain`
  (`"authentication required"`, `"ambiguous credential cookie"`,
  `"malformed credentials"`) rather than JSON.
* `login` does not return an id in cookie mode. The only way to learn who you
  are is to call `me()` afterwards.

---

## 8. React wiring: provider, hooks, guards

### 8.1 Auth context

`src/auth/AuthProvider.tsx`:

```tsx
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { oxsession, OxsessionError, type SessionInfo } from "../lib/oxsession";

type Status = "loading" | "authenticated" | "anonymous";

interface AuthState {
  status: Status;
  session: SessionInfo | null;
  error: Error | null;
}

interface AuthContextValue extends AuthState {
  login(subject: string): Promise<void>;
  logout(): Promise<void>;
  refresh(): Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    status: "loading",
    session: null,
    error: null,
  });

  const refresh = useCallback(async () => {
    try {
      const session = await oxsession.me();
      setState({ status: "authenticated", session, error: null });
    } catch (error) {
      if (error instanceof OxsessionError && error.isUnauthenticated) {
        // The credential is missing, expired, revoked, or forged. This is a
        // normal signed-out state, not an application error.
        setState({ status: "anonymous", session: null, error: null });
        return;
      }
      // Network failure, 500, misconfigured proxy: keep the user signed out
      // but surface the cause.
      setState({ status: "anonymous", session: null, error: error as Error });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const login = useCallback(
    async (subject: string) => {
      await oxsession.login(subject);
      // In cookie mode the response never contains the id, so identity is
      // only known after this second call.
      await refresh();
    },
    [refresh],
  );

  const logout = useCallback(async () => {
    try {
      await oxsession.logout();
    } catch (error) {
      if (!(error instanceof OxsessionError && error.isUnauthenticated)) {
        // `logout` deliberately does not clear the cookie when revocation
        // fails, so the session may still be live. Keep the user signed in
        // and let the UI retry instead of lying about it.
        throw error;
      }
    }
    setState({ status: "anonymous", session: null, error: null });
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({ ...state, login, logout, refresh }),
    [state, login, logout, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside <AuthProvider>");
  return context;
}
```

Notes:

* React 18/19 `StrictMode` mounts effects twice in development. `/me` is a
  `GET`, and a cookie-authenticated `/me` re-issues the cookie, so the duplicate
  is harmless. If the duplicate request bothers you in logs, gate it with a ref
  — do **not** disable `StrictMode`.
* `error` is kept separate from `status`. A `500` from a misconfigured proxy
  should render "cannot reach auth service", not "please log in again".
* `logout` rethrows non-`401` failures on purpose. The server returns `500`
  and leaves the cookie in place when it cannot revoke the session, so the user
  really is still logged in.

### 8.2 Route guard

`src/auth/RequireAuth.tsx`:

```tsx
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "./AuthProvider";

export function RequireAuth() {
  const { status } = useAuth();
  const location = useLocation();

  if (status === "loading") {
    return <div className="auth-loading">Checking session…</div>;
  }

  if (status === "anonymous") {
    // `state.from` lets the login page send the user back where they tried
    // to go, including the query string.
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return <Outlet />;
}
```

With React Router v6/v7 data routers:

```tsx
<Route element={<RequireAuth />}>
  <Route path="/" element={<Dashboard />} />
  <Route path="/settings" element={<Settings />} />
</Route>
```

### 8.3 Hook: session + expiry

`src/auth/useSession.ts`:

```ts
import { useEffect, useState } from "react";
import { useAuth } from "./AuthProvider";

/** Refreshes on tab focus so a session revoked elsewhere is noticed promptly. */
export function useSessionWatch() {
  const { status, refresh } = useAuth();

  useEffect(() => {
    if (status !== "authenticated") return;

    const onFocus = () => void refresh();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [status, refresh]);
}
```

`expires_at` is Unix **seconds**, not milliseconds:

```ts
function expiryDate(session: { expires_at: number }): Date {
  return new Date(session.expires_at * 1000);
}
```

Do not poll `/me` aggressively. Every successful call slides the idle deadline
forward (up to the absolute cap) and writes through the store, so a 10-second
poll keeps every session alive forever and multiplies store traffic. Refresh on
focus, after login, and after a mutation that changes identity.

---

## 9. Login, logout, and expiry

### 9.1 Login page

`src/pages/LoginPage.tsx`:

```tsx
import { useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider";

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [subject, setSubject] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const from =
    (location.state as { from?: { pathname?: string; search?: string } } | null)
      ?.from?.pathname ?? "/";

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    const trimmed = subject.trim();
    if (!trimmed) {
      setError("Enter a subject.");
      return;
    }

    setPending(true);
    setError(null);
    try {
      await login(trimmed);
      navigate(from, { replace: true });
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Login failed.",
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={onSubmit}>
      <h1>Sign in</h1>
      <label>
        Subject
        <input
          value={subject}
          onChange={(event) => setSubject(event.target.value)}
          autoComplete="username"
          disabled={pending}
        />
      </label>
      {error && <p role="alert">{error}</p>}
      <button type="submit" disabled={pending}>
        {pending ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
```

This is **not** a password form, because there is no password store. If you see
this in a production build, `AUTH_DEV_LOGIN` is still on and anyone can mint a
session for any subject. §17 covers the deployment gate.

Error messages worth mapping in the UI:

| Status | Body | Meaning |
| --- | --- | --- |
| `404` | `not found` | `AUTH_DEV_LOGIN` is off |
| `400` | `subject must not be empty` | Empty or whitespace-only subject |
| `400` | `subject exceeds the 1024-byte limit` | Subject too long |
| `415` | — | Missing/wrong `content-type: application/json` |
| `422` | — | Body missing the `subject` field |
| `500` | `internal server error` | Entropy or store failure; check server logs |

### 9.2 Logout

```tsx
function LogoutButton() {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [pending, setPending] = useState(false);

  async function onClick() {
    if (pending) return;
    setPending(true);
    try {
      await logout();
      navigate("/login", { replace: true });
    } catch {
      // Revocation failed; the cookie was intentionally not cleared.
      window.alert("Could not sign out. Try again.");
    } finally {
      setPending(false);
    }
  }

  return (
    <button onClick={onClick} disabled={pending}>
      {pending ? "Signing out…" : "Sign out"}
    </button>
  );
}
```

`POST /logout` always attempts to clear the cookie (`Max-Age=0`), so a stale
cookie from an earlier configuration is removed even when no credential can be
identified. There is no client-side id to delete in cookie mode, which is one
of the advantages of this setup.

### 9.3 Handling expiry

Two deadlines exist:

* **Idle TTL** (7 days by default). Every valid use slides it forward:
  `expires_at = min(now + ttl, issued_at + absolute_ttl)`.
* **Absolute TTL** (30 days by default), measured from creation. It never moves.

The browser's cookie `Max-Age` is refreshed on every cookie-authenticated
`/me`, so a user who keeps using the app keeps their cookie. When the absolute
cap is reached, `/me` returns `401`, the provider flips to `anonymous`, and
`RequireAuth` redirects to `/login`.

Because the whole flow is `401`-driven, you do not need a client-side timer. If
you want proactive UX, warn when the remaining time is short:

```ts
const secondsLeft = session.expires_at - Math.floor(Date.now() / 1000);
if (secondsLeft < 24 * 60 * 60) {
  // "Your session expires soon."
}
```

There is **no refresh endpoint**. `SessionManager::rotate` exists in Rust but is
not exposed over HTTP, so a React client cannot rotate its own id. Rotation
after a privilege change requires a server-side route you write yourself.

---

## 10. Endpoint reference

All endpoints are plain JSON or text. None of the four routes has an `OPTIONS`
handler, so preflight requests get `405`.

### `GET /health`

Public liveness probe. No credential, no side effects.

```
200 {"status":"ok"}
```

### `POST /sessions`

Development-only session mint. `404` unless `AUTH_DEV_LOGIN=1`.

Request:

```
Content-Type: application/json
{"subject":"user-1"}
```

Response (`201 Created`):

```jsonc
// AUTH_SESSION_DELIVERY=cookie (default)
{"subject":"user-1","expires_at":1763510400}

// AUTH_SESSION_DELIVERY=token
{"subject":"user-1","expires_at":1763510400,"session_id":"…43 chars…"}

// AUTH_SESSION_DELIVERY=both
{"subject":"user-1","expires_at":1763510400,"session_id":"…43 chars…"}
```

`sends_cookie()` modes also append:

```
Set-Cookie: session=<id or os1.…>; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax
```

Header: `Cache-Control: no-store`, `Pragma: no-cache`.

### `GET /me`

Request: cookie (or `Authorization: Bearer <id>` in any mode).

```
200 {"subject":"user-1","expires_at":1763510400,"source":"cookie"}
```

`source` is `"cookie"` or `"bearer"` — useful for telemetry and for asserting
which path a client is actually using.

In cookie mode the response also re-issues `Set-Cookie` with a fresh `Max-Age`
whenever the cookie is the carrier and the mode sends cookies. It does **not**
re-issue for `source: "bearer"`, and never in token mode.

Failures:

| Status | Body | Cause |
| --- | --- | --- |
| `401` | `authentication required` | Missing, unknown, expired, or forged credential; also any signature failure |
| `400` | `ambiguous credential cookie` | The cookie name appears twice in the request |
| `400` | `malformed credentials` | Bad `Authorization` scheme or malformed header |

`401` and `400` responses also carry `Cache-Control: no-store`.

### `POST /logout`

No body. Revokes whatever credential can be identified — including a cookie
that token mode would refuse to authenticate for `/me` — then clears the cookie.

```
204 No Content
Set-Cookie: session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
Cache-Control: no-store
Pragma: no-cache
```

Returns `204` even with no credential. Returns `500` if revocation fails, and in
that case the deletion cookie is **not** sent, so the client keeps its credential
and can retry.

### Cookie attributes (not configurable beyond name and `Secure`)

| Attribute | Value | Effect on React |
| --- | --- | --- |
| `Path` | `/` | Sent on every same-origin request, including `/api/*` |
| `HttpOnly` | always | `document.cookie` cannot see it; only `/me` reveals identity |
| `SameSite` | `Lax` | Blocks cross-site subrequests; top-level navigation still sends it |
| `Max-Age` | idle TTL, refreshed on `/me` | Browser drops it when the server would reject it |
| `Secure` | `AUTH_SESSION_COOKIE_SECURE` | Off for `http://localhost`; required elsewhere |
| `Domain` | unset | Host-only: no subdomain sharing |

Because `SameSite` is hard-coded to `Lax`, the app cannot be embedded as a
cross-site iframe and cannot authenticate cross-site `fetch` calls, even if
CORS were added. If you need embedded widgets, you have to change the server,
not the client.

---

## 11. Signed cookies and key rotation

Signing is opt-in and entirely transparent to React: the cookie is `HttpOnly`,
so the browser never exposes either form to your code.

```sh
# 32 random bytes, unpadded base64url
KEY=$(python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))")

AUTH_COOKIE_KEYS="k1:$KEY" cargo run -p oxsession-server
```

The wire value becomes `os1.k1.<payload>.<mac>`.

What this changes for the SPA:

* **Nothing in the client.** Same cookie, same endpoints.
* **Failure mode gets cheaper.** A tampered cookie fails the HMAC before any
  store lookup, so garbage traffic does not hit the store.
* **Rotation is invisible *if* `/me` keeps being called.** With
  `AUTH_COOKIE_KEYS="k2:<new>,k1:<old>"`, the first entry signs and the rest
  verify. `/me` re-signs with the current key on every cookie-authenticated
  call, so an active browser migrates to `k2` on its next request. An idle
  browser keeps working until the retired key is dropped, then gets `401` and
  must log in again.
* **`logs.md` is stale here.** It claims there is no `Set-Cookie` re-issue path
  for rotation. `routes.rs` re-issues on every cookie-authenticated `/me`, so
  rotation works for active clients without a re-login.

Two limits worth knowing:

* Signing is **not encryption**. The payload is readable — but in this setup it
  is inside `HttpOnly`, so page scripts still cannot read it. An attacker who
  can read the wire (e.g. a compromised proxy) can read the id; the signature
  only proves it was not modified.
* A raw id is still a valid bearer credential. If the id leaks, the signature
  does not save you. Revocation is the only remedy, which is why the id must
  never be logged.

Generate and store `AUTH_COOKIE_KEYS` outside the repo. Environment variables
are visible in `/proc/<pid>/environ`, `docker inspect`, and shell history.

---

## 12. Token mode and `localStorage`

Token mode is the escape hatch. It gives the body a `session_id` and stops
issuing **and accepting** cookies.

```sh
AUTH_DEV_LOGIN=1 AUTH_SESSION_DELIVERY=token cargo run -p oxsession-server
```

Client variant:

```ts
const STORAGE_KEY = "oxsession.session";

function bearer(): Record<string, string> {
  const id = localStorage.getItem(STORAGE_KEY);
  return id ? { authorization: `Bearer ${id}` } : {};
}

export async function tokenLogin(subject: string) {
  const response = await fetch("/api/sessions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ subject }),
    credentials: "omit", // keep a stale cookie out; token mode ignores it anyway
  });
  if (!response.ok) throw new Error(`login failed: ${response.status}`);

  const session = (await response.json()) as CreatedSession;
  if (!session.session_id) {
    throw new Error("no session_id; is AUTH_SESSION_DELIVERY=token?");
  }
  localStorage.setItem(STORAGE_KEY, session.session_id);
  return session;
}

export function tokenMe(signal?: AbortSignal) {
  return fetch("/api/me", {
    headers: bearer(),
    credentials: "omit",
    signal,
  });
}

export function tokenLogout() {
  localStorage.removeItem(STORAGE_KEY); // must happen even if the request fails
  return fetch("/api/logout", {
    method: "POST",
    headers: bearer(),
    credentials: "omit",
  });
}
```

Rules that differ from the cookie path:

* The body value is the **raw id**, never the `os1.…` wire value. A signed
  cookie value is not a valid bearer token (there is a test for this).
* Token mode ignores cookies completely — they are not even parsed. A cookie
  presented to `/me` in this mode is a `401`, not a fallback.
* `logout` still revokes a cookie the mode refuses for authentication, but this
  client has no cookie to revoke; the `localStorage` entry is yours to remove.
* **XSS is session theft.** Any script on the page can read `localStorage`.
  Prefer the cookie path for a browser app; use token mode when the client
  cannot hold a cookie (native apps, CLIs, some BFFs).
* CORS: token mode still needs the proxy (or a CORS layer), because the browser
  blocks cross-origin responses regardless of the carrier.

Migrating from the repo's `examples/localstorage.js` is mechanical: the shape of
`login`, `me`, and `logout` matches, only the framework wrapper changes.

---

## 13. Why direct cross-origin calls fail

`routes::router` is a bare Axum `Router`:

```rust
Router::new()
    .route("/health", get(health))
    .route("/me", get(me))
    .route("/sessions", post(create_session))
    .route("/logout", post(logout))
    .with_state(state)
```

There is no `tower-http` `CorsLayer`, no `OPTIONS` route, and no
`Access-Control-Allow-*` header anywhere in the workspace. Calling
`http://127.0.0.1:3000/me` from `http://localhost:5173` therefore fails at the
preflight (or at response filtering) with a CORS error — the request may reach
the server, but the browser refuses to hand the response to your code. The
failure is **not** a `401`, so do not debug it as an auth problem.

You have two options.

### Option A: proxy (recommended, this guide)

Use §6. Same-origin, no server change, cookies just work.

### Option B: add CORS to the server

This is a code change, not configuration. Add `tower-http` with the `cors`
feature to `crates/oxsession-server/Cargo.toml`, then:

```rust
use axum::http::{header, HeaderValue, Method};
use tower_http::cors::CorsLayer;

let cors = CorsLayer::new()
    .allow_origin("http://localhost:5173".parse::<HeaderValue>().unwrap())
    .allow_credentials(true)
    .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
    .allow_headers([header::CONTENT_TYPE]);

Router::new()
    // …routes…
    .layer(cors)
    .with_state(state)
```

Constraints:

* `allow_credentials(true)` forbids `allow_origin(Any)`. You must name every
  origin, and ideally read them from configuration instead of hard-coding.
* The response needs `Access-Control-Allow-Credentials: true`, which the layer
  adds. Without it the browser drops the `Set-Cookie`.
* `SameSite=Lax` still applies. `localhost:5173 → localhost:3000` is same-site
  (ports do not affect site), so cookies flow; a truly cross-site deployment
  would need `SameSite=None; Secure`, which the server hard-codes away.
* This does not exist today. Do not assume the repo already supports it.

---

## 14. Production deployment

The Rust binary serves **only** the four routes. It will not serve your React
build, and there is no static-file handler. Ship the SPA as static files and
put both behind one origin.

### 14.1 Build

```sh
# front end
npm run build          # → dist/

# server
cargo build --release -p oxsession-server
```

### 14.2 One origin with nginx

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name app.example.com;

    ssl_certificate     /etc/ssl/app.crt;
    ssl_certificate_key /etc/ssl/app.key;

    root /srv/my-app/dist;
    index index.html;

    # SPA fallback: client-side routes must not 404.
    location / {
        try_files $uri $uri/ /index.html;
    }

    # The four auth endpoints, same origin as the app.
    location = /health   { proxy_pass http://127.0.0.1:3000; }
    location = /me       { proxy_pass http://127.0.0.1:3000; }
    location = /sessions { proxy_pass http://127.0.0.1:3000; }
    location = /logout   { proxy_pass http://127.0.0.1:3000; }
}
```

If you keep the `/api` prefix in production, rewrite it the same way Vite does:

```nginx
location /api/ {
    proxy_pass http://127.0.0.1:3000/;   # trailing slash strips /api/
}
```

### 14.3 Server environment

```sh
AUTH_BIND_ADDR=127.0.0.1          # TLS is terminated by the proxy
AUTH_PORT=3000
AUTH_SESSION_COOKIE_SECURE=1      # mandatory off loopback
AUTH_SESSION_COOKIE=__Host-session
AUTH_SESSION_DELIVERY=cookie
AUTH_SESSION_TTL_SECONDS=604800
AUTH_SESSION_ABSOLUTE_TTL_SECONDS=2592000
AUTH_COOKIE_KEYS="k2:…,k1:…"
# AUTH_DEV_LOGIN must be absent
```

`__Host-session` is the strongest name: it forces `Secure`, `Path=/`, and no
`Domain`, so a sibling subdomain cannot overwrite it. It requires
`AUTH_SESSION_COOKIE_SECURE=1` at startup, which you are already setting.

### 14.4 Deployment checklist

* [ ] `AUTH_DEV_LOGIN` is **not** set (otherwise anyone can mint a session).
* [ ] `AUTH_SESSION_COOKIE_SECURE=1` and the site is HTTPS-only.
* [ ] Session cookie is `HttpOnly`, `Path=/`, `SameSite=Lax` (verify in DevTools).
* [ ] `/me`, `/sessions`, `/logout` responses carry `Cache-Control: no-store`.
* [ ] Session ids never appear in access logs. The server logs errors, not ids;
      your proxy must not log `Cookie` or `Set-Cookie`.
* [ ] `AUTH_COOKIE_KEYS` comes from a secret store, not a committed file.
* [ ] The React build has no `VITE_*` secret. Vite inlines `VITE_*` into the
      bundle; signing keys must never be named `VITE_…`.
* [ ] A durable `SessionStore` is planned. `MemoryStore` loses every session on
      restart and does not share across processes.

Restarting the server with `MemoryStore` invalidates all sessions. Every open
tab gets `401` on its next `/me` and lands on the login page — correct behavior,
surprising during a deploy if you did not expect it.

---

## 15. Next.js and server-side rendering

The cookie path assumes the browser and the origin are the same. In Next.js:

* **Client components** can use the same client and provider as above, with a
  `next.config.js` rewrite standing in for the Vite proxy.
* **Server components** cannot read `HttpOnly` cookies through `document`, but
  they can read the request's `Cookie` header and forward it.
* `localStorage` does not exist during SSR, so token mode cannot be the primary
  path for server-rendered routes.

### 15.1 Rewrite for development

`next.config.js`:

```js
/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      { source: "/api/:path*", destination: "http://127.0.0.1:3000/:path*" },
    ];
  },
};

module.exports = nextConfig;
```

In the App Router, `rewrites` do **not** apply to `fetch` made in server
components during `next build`/SSR; you need an absolute URL and a forwarded
cookie there.

### 15.2 Forwarding the cookie from a server component

```tsx
// app/dashboard/page.tsx
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

export default async function DashboardPage() {
  const cookieHeader = (await cookies()).toString();

  const response = await fetch(`${process.env.OXSESSION_URL}/me`, {
    headers: { cookie: cookieHeader },
    cache: "no-store",
  });

  if (response.status === 401) redirect("/login");
  if (!response.ok) throw new Error(`auth service: ${response.status}`);

  const session = (await response.json()) as {
    subject: string;
    expires_at: number;
    source: "cookie" | "bearer";
  };

  return <h1>Hello, {session.subject}</h1>;
}
```

Caveats specific to this approach:

* `Set-Cookie` from the upstream `/me` is **not** forwarded to the browser by a
  server-component `fetch`, so the sliding `Max-Age` refresh is lost. Either
  accept that the browser cookie expires on its mint-time schedule, or proxy
  through a route handler that copies `Set-Cookie`.
* `cookies()` in Next 15 is async; in Next 14 it is synchronous.
* Use a route handler for login/logout so `Set-Cookie` and `204` reach the
  browser:

```ts
// app/api/[...path]/route.ts
import { NextRequest } from "next/server";

const UPSTREAM = process.env.OXSESSION_URL!;

async function forward(request: NextRequest, path: string[]) {
  const upstream = await fetch(`${UPSTREAM}/${path.join("/")}`, {
    method: request.method,
    headers: {
      cookie: request.headers.get("cookie") ?? "",
      "content-type": request.headers.get("content-type") ?? "application/json",
    },
    body:
      request.method === "POST" ? await request.text() : undefined,
    cache: "no-store",
    redirect: "manual",
  });

  const headers = new Headers();
  const setCookie = upstream.headers.get("set-cookie");
  if (setCookie) headers.set("set-cookie", setCookie);
  headers.set("cache-control", "no-store");

  return new Response(
    upstream.status === 204 ? null : await upstream.text(),
    { status: upstream.status, headers },
  );
}

export async function GET(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return forward(request, (await context.params).path);
}

export async function POST(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return forward(request, (await context.params).path);
}
```

This route is a hand-written BFF. It is worth it only if you need SSR. A
client-rendered app with the Vite proxy is simpler and has fewer places for a
credential to leak.

### 15.3 Using the Node addon in a BFF

`oxsession-node` runs in Node, so a BFF can use it instead of the HTTP server:

```js
const express = require("express");
const cookieParser = require("cookie-parser");
const { SessionManager } = require("oxsession-node");

const sessions = new SessionManager(604800, 2592000);
const app = express();
app.use(express.json());
app.use(cookieParser());

app.post("/api/sessions", async (request, response) => {
  const session = await sessions.create(request.body.subject);
  // You now own cookie serialization, signing, expiry, and logout.
  response.status(201).json({ subject: session.subject, expires_at: session.expiresAt });
});

app.get("/api/me", async (request, response) => {
  const id = request.cookies?.session;
  if (!id) return response.status(401).end();
  try {
    const session = await sessions.validate(id);
    return response.json({
      subject: session.subject,
      expires_at: session.expiresAt,
      source: "cookie",
    });
  } catch {
    return response.status(401).end();
  }
});

app.listen(4000);
```

The addon's `MemoryStore` is process-local and non-durable, exactly like the
Rust server's. It also means you reimplement the cookie contract that
`oxsession-server` already enforces. Prefer running the Rust server unless you
need Node-only integrations; if you do use the addon, copy the cookie rules from
`docs/sessions.md` rather than inventing them.

---

## 16. Testing with MSW and Vitest

The client is a thin `fetch` wrapper, so MSW covers it without touching the
network.

```sh
npm install -D vitest @testing-library/react @testing-library/jest-dom msw jsdom
```

`src/test/handlers.ts`:

```ts
import { http, HttpResponse } from "msw";

/**
 * MSW does not emulate the browser's cookie jar, so a handler that inspects
 * `request.headers.get("cookie")` would always see nothing. Model the
 * server-side session explicitly instead.
 */
export const authState = { signedIn: false };

export function resetAuthState() {
  authState.signedIn = false;
}

export const handlers = [
  http.get("/api/me", () => {
    if (!authState.signedIn) {
      return new HttpResponse("authentication required", {
        status: 401,
        headers: { "cache-control": "no-store" },
      });
    }
    return HttpResponse.json({
      subject: "user-1",
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      source: "cookie",
    });
  }),

  http.post("/api/sessions", async ({ request }) => {
    const body = (await request.json()) as { subject?: string };
    if (!body.subject?.trim()) {
      return new HttpResponse("subject must not be empty", { status: 400 });
    }
    authState.signedIn = true;
    return HttpResponse.json(
      { subject: body.subject, expires_at: Math.floor(Date.now() / 1000) + 3600 },
      { status: 201 },
    );
  }),

  http.post("/api/logout", () => {
    authState.signedIn = false;
    return new HttpResponse(null, {
      status: 204,
      headers: { "set-cookie": "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax" },
    });
  }),

  http.get("/api/health", () => HttpResponse.json({ status: "ok" })),
];
```

`src/test/server.ts`:

```ts
import { setupServer } from "msw/node";
import { handlers } from "./handlers";

export const server = setupServer(...handlers);
```

`src/test/setup.ts`:

```ts
import "@testing-library/jest-dom/vitest";
import { afterAll, afterEach, beforeAll } from "vitest";
import { server } from "./server";
import { resetAuthState } from "./handlers";

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  resetAuthState();
});
afterAll(() => server.close());
```

`vite.config.ts` test block (import `defineConfig` from `"vitest/config"` so the
`test` key type-checks):

```ts
test: {
  environment: "jsdom",
  setupFiles: ["./src/test/setup.ts"],
},
```

A provider test:

```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuthProvider, useAuth } from "../auth/AuthProvider";

function Probe() {
  const { status, session, login } = useAuth();
  return (
    <div>
      <span data-testid="status">{status}</span>
      <span data-testid="subject">{session?.subject ?? ""}</span>
      <button onClick={() => void login("user-1")}>login</button>
    </div>
  );
}

it("starts anonymous when /me is 401 and signs in", async () => {
  render(
    <AuthProvider>
      <Probe />
    </AuthProvider>,
  );

  expect(await screen.findByTestId("status")).toBeInTheDocument();

  await waitFor(() =>
    expect(screen.getByTestId("status")).toHaveTextContent("anonymous"),
  );

  await userEvent.click(screen.getByRole("button", { name: "login" }));

  await waitFor(() =>
    expect(screen.getByTestId("status")).toHaveTextContent("authenticated"),
  );
  expect(screen.getByTestId("subject")).toHaveTextContent("user-1");
});
```

Note the explicit `authState` flag: MSW does not emulate the browser cookie jar,
so "the cookie was sent" cannot be asserted at this layer. That is fine for the
client, which never reads the cookie — but cookie refresh and revocation must be
asserted against the real server (§5.2) or in an integration test that runs it.

---

## 17. Security checklist

Cookie mode is the safer default, but it is not magic. Each item below maps to a
real property of the code.

**Credential handling**

* The session id is a bearer credential. It is 32 random bytes, base64url, 43
  chars. Never log it, never put it in analytics, never render it.
* `HttpOnly` keeps it out of `document.cookie`, so XSS cannot read it — but XSS
  can still *use* the session by issuing same-origin requests. XSS is a
  compromise either way; `HttpOnly` only removes exfiltration.
* `Set-Cookie` never carries `Domain`, so the cookie is host-only. Keep
  `__Host-session` in production to prevent a sibling subdomain from shadowing
  it.

**CSRF**

* `SameSite=Lax` blocks cookies on cross-site `POST`/`fetch`, which covers the
  common case.
* It does **not** cover same-site attackers (a compromised sibling subdomain)
  and it does not cover clients that ignore `SameSite`.
* There is no CSRF token and no `Origin`/`Referer` check in the server. If your
  threat model includes same-site attackers, add an origin check in a proxy or
  in the server; the client cannot fix it.

**Session lifecycle**

* Logout revokes server-side, immediately. There is no JWT denylist problem.
* Expiry is enforced server-side on every request; the cookie's `Max-Age` is a
  hint, not the authority.
* `MemoryStore` is process-local. A restart logs everyone out; two server
  processes do not share sessions. Sticky sessions or a durable adapter are
  required for horizontal scaling.
* `MemoryStore` evicts the session closest to expiry when full. A session flood
  can evict legitimate users. There is no rate limiting on `POST /sessions` or
  `/logout`.

**Transport and deployment**

* The binary speaks plain HTTP and has no TLS. Terminate TLS at a proxy and set
  `AUTH_SESSION_COOKIE_SECURE=1`.
* Secrets live in environment variables with no file/secret-manager loader.
  Prefer your platform's secret injection over a checked-in `.env`.
* `AUTH_DEV_LOGIN` mints sessions for any subject. It must never be enabled
  outside local development. Add a build/deploy gate that fails if it is set.
* There is no `/health` readiness check against the store, no metrics, and no
  structured logging. A spike in forged cookies is invisible today.

**Front-end specifically**

* Do not cache `/me` responses in a service worker, React Query with a long
  `staleTime` plus persistence, or `localStorage`. Identity is per-request.
* Do not mirror `session.subject` into `localStorage` as an auth decision. It is
  display state; the server decides authorization.
* If you must show a "remember me" toggle, note that the server always sets a
  persistent cookie with `Max-Age`; there is no session-cookie mode.
* Keep `AUTH_DEV_LOGIN` off in previews and staging shared with untrusted users.

---

## 18. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `POST /sessions` → `404` | `AUTH_DEV_LOGIN` unset | Start the server with `AUTH_DEV_LOGIN=1` |
| `POST /sessions` → `415` | Missing `content-type: application/json` | Set the header in the client |
| `POST /sessions` → `422` | Body lacks `subject` | Send `{"subject":"..."}` |
| `POST /sessions` → `400 subject must not be empty` | Empty/whitespace subject | Validate client-side too |
| Login succeeds, `/me` → `401` | Cookie not stored or not sent | Check DevTools → Application → Cookies; verify proxy and `Secure` |
| `/me` → `401` right after a server restart | `MemoryStore` lost the session | Expected; log in again |
| `/me` → `401` only in token mode | Token mode rejects cookies by design | Use `AUTH_SESSION_DELIVERY=both` while migrating, or send `Authorization: Bearer` |
| `/me` → `400 ambiguous credential cookie` | Two `session=` cookies on the request | Clear stale cookies; check for a duplicate `Set-Cookie` from an old deployment |
| Browser shows a CORS error, no status | Calling `:3000` directly from `:5173` | Use the Vite proxy (§6) or add CORS (§13) |
| `Set-Cookie` visible in response but no cookie stored | `AUTH_SESSION_COOKIE_SECURE=1` over `http://` | Set it to `0` for localhost, or use HTTPS |
| Cookie stored but not sent on `/api/*` | Cookie `Path` or proxy rewrite wrong | Cookie is `Path=/`; verify the request path after rewrite |
| `/me` works with `curl` but not in the browser | Browser is using a different host (`127.0.0.1` vs `localhost`) | Use one host consistently; cookies are host-scoped |
| Login loops back to `/login` | `refresh()` failed for a non-auth reason (proxy down) | Render `error` from `useAuth`; fix the proxy |
| `logout` → `500` | Revocation failed (store error) | The cookie is intentionally not cleared; retry, check server logs |
| `manifest`/`fetch` works but SSR 401s | Next.js server component has no browser cookie | Forward the `Cookie` header (§15.2) |
| Session dies after ~7 days of activity | Server was started with a short TTL, or the absolute cap was reached | Check `AUTH_SESSION_TTL_SECONDS` and `AUTH_SESSION_ABSOLUTE_TTL_SECONDS` |
| Session dies on every deploy | Non-durable store | Expected until a durable adapter exists |

Debugging sequence that resolves most reports:

1. `curl -i http://127.0.0.1:3000/health` — is the server up?
2. `curl -i -c jar -H 'content-type: application/json' -d '{"subject":"u"}' http://127.0.0.1:3000/sessions` — does minting work?
3. `curl -i -b jar http://127.0.0.1:3000/me` — does the cookie authenticate outside the browser?
4. DevTools → Network → the `/api/me` request: is `Cookie` present? Is the response `401` or a CORS failure?
5. DevTools → Application → Cookies for the **app** origin: is `session` there, with `HttpOnly` and the right expiry?
6. Repeat with the proxy disabled? It should fail; if it succeeds, you patched something you forgot about.

---

## 19. What this library does not do yet

A React app can be built today against these four endpoints, but it is a
development-grade auth layer. Missing pieces, with the workaround a React team
would need:

| Gap | Impact on a React app | Workaround |
| --- | --- | --- |
| No OIDC / identity provider | `POST /sessions` trusts any subject | Keep `AUTH_DEV_LOGIN` out of production; write your own identity route against `SessionManager` |
| No password/user store | No registration, no credentials | External IdP, then mint a session server-side |
| No durable store | Logout on restart, no multi-node | Sticky sessions for now; PostgreSQL/SQLite/Redis adapter is roadmap |
| No CORS layer | Cross-origin dev calls fail | Vite proxy (§6) or patch the router (§13) |
| No static file serving | Rust binary cannot host the SPA | Serve `dist/` from nginx/Caddy and proxy the four routes |
| No refresh/rotate endpoint | Cannot rotate after privilege change | Add a route that calls `SessionManager::rotate` |
| No CSRF token or origin check | Same-site attacks are open | Add an `Origin` check at the proxy |
| No rate limiting | Session flood can evict users | Rate-limit at the proxy |
| Plain-text error bodies | Client must branch on status | Typed `OxsessionError` (§7) |
| No JWT / JWKS | No token-based federation | Not available; sessions are opaque by design |
| No structured logging/metrics | Hard to detect forgery spikes | Proxy logs plus your own metrics |
| No CI | Regressions go unnoticed | Add `cargo test --workspace` to CI |

The honest summary: the library gives you a correct, well-tested **session
primitive** and a small HTTP surface. Everything above the session — who the
user is, how they proved it, where sessions live — is still yours to supply.
The React integration in this guide is therefore mostly about the boundary:
one origin, one credential carrier, one `401`-driven state machine.

---

## Appendix A: file layout used in this guide

```
my-app/
├── index.html
├── package.json
├── tsconfig.json
├── vite.config.ts
└── src/
    ├── main.tsx
    ├── App.tsx
    ├── vite-env.d.ts
    ├── lib/
    │   └── oxsession.ts
    ├── auth/
    │   ├── AuthProvider.tsx
    │   ├── RequireAuth.tsx
    │   └── useSession.ts
    ├── pages/
    │   ├── LoginPage.tsx
    │   └── Dashboard.tsx
    └── test/
        ├── handlers.ts
        ├── server.ts
        └── setup.ts
```

## Appendix B: minimal `App.tsx`

```tsx
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./auth/AuthProvider";
import { RequireAuth } from "./auth/RequireAuth";
import { LoginPage } from "./pages/LoginPage";
import { Dashboard } from "./pages/Dashboard";

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<RequireAuth />}>
            <Route path="/" element={<Dashboard />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
```

## Appendix C: `Dashboard.tsx`

```tsx
import { useState } from "react";
import { useAuth } from "../auth/AuthProvider";
import { useSessionWatch } from "../auth/useSession";

export function Dashboard() {
  const { session, logout } = useAuth();
  const [error, setError] = useState<string | null>(null);
  useSessionWatch();

  if (!session) return null;

  async function onLogout() {
    setError(null);
    try {
      await logout();
    } catch {
      setError("Could not sign out. Try again.");
    }
  }

  return (
    <main>
      <h1>Signed in as {session.subject}</h1>
      <p>
        Expires {new Date(session.expires_at * 1000).toLocaleString()} · via{" "}
        {session.source}
      </p>
      {error && <p role="alert">{error}</p>}
      <button onClick={() => void onLogout()}>Sign out</button>
    </main>
  );
}
```

## Appendix D: curl equivalents for every call the SPA makes

```sh
BASE=http://127.0.0.1:3000
JAR=/tmp/ox.jar

# health
curl -s "$BASE/health"

# login (cookie mode: no session_id in the body)
curl -s -i -c "$JAR" -H 'content-type: application/json' \
     -d '{"subject":"user-1"}' "$BASE/sessions"

# who am I (also refreshes Max-Age)
curl -s -i -b "$JAR" "$BASE/me"

# logout
curl -s -i -b "$JAR" -X POST "$BASE/logout"

# token mode — restart the server with AUTH_SESSION_DELIVERY=token first
ID=$(curl -s -H 'content-type: application/json' \
     -d '{"subject":"user-1"}' "$BASE/sessions" | jq -r .session_id)
curl -s -i -H "authorization: Bearer $ID" "$BASE/me"
```

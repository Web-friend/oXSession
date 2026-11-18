// Minimal browser client that keeps the session id in `localStorage`.
//
// The server must run with AUTH_SESSION_DELIVERY=token (or `both`), because a
// `localStorage` client needs the id in the response body. With the default
// `cookie` delivery the body has no `session_id` and this file cannot work.
//
// The id is a bearer credential. Unlike an HttpOnly cookie it is readable by
// any script on the page, so an XSS bug becomes a session theft. The upside is
// that it is never sent automatically: cross-site requests carry no ambient
// credential, so the usual CSRF defenses are unnecessary.

const STORAGE_KEY = "oxsession.session";

export function currentSessionId() {
  return localStorage.getItem(STORAGE_KEY);
}

// `credentials: "omit"` keeps a stale cookie (from an earlier deployment) out
// of the request, so exactly one credential is ever presented.
async function send(path, init = {}) {
  const headers = { ...(init.headers ?? {}) };
  const id = currentSessionId();
  if (id) headers.authorization = `Bearer ${id}`;

  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "omit",
  });

  // The server is the source of truth: it rejects revoked and expired ids, so
  // a 401 means the stored credential is worthless and should be dropped.
  if (response.status === 401) {
    localStorage.removeItem(STORAGE_KEY);
  }
  return response;
}

export async function login(subject) {
  const response = await fetch("/sessions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ subject }),
    credentials: "omit",
  });
  if (!response.ok) {
    throw new Error(`login failed: ${response.status}`);
  }

  const session = await response.json();
  if (!session.session_id) {
    throw new Error("server did not return a session_id; is AUTH_SESSION_DELIVERY=token?");
  }
  localStorage.setItem(STORAGE_KEY, session.session_id);
  return session;
}

export async function me() {
  const response = await send("/me");
  return response.ok ? response.json() : null;
}

export async function logout() {
  const response = await send("/logout", { method: "POST" });
  localStorage.removeItem(STORAGE_KEY);
  return response.status;
}

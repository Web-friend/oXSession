//! End-to-end tests for the session endpoints.
//!
//! These go through the real router, the real manager, and the real in-memory
//! store, so a request is the only thing that is simulated.

use std::collections::HashMap;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc, RwLock};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use oxsession_core::{Session, SessionId, SessionStore};
use oxsession_server::{
    config::{Config, SessionDelivery},
    routes,
    state::AppState,
};
use oxsession_session::{Policy, SessionManager};
use oxsession_sign::{CookieSigner, KeyId, SecretKey};
use tower::ServiceExt;

struct Reply {
    status: StatusCode,
    set_cookie: Option<String>,
    cache_control: Option<String>,
    pragma: Option<String>,
    body: String,
}

fn config() -> Config {
    Config {
        bind_address: "127.0.0.1:0".parse().unwrap(),
        session_cookie: "session".to_owned(),
        policy: Policy::new(3_600, 86_400).unwrap(),
        session_cookie_secure: false,
        dev_login: true,
        session_delivery: SessionDelivery::Cookie,
        signer: None,
    }
}

fn unsigned_app() -> Router {
    routes::router(config())
}

fn unsigned_app_with(delivery: SessionDelivery) -> Router {
    let mut config = config();
    config.session_delivery = delivery;
    routes::router(config)
}

fn signed_app() -> Router {
    signed_app_with(SessionDelivery::Cookie)
}

fn signed_app_with(delivery: SessionDelivery) -> Router {
    let mut config = config();
    config.session_delivery = delivery;
    config.signer = Some(Arc::new(CookieSigner::new(
        KeyId::new("k1").unwrap(),
        SecretKey::from_slice(&[7; 32]).unwrap(),
    )));
    routes::router(config)
}

async fn call(
    app: Router,
    method: &str,
    uri: &str,
    body: Option<&str>,
    cookie: Option<&str>,
) -> Reply {
    request(app, method, uri, body, cookie, None).await
}

/// Same as [`call`], but with an `Authorization: Bearer` credential and no
/// cookie, which is how a `localStorage` client talks to the server.
async fn call_bearer(app: Router, method: &str, uri: &str, token: &str) -> Reply {
    request(app, method, uri, None, None, Some(token)).await
}

/// Send both carriers at once, to pin down the precedence rule.
async fn call_both(app: Router, method: &str, uri: &str, cookie: &str, token: &str) -> Reply {
    request(app, method, uri, None, Some(cookie), Some(token)).await
}

async fn request(
    app: Router,
    method: &str,
    uri: &str,
    body: Option<&str>,
    cookie: Option<&str>,
    token: Option<&str>,
) -> Reply {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = builder
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_owned())))
        .unwrap();

    reply(app.oneshot(request).await.unwrap()).await
}

async fn reply(response: axum::response::Response) -> Reply {
    let status = response.status();
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let cache_control = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let pragma = response
        .headers()
        .get(header::PRAGMA)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();

    Reply {
        status,
        set_cookie,
        cache_control,
        pragma,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

fn cookie_pair(set_cookie: &str) -> &str {
    set_cookie.split(';').next().unwrap().trim()
}

/// Pull `"<field>":<number>` out of the tiny JSON bodies these tests assert on.
fn field_u64(body: &str, name: &str) -> Option<u64> {
    let key = format!("\"{name}\":");
    let start = body.find(&key)? + key.len();
    let rest = &body[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit())?;
    rest[..end].parse().ok()
}

fn short_config() -> Config {
    let mut config = config();
    config.policy = Policy::new(2, 100).unwrap();
    config
}

fn short_app() -> Router {
    routes::router(short_config())
}

fn short_app_with(delivery: SessionDelivery) -> Router {
    let mut config = short_config();
    config.session_delivery = delivery;
    routes::router(config)
}

/// Pull `"<field>":"<value>"` out of the tiny JSON bodies these tests assert on.
fn field<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("\"{name}\":\"");
    let start = body.find(&key)? + key.len();
    let rest = &body[start..];
    Some(&rest[..rest.find('"')?])
}

#[tokio::test]
async fn login_creates_a_session_the_client_can_use() {
    let app = unsigned_app();
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;

    assert_eq!(created.status, StatusCode::CREATED);
    assert!(created.body.contains(r#""subject":"user-1""#));
    let cookie = cookie_pair(created.set_cookie.as_deref().unwrap()).to_owned();
    assert!(cookie.starts_with("session="));

    let me = call(app, "GET", "/me", None, Some(&cookie)).await;
    assert_eq!(me.status, StatusCode::OK);
    assert!(me.body.contains(r#""subject":"user-1""#));
    assert!(me.body.contains(r#""source":"cookie""#));
}

#[tokio::test]
async fn me_without_credentials_is_unauthorized() {
    let reply = call(unsigned_app(), "GET", "/me", None, None).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_session_ids_are_unauthorized() {
    let cookie = format!("session={}", "a".repeat(43));
    let reply = call(unsigned_app(), "GET", "/me", None, Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_session_ids_are_unauthorized() {
    let reply = call(unsigned_app(), "GET", "/me", None, Some("session=short")).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn dev_login_is_absent_when_disabled() {
    let mut config = config();
    config.dev_login = false;
    let reply = call(
        routes::router(config),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn empty_subjects_are_rejected() {
    let reply = call(
        unsigned_app(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"   "}"#),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn logout_revokes_the_session_and_clears_the_cookie() {
    let app = unsigned_app();
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    let cookie = cookie_pair(created.set_cookie.as_deref().unwrap()).to_owned();

    let logged_out = call(app.clone(), "POST", "/logout", None, Some(&cookie)).await;
    assert_eq!(logged_out.status, StatusCode::NO_CONTENT);
    assert!(
        logged_out
            .set_cookie
            .as_deref()
            .unwrap()
            .starts_with("session=;")
    );
    assert!(
        logged_out
            .set_cookie
            .as_deref()
            .unwrap()
            .contains("Max-Age=0")
    );

    let me = call(app, "GET", "/me", None, Some(&cookie)).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn signed_mode_issues_and_accepts_signed_cookies() {
    let app = signed_app();
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;

    let cookie = cookie_pair(created.set_cookie.as_deref().unwrap()).to_owned();
    assert!(
        cookie.starts_with("session=os1.k1."),
        "expected a signed cookie, got {cookie}"
    );

    let me = call(app, "GET", "/me", None, Some(&cookie)).await;
    assert_eq!(me.status, StatusCode::OK);
    assert!(me.body.contains(r#""subject":"user-1""#));
}

#[tokio::test]
async fn signed_mode_rejects_unsigned_cookies() {
    let cookie = format!("session={}", "a".repeat(43));
    let reply = call(signed_app(), "GET", "/me", None, Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bearer_tokens_use_the_session_id_directly() {
    let app = unsigned_app_with(SessionDelivery::Token);
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-2"}"#),
        None,
    )
    .await;
    let id = field(&created.body, "session_id").unwrap().to_owned();

    let me = call_bearer(app, "GET", "/me", &id).await;
    assert_eq!(me.status, StatusCode::OK);
    assert!(me.body.contains(r#""subject":"user-2""#));
    assert!(me.body.contains(r#""source":"bearer""#));
}

#[tokio::test]
async fn token_delivery_returns_the_id_and_sets_no_cookie() {
    let created = call(
        unsigned_app_with(SessionDelivery::Token),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;

    assert_eq!(created.status, StatusCode::CREATED);
    assert!(
        created.set_cookie.is_none(),
        "token mode must not set a cookie"
    );

    let id = field(&created.body, "session_id").expect("session_id must be in the body");
    assert!(oxsession_core::is_valid_session_id(id));
    assert_eq!(id.len(), 43);
    // The body carries the raw id, never the signed wire value.
    assert!(!id.starts_with("os1."));
}

#[tokio::test]
async fn cookie_delivery_never_leaks_the_id_into_the_body() {
    let created = call(
        unsigned_app(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;

    assert!(created.set_cookie.is_some());
    assert!(!created.body.contains("session_id"));
}

#[tokio::test]
async fn both_delivery_sends_the_same_credential_twice() {
    let app = unsigned_app_with(SessionDelivery::Both);
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;

    let id = field(&created.body, "session_id").unwrap().to_owned();
    let cookie = cookie_pair(created.set_cookie.as_deref().unwrap()).to_owned();
    assert_eq!(cookie, format!("session={id}"));

    assert_eq!(
        call_bearer(app, "GET", "/me", &id).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn session_responses_are_not_cacheable() {
    let created = call(
        unsigned_app_with(SessionDelivery::Token),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    assert_eq!(created.cache_control.as_deref(), Some("no-store"));
}

#[tokio::test]
async fn logout_revokes_a_token_session() {
    let app = unsigned_app_with(SessionDelivery::Token);
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    let id = field(&created.body, "session_id").unwrap().to_owned();

    let logged_out = call_bearer(app.clone(), "POST", "/logout", &id).await;
    assert_eq!(logged_out.status, StatusCode::NO_CONTENT);

    // The id is revoked server-side; the client dropping it is not trusted.
    assert_eq!(
        call_bearer(app, "GET", "/me", &id).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn token_delivery_still_works_with_a_signer() {
    // Signing protects the cookie channel; a client holding the raw id uses the
    // bearer channel, which is verified by lookup alone.
    let mut config = config();
    config.session_delivery = SessionDelivery::Token;
    config.signer = Some(Arc::new(CookieSigner::new(
        KeyId::new("k1").unwrap(),
        SecretKey::from_slice(&[7; 32]).unwrap(),
    )));

    let app = routes::router(config);
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-3"}"#),
        None,
    )
    .await;

    let id = field(&created.body, "session_id").unwrap().to_owned();
    let me = call_bearer(app, "GET", "/me", &id).await;
    assert_eq!(me.status, StatusCode::OK);
    assert!(me.body.contains(r#""subject":"user-3""#));
}

#[tokio::test]
async fn a_signed_cookie_is_not_a_valid_bearer_token() {
    // The wire value carries the signature; presenting it as a bearer token
    // must fail the session lookup rather than being parsed as a session id.
    let app = signed_app();
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    let wire = cookie_pair(created.set_cookie.as_deref().unwrap())
        .trim_start_matches("session=")
        .to_owned();
    assert!(wire.starts_with("os1."));

    assert_eq!(
        call_bearer(app, "GET", "/me", &wire).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn signed_both_mode_returns_the_raw_id_alongside_a_signed_cookie() {
    let app = signed_app_with(SessionDelivery::Both);
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-4"}"#),
        None,
    )
    .await;

    let id = field(&created.body, "session_id").unwrap();
    let wire = cookie_pair(created.set_cookie.as_deref().unwrap()).trim_start_matches("session=");
    assert!(wire.starts_with("os1.k1."), "cookie must be signed");
    assert_ne!(id, wire, "the body must not carry the signed wire value");
    assert_eq!(id.len(), 43);

    assert_eq!(
        call_bearer(app, "GET", "/me", id).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn token_mode_rejects_cookie_authentication() {
    // Issuing no cookie is not a security property on its own: if the server
    // still accepted one, any ambient cookie would authenticate the request.
    let app = unsigned_app_with(SessionDelivery::Token);
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    let id = field(&created.body, "session_id").unwrap().to_owned();

    let reply = call(app, "GET", "/me", None, Some(&format!("session={id}"))).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn both_mode_still_accepts_cookies() {
    let app = unsigned_app_with(SessionDelivery::Both);
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    let id = field(&created.body, "session_id").unwrap().to_owned();

    let me = call(app, "GET", "/me", None, Some(&format!("session={id}"))).await;
    assert_eq!(me.status, StatusCode::OK);
    assert!(me.body.contains(r#""source":"cookie""#));
}

#[tokio::test]
async fn logout_revokes_even_when_the_mode_rejects_the_carrier() {
    // A token-only deployment must still be able to kill a session presented
    // as a cookie, otherwise that id stays valid until it expires.
    let app = unsigned_app_with(SessionDelivery::Token);
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    let id = field(&created.body, "session_id").unwrap().to_owned();

    let logged_out = call(
        app.clone(),
        "POST",
        "/logout",
        None,
        Some(&format!("session={id}")),
    )
    .await;
    assert_eq!(logged_out.status, StatusCode::NO_CONTENT);

    assert_eq!(
        call_bearer(app, "GET", "/me", &id).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn bearer_wins_over_a_tampered_cookie() {
    let app = signed_app_with(SessionDelivery::Both);
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    let id = field(&created.body, "session_id").unwrap().to_owned();
    let mut wire = cookie_pair(created.set_cookie.as_deref().unwrap())
        .trim_start_matches("session=")
        .to_owned();
    let last = wire.pop().unwrap();
    wire.push(if last == 'A' { 'B' } else { 'A' });

    let me = call_both(app, "GET", "/me", &format!("session={wire}"), &id).await;
    assert_eq!(me.status, StatusCode::OK, "the bearer must win");
    assert!(me.body.contains(r#""source":"bearer""#));
}

#[tokio::test]
async fn authenticated_responses_are_not_cacheable() {
    let app = unsigned_app();
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    assert_eq!(created.cache_control.as_deref(), Some("no-store"));
    assert_eq!(created.pragma.as_deref(), Some("no-cache"));

    let cookie = cookie_pair(created.set_cookie.as_deref().unwrap()).to_owned();

    let me = call(app.clone(), "GET", "/me", None, Some(&cookie)).await;
    assert_eq!(me.cache_control.as_deref(), Some("no-store"));
    assert_eq!(me.pragma.as_deref(), Some("no-cache"));

    // The failure path must not be cacheable either.
    let denied = call(app.clone(), "GET", "/me", None, Some("session=short")).await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
    assert_eq!(denied.cache_control.as_deref(), Some("no-store"));

    // Nor may a logout be replayed from a cache.
    let logged_out = call(app, "POST", "/logout", None, Some(&cookie)).await;
    assert_eq!(logged_out.status, StatusCode::NO_CONTENT);
    assert_eq!(logged_out.cache_control.as_deref(), Some("no-store"));
    assert_eq!(logged_out.pragma.as_deref(), Some("no-cache"));
}

#[tokio::test]
async fn token_mode_never_parses_the_cookie() {
    // A duplicate credential cookie is a `400` in cookie mode because the
    // ambiguity is the client's fault. In token mode the cookie is not a
    // credential at all, so it must not change the answer: `401`.
    let app = unsigned_app_with(SessionDelivery::Token);
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    let id = field(&created.body, "session_id").unwrap().to_owned();

    let reply = call(
        app,
        "GET",
        "/me",
        None,
        Some(&format!("session={id}; session={id}")),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cookie_mode_still_reports_ambiguous_cookies() {
    let app = unsigned_app();
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    let id = cookie_pair(created.set_cookie.as_deref().unwrap())
        .trim_start_matches("session=")
        .to_owned();

    let reply = call(
        app,
        "GET",
        "/me",
        None,
        Some(&format!("session={id}; session={id}")),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

/// A store whose `delete` can be made to fail, to exercise the logout
/// error-surfacing path without breaking a real adapter.
struct RevokeFailsStore {
    sessions: RwLock<HashMap<SessionId, Session>>,
    fail_delete: AtomicBool,
}

impl RevokeFailsStore {
    fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            fail_delete: AtomicBool::new(false),
        }
    }
}

impl SessionStore for RevokeFailsStore {
    type Error = std::io::Error;

    async fn insert(&self, session: Session) -> Result<(), Self::Error> {
        self.sessions
            .write()
            .unwrap()
            .insert(session.id().clone(), session);
        Ok(())
    }

    async fn get(&self, id: &SessionId) -> Result<Option<Session>, Self::Error> {
        Ok(self.sessions.read().unwrap().get(id).cloned())
    }

    async fn touch(
        &self,
        _id: &SessionId,
        _expires_at: u64,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn delete(&self, id: &SessionId) -> Result<bool, Self::Error> {
        if self.fail_delete.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("revocation failed"));
        }
        Ok(self.sessions.write().unwrap().remove(id).is_some())
    }

    async fn delete_expired(&self, _now: u64) -> Result<usize, Self::Error> {
        Ok(0)
    }
}

#[tokio::test]
async fn logout_surfaces_revocation_failures() {
    let mut store = RevokeFailsStore::new();
    store.fail_delete.store(true, Ordering::Relaxed);
    let state = AppState {
        config: short_config(),
        sessions: Arc::new(SessionManager::new(store, Policy::new(2, 100).unwrap())),
    };
    let app = routes::router_with_state(state);

    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let cookie = cookie_pair(created.set_cookie.as_deref().unwrap()).to_owned();

    // Revocation fails server-side: logout must report an error and must not
    // clear the cookie, so the client keeps its session and can retry.
    let logged_out = call(app.clone(), "POST", "/logout", None, Some(&cookie)).await;
    assert_eq!(logged_out.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(logged_out.set_cookie.is_none());

    // The session is still valid server-side.
    let me = call(app, "GET", "/me", None, Some(&cookie)).await;
    assert_eq!(me.status, StatusCode::OK);
}

#[tokio::test]
async fn health_stays_public() {
    let reply = call(unsigned_app(), "GET", "/health", None, None).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains(r#""status":"ok""#));
}

#[tokio::test]
async fn me_reissues_cookie_when_expiry_slides() {
    let app = short_app();
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let create_expires = field_u64(&created.body, "expires_at").unwrap();
    let cookie = cookie_pair(created.set_cookie.as_deref().unwrap()).to_owned();

    // Let the idle deadline get close so a `/me` use slides the expiry.
    std::thread::sleep(std::time::Duration::from_secs(1));

    let me = call(app, "GET", "/me", None, Some(&cookie)).await;
    assert_eq!(me.status, StatusCode::OK);
    let me_expires = field_u64(&me.body, "expires_at").unwrap();
    assert!(
        me_expires > create_expires,
        "sliding expiry must move the stored deadline forward"
    );

    // The cookie must be re-issued so the browser's Max-Age tracks the slide.
    let set_cookie = me.set_cookie.as_deref().unwrap();
    assert!(set_cookie.starts_with("session="));
    assert!(
        set_cookie.contains("Max-Age=2"),
        "re-issued cookie must refresh Max-Age: {set_cookie}"
    );
}

#[tokio::test]
async fn me_keeps_reissuing_cookie_on_every_use() {
    let app = short_app();
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    let cookie = cookie_pair(created.set_cookie.as_deref().unwrap()).to_owned();

    let first = call(app.clone(), "GET", "/me", None, Some(&cookie)).await;
    assert_eq!(first.status, StatusCode::OK);
    assert!(first.set_cookie.is_some());

    let second = call(app, "GET", "/me", None, Some(&cookie)).await;
    assert_eq!(second.status, StatusCode::OK);
    assert!(second.set_cookie.is_some());
}

#[tokio::test]
async fn me_does_not_reissue_cookie_in_token_mode() {
    let app = short_app_with(SessionDelivery::Token);
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    let id = field(&created.body, "session_id").unwrap().to_owned();

    let me = call_bearer(app, "GET", "/me", &id).await;
    assert_eq!(me.status, StatusCode::OK);
    assert!(
        me.set_cookie.is_none(),
        "token mode must not set a cookie on /me"
    );
}

#[tokio::test]
async fn me_does_not_reissue_cookie_for_bearer_source() {
    let app = short_app_with(SessionDelivery::Both);
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-1"}"#),
        None,
    )
    .await;
    let id = field(&created.body, "session_id").unwrap().to_owned();

    let me = call_bearer(app, "GET", "/me", &id).await;
    assert_eq!(me.status, StatusCode::OK);
    assert!(
        me.set_cookie.is_none(),
        "a bearer-authenticated /me must not re-issue a cookie"
    );
}

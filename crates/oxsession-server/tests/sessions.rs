//! End-to-end tests for the session endpoints.
//!
//! These go through the real router, the real manager, and the real in-memory
//! store, so a request is the only thing that is simulated.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use oxsession_server::{config::Config, routes};
use oxsession_session::Policy;
use oxsession_sign::{CookieSigner, KeyId, SecretKey};
use tower::ServiceExt;

struct Reply {
    status: StatusCode,
    set_cookie: Option<String>,
    body: String,
}

fn config() -> Config {
    Config {
        bind_address: "127.0.0.1:0".parse().unwrap(),
        session_cookie: "session".to_owned(),
        policy: Policy::new(3_600, 86_400).unwrap(),
        session_cookie_secure: false,
        dev_login: true,
        signer: None,
    }
}

fn unsigned_app() -> Router {
    routes::router(config())
}

fn signed_app() -> Router {
    let mut config = config();
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
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let request = builder
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_owned())))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();

    Reply {
        status,
        set_cookie,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

fn cookie_pair(set_cookie: &str) -> &str {
    set_cookie.split(';').next().unwrap().trim()
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
    let app = unsigned_app();
    let created = call(
        app.clone(),
        "POST",
        "/sessions",
        Some(r#"{"subject":"user-2"}"#),
        None,
    )
    .await;
    let id = cookie_pair(created.set_cookie.as_deref().unwrap())
        .trim_start_matches("session=")
        .to_owned();

    let request = Request::builder()
        .uri("/me")
        .header(header::AUTHORIZATION, format!("Bearer {id}"))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(body.contains(r#""subject":"user-2""#));
    assert!(body.contains(r#""source":"bearer""#));
}

#[tokio::test]
async fn health_stays_public() {
    let reply = call(unsigned_app(), "GET", "/health", None, None).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains(r#""status":"ok""#));
}

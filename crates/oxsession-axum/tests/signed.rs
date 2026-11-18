//! End-to-end checks for signed cookies through a real router.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    routing::get,
};
use oxsession_axum::{AuthError, CookieHeader, signed_cookie};
use oxsession_sign::{CookieSigner, KeyId, SecretKey};
use tower::ServiceExt;

#[derive(Clone)]
struct AppState {
    signer: Arc<CookieSigner>,
}

fn state() -> AppState {
    AppState {
        signer: Arc::new(CookieSigner::new(
            KeyId::new("k1").unwrap(),
            SecretKey::from_slice(&[7; 32]).unwrap(),
        )),
    }
}

async fn whoami(
    State(state): State<AppState>,
    cookies: CookieHeader,
) -> Result<&'static str, AuthError> {
    signed_cookie(&cookies, &state.signer, "session")?.map_or(Ok("none"), |_| Ok("signed"))
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/whoami", get(whoami))
        .with_state(state)
}

async fn send(state: AppState, cookie: &str) -> StatusCode {
    let request = Request::builder()
        .uri("/whoami")
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    app(state).oneshot(request).await.unwrap().status()
}

fn sign(payload: &str) -> String {
    state()
        .signer
        .sign("session", payload)
        .unwrap_or_else(|_| panic!("payload {payload:?} should sign"))
}

#[tokio::test]
async fn accepts_a_signed_cookie() {
    let wire = sign("dXNlcj00Mg");
    assert_eq!(
        send(state(), &format!("theme=dark; session={wire}")).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn missing_cookie_is_not_a_failure_to_verify() {
    assert_eq!(send(state(), "theme=dark").await, StatusCode::OK);
}

#[tokio::test]
async fn rejects_an_unsigned_cookie() {
    assert_eq!(
        send(state(), "session=dXNlcj00Mg").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn rejects_a_tampered_signature() {
    let mut wire = sign("dXNlcj00Mg");
    let last = wire.pop().unwrap();
    wire.push(if last == 'A' { 'B' } else { 'A' });
    assert_eq!(
        send(state(), &format!("session={wire}")).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn rejects_a_signature_minted_for_another_cookie_name() {
    let wire = state().signer.sign("theme", "dark").unwrap();
    assert_eq!(
        send(state(), &format!("session={wire}")).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn duplicate_signed_cookies_are_rejected() {
    let wire = sign("dXNlcj00Mg");
    assert_eq!(
        send(state(), &format!("session={wire}; session={wire}")).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn header_map_helper_is_not_required_for_signed_cookies() {
    // Sanity: the helper works on a standalone header map too.
    use axum::http::HeaderValue;
    let mut headers = HeaderMap::new();
    headers.append(
        "cookie",
        HeaderValue::from_str(&format!("session={}", sign("x1"))).unwrap(),
    );
    let cookies = CookieHeader::from_headers(&headers);
    assert_eq!(
        signed_cookie(&cookies, &state().signer, "session").unwrap(),
        Some("x1")
    );
}

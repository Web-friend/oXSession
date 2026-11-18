//! End-to-end check of the Axum adapter: the request goes through a real
//! router, and the handler only uses the public adapter API.

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
    routing::get,
};
use oxsession_axum::{AuthError, CookieHeader};
use oxsession_core::Credentials;
use tower::ServiceExt;

async fn whoami(headers: HeaderMap, cookies: CookieHeader) -> Result<&'static str, AuthError> {
    let credentials = cookies
        .credentials(&headers, "session")
        .map_err(AuthError)?;
    Ok(match credentials {
        Credentials::Bearer(_) => "bearer",
        Credentials::Cookie(_) => "cookie",
    })
}

fn app() -> Router {
    Router::new().route("/whoami", get(whoami))
}

async fn send(request: Request<Body>) -> (StatusCode, String) {
    let response = app().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn request(headers: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder().uri("/whoami");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn missing_credentials_is_unauthorized() {
    let (status, _) = send(request(&[])).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cookie_credentials_are_accepted() {
    let (status, body) = send(request(&[("cookie", "theme=dark; session=abc")])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "cookie");
}

#[tokio::test]
async fn bearer_credentials_are_accepted() {
    let (status, body) = send(request(&[("authorization", "Bearer abc")])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "bearer");
}

#[tokio::test]
async fn bearer_wins_over_cookie() {
    let (status, body) = send(request(&[
        ("authorization", "Bearer abc"),
        ("cookie", "session=cookie-abc"),
    ]))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "bearer");
}

#[tokio::test]
async fn several_cookie_headers_are_joined() {
    let (status, body) = send(request(&[
        ("cookie", "theme=dark"),
        ("cookie", "session=abc"),
    ]))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "cookie");
}

#[tokio::test]
async fn duplicate_session_cookies_are_rejected() {
    let (status, _) = send(request(&[("cookie", "session=a; session=b")])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn other_authorization_schemes_are_rejected() {
    let (status, _) = send(request(&[
        ("authorization", "Basic dXNlcjpwYXNz"),
        ("cookie", "session=abc"),
    ]))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn set_cookie_helper_renders_a_session_cookie() {
    use oxsession_axum::{append_set_cookie, set_cookie};
    use oxsession_core::{SameSite, SetCookie};

    let cookie = SetCookie::builder("__Host-session", "abc")
        .unwrap()
        .path("/")
        .secure()
        .http_only()
        .same_site(SameSite::Lax)
        .max_age(3600)
        .build()
        .unwrap();

    let (name, value) = set_cookie(&cookie);
    assert_eq!(name, header::SET_COOKIE);
    assert_eq!(
        value.to_str().unwrap(),
        "__Host-session=abc; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"
    );

    let mut headers = HeaderMap::new();
    append_set_cookie(&mut headers, &cookie);
    assert_eq!(headers.get_all(header::SET_COOKIE).iter().count(), 1);
}

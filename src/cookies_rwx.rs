use axum::{http::StatusCode, Json, Router, routing::get};
use axum_extra::extract::cookie::CookieJar;

pub mod cookies_rwx {
pub const SESSION: &str = "session";

pub async fn getCookie(jar: CookieJar) -> Result<String, StatusCode> {
    jar.get(SESSION)
        .map(|cookie| cookie.value().to_string())
        .ok_or(StatusCode::NOT_FOUND)
}

pub fn router() -> Router {
    Router::new().route("/cookie", get(getCookie))
}

pub async fn listCookies(jar: CookieJar) -> String {
    jar.iter()
        .map(|cookie| format!("{}: {}", cookie.name(), cookie.value()))
        .collect::<Vec<String>>()
        .join("\n")
}
}


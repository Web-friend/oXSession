use axum::{Json, Router, extract::State, http::HeaderMap, routing::get};
use oxsession_axum::{AuthError, CookieHeader, signed_cookie};
use oxsession_core::Error;
use serde::Serialize;

use crate::config::Config;

pub fn router(config: Config) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/me", get(me))
        .with_state(config)
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

#[derive(Serialize)]
struct MeResponse {
    source: &'static str,
}

/// Reports which credential the client presented.
///
/// When signing is configured, the session cookie must verify: an unsigned or
/// tampered value is rejected instead of being trusted. Looking the payload up
/// in storage is the next slice, so nothing from it is returned here.
async fn me(
    State(config): State<Config>,
    headers: HeaderMap,
    cookies: CookieHeader,
) -> Result<Json<MeResponse>, AuthError> {
    let source = authenticate(&config, &headers, &cookies)
        .inspect_err(|error| eprintln!("credential rejected: {error}"))?;
    Ok(Json(MeResponse { source }))
}

fn authenticate(
    config: &Config,
    headers: &HeaderMap,
    cookies: &CookieHeader,
) -> Result<&'static str, AuthError> {
    // Bearer tokens bypass cookie handling entirely; the token itself is
    // resolved by the session layer once it exists.
    if oxsession_axum::bearer(headers).is_some() {
        cookies.credentials(headers, &config.session_cookie)?;
        return Ok("bearer");
    }

    match config.signer.as_deref() {
        Some(signer) => {
            signed_cookie(cookies, signer, &config.session_cookie)?
                .ok_or(AuthError::from(Error::Unauthenticated))?;
            Ok("cookie")
        }
        None => {
            cookies.credentials(headers, &config.session_cookie)?;
            Ok("cookie")
        }
    }
}

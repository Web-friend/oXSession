use axum::{Json, Router, extract::State, http::HeaderMap, routing::get};
use oxsession_axum::{AuthError, CookieHeader};
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

/// Resolves the credential the client presented.
///
/// Looking the token up in storage is the next slice; until then this only
/// proves the transport contract (bearer or cookie) is wired correctly. The
/// token itself is never echoed back.
async fn me(
    State(config): State<Config>,
    headers: HeaderMap,
    cookies: CookieHeader,
) -> Result<Json<MeResponse>, AuthError> {
    let credentials = cookies
        .credentials(&headers, &config.session_cookie)
        .map_err(AuthError)?;

    Ok(Json(MeResponse {
        source: if credentials.is_bearer() {
            "bearer"
        } else {
            "cookie"
        },
    }))
}

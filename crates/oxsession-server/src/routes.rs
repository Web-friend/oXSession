use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use oxsession_axum::{
    AuthError, CookieHeader, append_set_cookie, bearer, set_cookie, signed_cookie,
};
use oxsession_core::{Error, SameSite, SessionId, SetCookie};
use oxsession_session::{Error as SessionError, now};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::state::AppState;

pub fn router(config: Config) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/me", get(me))
        .route("/sessions", post(create_session))
        .route("/logout", post(logout))
        .with_state(AppState::new(config))
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
    subject: String,
    expires_at: u64,
    source: &'static str,
}

/// Resolve the caller's session and report its subject.
async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
    cookies: CookieHeader,
) -> Result<Json<MeResponse>, ApiError> {
    let (id, source) = session_id(&state.config, &headers, &cookies)?;
    let session = state.sessions.validate(&id, now()).await?;

    Ok(Json(MeResponse {
        subject: session.subject().to_owned(),
        expires_at: session.expires_at(),
        source,
    }))
}

#[derive(Deserialize)]
struct CreateSessionRequest {
    subject: String,
}

#[derive(Serialize)]
struct SessionCreated {
    subject: String,
    expires_at: u64,
}

/// Mint a session for `subject`.
///
/// There is no provider yet, so this endpoint is gated behind `AUTH_DEV_LOGIN`
/// and is absent (404) otherwise.
async fn create_session(
    State(state): State<AppState>,
    Json(body): Json<CreateSessionRequest>,
) -> Result<Response, ApiError> {
    if !state.config.dev_login {
        return Err(ApiError::NotFound);
    }

    let session = state.sessions.create(&body.subject, now()).await?;
    let wire = signed_or_raw(&state.config, session.id().as_str())?;
    let cookie = session_cookie(&state.config, &wire)?;

    let mut response = (
        StatusCode::CREATED,
        Json(SessionCreated {
            subject: session.subject().to_owned(),
            expires_at: session.expires_at(),
        }),
    )
        .into_response();

    let (name, value) = set_cookie(&cookie);
    response.headers_mut().append(name, value);
    Ok(response)
}

/// Revoke the caller's session and clear the cookie.
///
/// Best effort: an unreadable cookie still gets cleared, because a client that
/// cannot be identified should not keep presenting one.
async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    cookies: CookieHeader,
) -> Response {
    if let Ok((id, _)) = session_id(&state.config, &headers, &cookies) {
        if let Err(error) = state.sessions.revoke(&id).await {
            eprintln!("failed to revoke session: {error}");
        }
    }

    let mut response = StatusCode::NO_CONTENT.into_response();
    match clear_cookie(&state.config) {
        Ok(cookie) => {
            let (name, value) = set_cookie(&cookie);
            response.headers_mut().append(name, value);
        }
        Err(error) => eprintln!("failed to build cookie deletion: {error}"),
    }
    response
}

/// Extract and shape-check the session id.
fn session_id(
    config: &Config,
    headers: &HeaderMap,
    cookies: &CookieHeader,
) -> Result<(SessionId, &'static str), ApiError> {
    let name = config.session_cookie.as_str();

    let (token, source) = if oxsession_axum::bearer(headers).is_some() {
        let credentials = cookies.credentials(headers, name)?;
        (credentials.token(), "bearer")
    } else if let Some(signer) = config.signer.as_deref() {
        let payload = signed_cookie(cookies, signer, name)?
            .ok_or_else(|| ApiError::Auth(AuthError::from(Error::Unauthenticated)))?;
        (payload, "cookie")
    } else {
        let credentials = cookies.credentials(headers, name)?;
        (credentials.token(), "cookie")
    };

    let id = SessionId::new(token).map_err(|_| {
        // A malformed id is a bad credential, not a server fault.
        ApiError::Auth(AuthError::from(Error::Unauthenticated))
    })?;
    Ok((id, source))
}

fn signed_or_raw(config: &Config, id: &str) -> Result<String, ApiError> {
    match config.signer.as_deref() {
        Some(signer) => signer
            .sign(&config.session_cookie, id)
            .map_err(|error| ApiError::Internal(format!("could not sign session cookie: {error}"))),
        None => Ok(id.to_owned()),
    }
}

fn session_cookie<'a>(config: &'a Config, value: &'a str) -> Result<SetCookie<'a>, ApiError> {
    let mut builder = SetCookie::builder(&config.session_cookie, value)
        .map_err(|error| ApiError::Internal(format!("invalid session cookie: {error}")))?
        .path("/")
        .http_only()
        .same_site(SameSite::Lax)
        .max_age(config.policy.ttl());

    if config.session_cookie_secure {
        builder = builder.secure();
    }

    builder
        .build()
        .map_err(|error| ApiError::Internal(format!("invalid session cookie: {error}")))
}

fn clear_cookie(config: &Config) -> Result<SetCookie<'_>, ApiError> {
    let mut builder = SetCookie::builder(&config.session_cookie, "")
        .map_err(|error| ApiError::Internal(format!("invalid session cookie: {error}")))?
        .path("/")
        .http_only()
        .same_site(SameSite::Lax)
        .max_age(0);

    if config.session_cookie_secure {
        builder = builder.secure();
    }

    builder
        .build()
        .map_err(|error| ApiError::Internal(format!("invalid session cookie: {error}")))
}

/// Everything a handler can fail with, rendered as an HTTP response.
#[derive(Debug)]
pub enum ApiError {
    /// The credential was missing, ambiguous, or failed verification.
    Auth(AuthError),
    /// The session layer failed.
    Session(SessionError),
    /// The request was well-formed but unusable.
    Invalid(&'static str),
    /// The endpoint is not available in this configuration.
    NotFound,
    /// A server-side invariant failed. Logged, never detailed to the client.
    Internal(String),
}

impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        Self::Auth(AuthError::from(error))
    }
}

impl From<SessionError> for ApiError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth(error) => write!(formatter, "{error}"),
            Self::Session(error) => write!(formatter, "{error}"),
            Self::Invalid(message) => formatter.write_str(message),
            Self::NotFound => formatter.write_str("not found"),
            Self::Internal(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Auth(error) => error.into_response(),
            Self::Session(SessionError::NotFound | SessionError::Expired) => {
                (StatusCode::UNAUTHORIZED, "authentication required").into_response()
            }
            Self::Session(SessionError::InvalidSubject) => {
                (StatusCode::BAD_REQUEST, "subject must not be empty").into_response()
            }
            Self::Session(error @ (SessionError::Store(_) | SessionError::Entropy)) => {
                eprintln!("session failure: {error}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
            Self::Session(error) => {
                // `SessionError` is non-exhaustive: new variants are server-side
                // faults until proven otherwise.
                eprintln!("unhandled session failure: {error}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
            Self::Invalid(message) => (StatusCode::BAD_REQUEST, message).into_response(),
            Self::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
            Self::Internal(message) => {
                eprintln!("internal failure: {message}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use oxsession_session::Policy;
    use oxsession_sign::{CookieSigner, KeyId, SecretKey};

    fn config() -> Config {
        Config {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            session_cookie: "session".to_owned(),
            policy: Policy::default(),
            session_cookie_secure: false,
            dev_login: true,
            signer: None,
        }
    }

    #[test]
    fn clears_the_cookie_with_max_age_zero() {
        let config = config();
        let cookie = clear_cookie(&config).unwrap();
        assert_eq!(
            cookie.encode(),
            "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn session_cookies_are_http_only_and_scoped_to_root() {
        let config = config();
        let cookie = session_cookie(&config, "abc").unwrap();
        assert_eq!(
            cookie.encode(),
            "session=abc; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn secure_cookies_require_the_flag() {
        let mut config = config();
        config.session_cookie_secure = true;
        let cookie = session_cookie(&config, "abc").unwrap();
        assert!(cookie.encode().contains("; Secure"));
    }

    #[test]
    fn signed_mode_wraps_the_session_id() {
        let mut config = config();
        config.signer = Some(Arc::new(CookieSigner::new(
            KeyId::new("k1").unwrap(),
            SecretKey::from_slice(&[7; 32]).unwrap(),
        )));

        let wire = signed_or_raw(&config, "abcdefghijklmnop").unwrap();
        assert!(wire.starts_with("os1.k1."));

        let signer = config.signer.as_deref().unwrap();
        assert_eq!(signer.verify("session", &wire).unwrap(), "abcdefghijklmnop");
    }

    #[test]
    fn errors_map_to_status_codes() {
        assert_eq!(
            ApiError::Session(SessionError::Expired)
                .into_response()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiError::Invalid("bad").into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::NotFound.into_response().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ApiError::Internal("boom".to_owned())
                .into_response()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}

use axum::{
    Json, Router,
    extract::State,
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, PRAGMA},
    },
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
///
/// The response is per-user and authenticated by an ambient cookie, so it must
/// never be stored by a shared cache.
async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
    cookies: CookieHeader,
) -> Result<Response, ApiError> {
    let (id, source) = session_id(&state.config, &headers, &cookies)?;
    let session = state.sessions.validate(&id, now()).await?;

    let mut response = Json(MeResponse {
        subject: session.subject().to_owned(),
        expires_at: session.expires_at(),
        source: source.as_str(),
    })
    .into_response();
    no_store(&mut response);
    Ok(response)
}

#[derive(Deserialize)]
struct CreateSessionRequest {
    subject: String,
}

#[derive(Serialize)]
struct SessionCreated {
    subject: String,
    expires_at: u64,
    /// Present only when `AUTH_SESSION_DELIVERY` includes `token`.
    ///
    /// This is the raw session id, not the signed cookie value: a client keeps
    /// it and presents it as `Authorization: Bearer`.
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
}

/// Mint a session for `subject`.
///
/// There is no provider yet, so this endpoint is gated behind `AUTH_DEV_LOGIN`
/// and is absent (404) otherwise.
///
/// The credential is delivered according to
/// [`SessionDelivery`](crate::config::SessionDelivery): as a cookie, in the
/// response body for clients that store it themselves, or both.
async fn create_session(
    State(state): State<AppState>,
    Json(body): Json<CreateSessionRequest>,
) -> Result<Response, ApiError> {
    if !state.config.dev_login {
        return Err(ApiError::NotFound);
    }

    let session = state.sessions.create(&body.subject, now()).await?;
    let delivery = state.config.session_delivery;

    let payload = SessionCreated {
        subject: session.subject().to_owned(),
        expires_at: session.expires_at(),
        session_id: delivery
            .sends_token()
            .then(|| session.id().as_str().to_owned()),
    };

    let mut response = (StatusCode::CREATED, Json(payload)).into_response();
    // A body that may carry a credential must not be stored by any cache.
    no_store(&mut response);

    if delivery.sends_cookie() {
        let wire = signed_or_raw(&state.config, session.id().as_str())?;
        let cookie = session_cookie(&state.config, &wire)?;
        append_set_cookie(response.headers_mut(), &cookie);
    }

    Ok(response)
}

/// Revoke the caller's session and clear the cookie.
///
/// Revocation uses whatever credential is presented, even one this deployment
/// does not accept for authentication: logging out must work for any client that
/// still holds a session, or the id would stay valid until it expires.
///
/// Best effort: an unreadable cookie still gets cleared, because a client that
/// cannot be identified should not keep presenting one.
async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    cookies: CookieHeader,
) -> Response {
    if let Ok((id, _)) = credential(&state.config, &headers, &cookies) {
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
    no_store(&mut response);
    response
}

/// Which carrier authenticated the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    Bearer,
    Cookie,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::Cookie => "cookie",
        }
    }
}

/// Extract and shape-check the session id, enforcing the delivery policy.
fn session_id(
    config: &Config,
    headers: &HeaderMap,
    cookies: &CookieHeader,
) -> Result<(SessionId, Source), ApiError> {
    let name = config.session_cookie.as_str();

    if bearer(headers).is_some() {
        let credentials = cookies.credentials(headers, name)?;
        return parse_id(credentials.token(), Source::Bearer);
    }

    // Checked before the cookie is parsed. In a token-only deployment the
    // cookie carrier is not a credential, so its contents must not decide the
    // status code — a duplicate cookie would otherwise answer `400 ambiguous`
    // instead of `401` — and it must not cost a signature check.
    if !config.session_delivery.accepts_cookie() {
        return Err(unauthenticated());
    }

    parse_id(cookie_token(config, headers, cookies)?, Source::Cookie)
}

/// The credential a request presents, before the delivery policy is applied.
///
/// Used by logout, which must be able to identify a session through a carrier
/// this deployment does not accept for authentication.
fn credential(
    config: &Config,
    headers: &HeaderMap,
    cookies: &CookieHeader,
) -> Result<(SessionId, Source), ApiError> {
    let name = config.session_cookie.as_str();

    if bearer(headers).is_some() {
        let credentials = cookies.credentials(headers, name)?;
        return parse_id(credentials.token(), Source::Bearer);
    }

    parse_id(cookie_token(config, headers, cookies)?, Source::Cookie)
}

/// Read the cookie carrier, verifying the signature when signing is enabled.
fn cookie_token<'a>(
    config: &Config,
    headers: &'a HeaderMap,
    cookies: &'a CookieHeader,
) -> Result<&'a str, ApiError> {
    let name = config.session_cookie.as_str();

    match config.signer.as_deref() {
        Some(signer) => signed_cookie(cookies, signer, name)?.ok_or_else(unauthenticated),
        None => Ok(cookies.credentials(headers, name)?.token()),
    }
}

fn parse_id(token: &str, source: Source) -> Result<(SessionId, Source), ApiError> {
    // A malformed id is a bad credential, not a server fault.
    let id = SessionId::new(token).map_err(|_| unauthenticated())?;
    Ok((id, source))
}

fn unauthenticated() -> ApiError {
    ApiError::Auth(AuthError::from(Error::Unauthenticated))
}

/// Mark a response as uncacheable.
///
/// `no-store` rather than `private`: a shared cache that ignores `Vary: Cookie`
/// must not be able to hand one user's subject to another. `Pragma` is repeated
/// for HTTP/1.0 intermediaries that never learned `Cache-Control`.
fn no_store(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
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

/// A credential failure, rendered as an HTTP response.
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
        let mut response = match self {
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
        };

        // An error page for an authenticated endpoint is still per-request.
        no_store(&mut response);
        response
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
            session_delivery: crate::config::SessionDelivery::Cookie,
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

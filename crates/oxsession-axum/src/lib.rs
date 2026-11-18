//! Axum adapter for oXSession.
//!
//! The adapter is intentionally thin: it turns request parts into the neutral
//! types from [`oxsession_core`] and maps errors back into an HTTP response.
//! Parsing and signing rules live in the core and signing crates, so an Actix
//! or Hyper adapter cannot drift from this one.

#![warn(missing_docs)]

use std::convert::Infallible;

use axum::{
    extract::FromRequestParts,
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{AUTHORIZATION, COOKIE, SET_COOKIE},
        request::Parts,
    },
    response::{IntoResponse, Response},
};
use oxsession_core::{Credentials, Error, Pairs, SetCookie};
use oxsession_sign::{CookieSigner, Error as SignError};

/// Every `Cookie` header of a request, joined as RFC 6265 section 5.4 requires.
///
/// Extracting this type never fails: a missing header yields an empty value,
/// and the credential resolution decides what that means.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CookieHeader {
    bytes: Vec<u8>,
}

impl CookieHeader {
    /// Join the `Cookie` headers of `headers` with `"; "`.
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let mut bytes = Vec::new();
        for value in headers.get_all(COOKIE) {
            if !bytes.is_empty() {
                bytes.extend_from_slice(b"; ");
            }
            bytes.extend_from_slice(value.as_bytes());
        }
        Self { bytes }
    }

    /// The joined header bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parse the joined header.
    #[must_use]
    pub fn pairs(&self) -> Pairs<'_> {
        Pairs::parse(&self.bytes)
    }

    /// Resolve one credential from this request.
    ///
    /// `Authorization: Bearer` wins over the cookie; see
    /// [`oxsession_core::resolve`] for the precedence rules.
    ///
    /// # Errors
    ///
    /// See [`oxsession_core::resolve`].
    pub fn credentials<'a>(
        &'a self,
        headers: &'a HeaderMap,
        cookie_name: &str,
    ) -> Result<Credentials<'a>, Error> {
        let pairs = self.pairs();
        oxsession_core::resolve(bearer(headers), &pairs, cookie_name)
    }
}

impl<S> FromRequestParts<S> for CookieHeader
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_headers(&parts.headers))
    }
}

/// The raw `Authorization` header value, if it is valid visible ASCII.
///
/// The header is returned unparsed so [`oxsession_core::resolve`] stays the one
/// place that interprets it.
#[must_use]
pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(AUTHORIZATION)?.to_str().ok()
}

/// Verify a signed cookie and return its payload.
///
/// `Ok(None)` means the cookie is absent. A present but unsigned, tampered, or
/// foreign-key cookie is an error: verification never falls back to the raw
/// value.
///
/// # Errors
///
/// [`AuthError::Credentials`] when the cookie name appears more than once,
/// [`AuthError::Signature`] when verification fails.
pub fn signed_cookie<'a>(
    cookies: &'a CookieHeader,
    signer: &CookieSigner,
    name: &str,
) -> Result<Option<&'a str>, AuthError> {
    match cookies.pairs().get_unique(name) {
        Ok(Some(wire)) => signer
            .verify(name, wire)
            .map(Some)
            .map_err(AuthError::Signature),
        Ok(None) => Ok(None),
        Err(ambiguous) => Err(AuthError::Credentials(Error::Ambiguous(ambiguous))),
    }
}

/// A credential failure, rendered as an HTTP response.
///
/// Mapping:
///
/// | Failure | Status |
/// | --- | --- |
/// | [`Error::Unauthenticated`], any signature failure | `401 Unauthorized` |
/// | [`Error::Ambiguous`] (duplicate cookie name) | `400 Bad Request` |
/// | any other malformed credential | `400 Bad Request` |
///
/// Signature failures deliberately share one response: telling a client whether
/// the key was unknown or the MAC was wrong turns the endpoint into a
/// verification oracle.
#[derive(Debug)]
pub enum AuthError {
    /// The credential was missing, ambiguous, or malformed.
    Credentials(Error),
    /// A signed cookie failed verification.
    Signature(SignError),
}

impl AuthError {
    /// The underlying failure, for logging.
    ///
    /// Never expose this text to clients; the HTTP mapping is deliberately
    /// coarse.
    #[must_use]
    pub fn reason(&self) -> &dyn std::fmt::Display {
        match self {
            Self::Credentials(error) => error,
            Self::Signature(error) => error,
        }
    }
}

impl From<Error> for AuthError {
    fn from(error: Error) -> Self {
        Self::Credentials(error)
    }
}

impl From<SignError> for AuthError {
    fn from(error: SignError) -> Self {
        Self::Signature(error)
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Credentials(error) => write!(formatter, "{error}"),
            Self::Signature(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Credentials(Error::Unauthenticated) | Self::Signature(_) => {
                (StatusCode::UNAUTHORIZED, "authentication required")
            }
            Self::Credentials(Error::Ambiguous(_)) => {
                (StatusCode::BAD_REQUEST, "ambiguous credential cookie")
            }
            Self::Credentials(_) => (StatusCode::BAD_REQUEST, "malformed credentials"),
        };
        (status, message).into_response()
    }
}

/// The `Set-Cookie` header for `cookie`.
///
/// # Panics
///
/// Never in practice: [`SetCookie`] validates that name and value are visible
/// ASCII, which is exactly what a header value accepts.
#[must_use]
pub fn set_cookie(cookie: &SetCookie<'_>) -> (HeaderName, HeaderValue) {
    let value = HeaderValue::from_str(&cookie.encode())
        .expect("a validated SetCookie always serializes to visible ASCII");
    (SET_COOKIE, value)
}

/// Append `cookie` to `headers` as a `Set-Cookie` header.
///
/// # Panics
///
/// See [`set_cookie`].
pub fn append_set_cookie(headers: &mut HeaderMap, cookie: &SetCookie<'_>) {
    let (name, value) = set_cookie(cookie);
    headers.append(name, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_every_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.append(COOKIE, HeaderValue::from_static("a=1"));
        headers.append(COOKIE, HeaderValue::from_static("b=2"));

        let cookies = CookieHeader::from_headers(&headers);
        assert_eq!(cookies.as_bytes(), b"a=1; b=2");
        assert_eq!(cookies.pairs().get("b"), Some("2"));
    }

    #[test]
    fn empty_header_is_empty() {
        let cookies = CookieHeader::from_headers(&HeaderMap::new());
        assert_eq!(cookies.as_bytes(), b"");
        assert_eq!(cookies.pairs().iter().count(), 0);
    }

    #[test]
    fn renders_core_errors() {
        assert_eq!(
            AuthError::from(Error::Unauthenticated)
                .into_response()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AuthError::from(Error::InvalidCookieName)
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AuthError::from(SignError::BadMac).into_response().status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

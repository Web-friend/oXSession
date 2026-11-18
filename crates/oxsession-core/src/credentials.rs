//! Resolving the session credential from a request.
//!
//! Cookies are a browser transport, not the platform contract. Mobile apps,
//! CLIs, and cross-site frontends send `Authorization: Bearer`, so credential
//! resolution happens in one place here and every adapter just feeds it the
//! two inputs it has.

use crate::cookies::Pairs;
use crate::error::Error;

/// A credential extracted from a request, borrowed from the request bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credentials<'a> {
    /// From the `Authorization: Bearer <token>` header.
    Bearer(&'a str),
    /// From a session cookie value.
    Cookie(&'a str),
}

impl<'a> Credentials<'a> {
    /// The opaque token to look up.
    #[must_use]
    pub const fn token(&self) -> &'a str {
        match self {
            Self::Bearer(token) | Self::Cookie(token) => token,
        }
    }

    /// Whether the credential arrived as a bearer token.
    #[must_use]
    pub const fn is_bearer(&self) -> bool {
        matches!(self, Self::Bearer(_))
    }
}

/// Resolve one credential from an `Authorization` header and a parsed cookie
/// header.
///
/// An `Authorization` header always wins when present: a client that sent one
/// means it, and silently falling back to a cookie would make it impossible to
/// tell which credential was used. Any non-`Bearer` scheme is rejected rather
/// than ignored.
///
/// # Errors
///
/// - [`Error::Unauthenticated`] when no usable credential is present.
/// - [`Error::Ambiguous`] when the cookie name appears more than once or the
///   header could not be scanned.
pub fn resolve<'a>(
    authorization: Option<&'a str>,
    cookies: &Pairs<'a>,
    cookie_name: &str,
) -> Result<Credentials<'a>, Error> {
    if let Some(header) = authorization {
        let (scheme, token) = header
            .trim()
            .split_once(char::is_whitespace)
            .ok_or(Error::Unauthenticated)?;

        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(Error::Unauthenticated);
        }

        let token = token.trim();
        if token.is_empty() {
            return Err(Error::Unauthenticated);
        }
        return Ok(Credentials::Bearer(token));
    }

    match cookies.get_unique(cookie_name).map_err(Error::Ambiguous)? {
        Some(value) => Ok(Credentials::Cookie(value)),
        None => Err(Error::Unauthenticated),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(header: &str) -> Pairs<'_> {
        Pairs::parse(header.as_bytes())
    }

    #[test]
    fn prefers_bearer_over_cookie() {
        let cookies = pairs("session=cookie-value");
        let credentials = resolve(Some("Bearer token-value"), &cookies, "session").unwrap();
        assert_eq!(credentials, Credentials::Bearer("token-value"));
        assert!(credentials.is_bearer());
    }

    #[test]
    fn bearer_scheme_is_case_insensitive_and_trimmed() {
        let cookies = pairs("");
        assert_eq!(
            resolve(Some("  bEaReR    token  "), &cookies, "session").unwrap(),
            Credentials::Bearer("token")
        );
    }

    #[test]
    fn reads_the_cookie_when_no_authorization_header_exists() {
        let cookies = pairs("theme=dark; session=cookie-value");
        assert_eq!(
            resolve(None, &cookies, "session").unwrap(),
            Credentials::Cookie("cookie-value")
        );
    }

    #[test]
    fn rejects_other_schemes_instead_of_falling_back() {
        let cookies = pairs("session=cookie-value");
        assert_eq!(
            resolve(Some("Basic dXNlcjpwYXNz"), &cookies, "session"),
            Err(Error::Unauthenticated)
        );
    }

    #[test]
    fn duplicate_cookies_are_an_error() {
        let cookies = pairs("session=a; session=b");
        assert_eq!(
            resolve(None, &cookies, "session"),
            Err(Error::Ambiguous(crate::cookies::Ambiguous::Duplicate {
                count: 2
            }))
        );
    }

    #[test]
    fn missing_credentials_are_unauthenticated() {
        let cookies = pairs("theme=dark");
        assert_eq!(
            resolve(None, &cookies, "session"),
            Err(Error::Unauthenticated)
        );
        assert_eq!(
            resolve(Some(""), &cookies, "session"),
            Err(Error::Unauthenticated)
        );
    }
}

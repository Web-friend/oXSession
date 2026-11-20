//! The error type shared by every adapter.

use core::fmt;

use crate::cookies::Ambiguous;

/// Errors produced by the core crate.
///
/// Adapters translate these into their own response types; the mapping is part
/// of the platform contract, so it is documented on each adapter.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// No usable credential was presented.
    Unauthenticated,
    /// A credential cookie could not be resolved to a single value.
    Ambiguous(Ambiguous),
    /// A cookie name is not a valid RFC 7230 token.
    InvalidCookieName,
    /// A cookie value contains bytes that are not cookie-octets.
    InvalidCookieValue,
    /// A cookie attribute was rejected; the message says which rule failed.
    InvalidAttribute(&'static str),
    /// A `__Host-` cookie is missing `Secure` or `Path=/`, or has a `Domain`.
    HostPrefix,
    /// A `__Secure-` cookie is missing `Secure`.
    SecurePrefix,
    /// `SameSite=None` requires `Secure`.
    SameSiteNoneRequiresSecure,
}

/// Stable, sanitized error class for language bindings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Malformed or otherwise invalid input.
    InvalidInput,
    /// No usable credential was supplied.
    MissingCredential,
    /// More than one matching credential was supplied.
    AmbiguousCredential,
}

impl Error {
    /// Return a stable category without exposing header contents.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::Unauthenticated => ErrorCategory::MissingCredential,
            Self::Ambiguous(_) => ErrorCategory::AmbiguousCredential,
            _ => ErrorCategory::InvalidInput,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated => formatter.write_str("no credential presented"),
            Self::Ambiguous(ambiguous) => {
                write!(formatter, "ambiguous credential cookie: {ambiguous}")
            }
            Self::InvalidCookieName => formatter.write_str("invalid cookie name"),
            Self::InvalidCookieValue => formatter.write_str("invalid cookie value"),
            Self::InvalidAttribute(rule) => write!(formatter, "invalid cookie attribute: {rule}"),
            Self::HostPrefix => {
                formatter.write_str("__Host- cookies require Secure, Path=/ and no Domain")
            }
            Self::SecurePrefix => formatter.write_str("__Secure- cookies require Secure"),
            Self::SameSiteNoneRequiresSecure => {
                formatter.write_str("SameSite=None requires Secure")
            }
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_categories_separate_missing_and_ambiguous_credentials() {
        assert_eq!(
            Error::Unauthenticated.category(),
            ErrorCategory::MissingCredential
        );
        assert_eq!(
            Error::Ambiguous(Ambiguous::Duplicate { count: 2 }).category(),
            ErrorCategory::AmbiguousCredential
        );
    }
}

impl fmt::Display for Ambiguous {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate { count } => write!(formatter, "name appears {count} times"),
            Self::Truncated => formatter.write_str("header was truncated before the scan ended"),
            Self::HeaderTooLong => formatter.write_str("header exceeds the size limit"),
        }
    }
}

impl std::error::Error for Ambiguous {}

/// Convenience alias for results produced by the core crate.
pub type Result<T> = core::result::Result<T, Error>;

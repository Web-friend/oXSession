//! Errors produced while signing or verifying a cookie.

use core::fmt;

/// Why signing or verification failed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A key was not exactly 32 bytes.
    KeySize,
    /// A key id was empty, longer than 16 bytes, or used other characters.
    InvalidKeyId,
    /// A configured key was not valid unpadded base64url.
    InvalidKeyEncoding,
    /// More than [`MAX_PREVIOUS_KEYS`](crate::MAX_PREVIOUS_KEYS) retired keys.
    TooManyKeys,
    /// A key id is already used by the current or a retired key.
    DuplicateKeyId,
    /// The cookie name is not an RFC 7230 token.
    InvalidCookieName,
    /// The payload is empty, contains `.`, or is not cookie-octets.
    PayloadNotEncodable,
    /// The signed value exceeds the size limit.
    TooLong,
    /// The value does not have the `os1.<keyid>.<payload>.<mac>` shape.
    Malformed,
    /// The value uses a format version this build does not understand.
    UnsupportedVersion,
    /// The key id is not in the signer's key ring.
    UnknownKey,
    /// The signature does not match.
    BadMac,
}

/// Stable, sanitized error class for language bindings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Invalid cookie, payload, or signed value.
    InvalidInput,
    /// Invalid signing configuration.
    Configuration,
    /// The signed value could not be authenticated.
    SignatureFailure,
}

impl Error {
    /// Return a stable category without exposing key material or wire values.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::InvalidCookieName
            | Self::PayloadNotEncodable
            | Self::TooLong
            | Self::Malformed
            | Self::UnsupportedVersion => ErrorCategory::InvalidInput,
            Self::KeySize
            | Self::InvalidKeyId
            | Self::InvalidKeyEncoding
            | Self::TooManyKeys
            | Self::DuplicateKeyId => ErrorCategory::Configuration,
            Self::UnknownKey | Self::BadMac => ErrorCategory::SignatureFailure,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeySize => formatter.write_str("signing keys must be 32 bytes"),
            Self::InvalidKeyId => {
                formatter.write_str("key ids must be 1-16 bytes of [A-Za-z0-9_-]")
            }
            Self::InvalidKeyEncoding => formatter.write_str("key is not unpadded base64url"),
            Self::TooManyKeys => formatter.write_str("too many retired keys"),
            Self::DuplicateKeyId => formatter.write_str("duplicate signing key id"),
            Self::InvalidCookieName => formatter.write_str("invalid cookie name"),
            Self::PayloadNotEncodable => {
                formatter.write_str("payload must be non-empty cookie-octets without '.'")
            }
            Self::TooLong => formatter.write_str("signed cookie is too long"),
            Self::Malformed => formatter.write_str("malformed signed cookie"),
            Self::UnsupportedVersion => formatter.write_str("unsupported signed cookie version"),
            Self::UnknownKey => formatter.write_str("unknown signing key"),
            Self::BadMac => formatter.write_str("signature mismatch"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_categories_hide_signature_details() {
        assert_eq!(Error::BadMac.category(), ErrorCategory::SignatureFailure);
        assert_eq!(
            Error::UnknownKey.category(),
            ErrorCategory::SignatureFailure
        );
        assert_eq!(
            Error::DuplicateKeyId.category(),
            ErrorCategory::Configuration
        );
        assert!(!Error::BadMac.to_string().contains("key"));
    }
}

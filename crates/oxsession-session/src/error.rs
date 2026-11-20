//! Errors from the session layer.

use core::fmt;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Why a session operation failed.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// No session exists for that id.
    NotFound,
    /// The session existed but is past its expiry.
    Expired,
    /// The subject was empty, so the session would belong to nobody.
    InvalidSubject,
    /// The subject exceeds the supported UTF-8 byte limit.
    SubjectTooLong,
    /// The operating system refused to provide randomness for a session id.
    Entropy,
    /// The storage adapter failed.
    Store(BoxError),
}

/// Stable, sanitized error class for language bindings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCategory {
    /// The subject is empty or whitespace-only.
    InvalidSubject,
    /// The subject exceeds the UTF-8 byte limit.
    SubjectTooLong,
    /// No session exists for the supplied id.
    MissingSession,
    /// The session exceeded its expiry deadline.
    ExpiredSession,
    /// Randomness could not be obtained.
    EntropyFailure,
    /// The backing store failed.
    StorageFailure,
}

impl Error {
    /// Return a stable category without exposing session ids or store details.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::InvalidSubject => ErrorCategory::InvalidSubject,
            Self::SubjectTooLong => ErrorCategory::SubjectTooLong,
            Self::NotFound => ErrorCategory::MissingSession,
            Self::Expired => ErrorCategory::ExpiredSession,
            Self::Entropy => ErrorCategory::EntropyFailure,
            Self::Store(_) => ErrorCategory::StorageFailure,
        }
    }
}

impl Error {
    pub(crate) fn store(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Store(Box::new(error))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("session not found"),
            Self::Expired => formatter.write_str("session expired"),
            Self::InvalidSubject => formatter.write_str("session subject must not be empty"),
            Self::SubjectTooLong => formatter.write_str("session subject exceeds the byte limit"),
            Self::Entropy => formatter.write_str("could not obtain randomness for a session id"),
            Self::Store(_) => formatter.write_str("session store failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_category_and_display_hide_adapter_details() {
        let error = Error::store(std::io::Error::other("private backend detail"));
        assert_eq!(error.category(), ErrorCategory::StorageFailure);
        assert_eq!(error.to_string(), "session store failed");
        assert!(!error.to_string().contains("private backend detail"));
    }

    #[test]
    fn wrapper_categories_keep_expected_failures_distinct() {
        assert_eq!(
            Error::InvalidSubject.category(),
            ErrorCategory::InvalidSubject
        );
        assert_eq!(
            Error::SubjectTooLong.category(),
            ErrorCategory::SubjectTooLong
        );
        assert_eq!(Error::NotFound.category(), ErrorCategory::MissingSession);
        assert_eq!(Error::Expired.category(), ErrorCategory::ExpiredSession);
        assert_eq!(Error::Entropy.category(), ErrorCategory::EntropyFailure);
    }
}

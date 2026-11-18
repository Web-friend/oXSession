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
    /// The operating system refused to provide randomness for a session id.
    Entropy,
    /// The storage adapter failed.
    Store(BoxError),
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
            Self::Entropy => formatter.write_str("could not obtain randomness for a session id"),
            Self::Store(error) => write!(formatter, "session store failed: {error}"),
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

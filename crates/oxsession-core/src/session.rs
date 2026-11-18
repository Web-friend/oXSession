//! Session model and the storage contract.
//!
//! The model and the [`SessionStore`] trait live here so that every storage
//! adapter — memory today, SQL later — implements the same interface. No
//! adapter-specific type leaks into this module.

use core::fmt;
use core::future::Future;
use core::str::FromStr;

/// Largest accepted session id, in bytes.
pub const MAX_SESSION_ID_BYTES: usize = 128;

/// Smallest accepted session id, in bytes.
///
/// Shorter ids are rejected rather than padded: a 10-byte id is a mistake, not
/// a preference.
pub const MIN_SESSION_ID_BYTES: usize = 16;

/// An opaque session identifier.
///
/// Ids are bearer credentials. [`Debug`] output is redacted so they cannot leak
/// into logs by accident; use [`SessionId::as_str`] when you mean to use one.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(Box<str>);

impl SessionId {
    /// Validate an id produced elsewhere.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSessionId`] unless `value` is 16–128 bytes of
    /// `[A-Za-z0-9_-]`, which is what an unpadded base64url token looks like.
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, InvalidSessionId> {
        let value = value.into();
        if !is_valid_session_id(&value) {
            return Err(InvalidSessionId);
        }
        Ok(Self(value))
    }

    /// The id as a string.
    ///
    /// Treat the result as a credential: it is what a client presents.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionId(<redacted>)")
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for SessionId {
    type Err = InvalidSessionId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Whether `value` is shaped like a session id.
#[must_use]
pub fn is_valid_session_id(value: &str) -> bool {
    (MIN_SESSION_ID_BYTES..=MAX_SESSION_ID_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Why a session id was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidSessionId;

impl fmt::Display for InvalidSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "session ids must be {MIN_SESSION_ID_BYTES}-{MAX_SESSION_ID_BYTES} bytes of [A-Za-z0-9_-]"
        )
    }
}

impl std::error::Error for InvalidSessionId {}

/// A stored session.
///
/// Construct through [`Session::new`] so the expiry can never precede the issue
/// time.
#[derive(Clone, PartialEq, Eq)]
pub struct Session {
    id: SessionId,
    subject: String,
    issued_at: u64,
    expires_at: u64,
}

impl Session {
    /// Assemble a session.
    ///
    /// `expires_at` is clamped to at least `issued_at + 1`, so a session always
    /// has a positive window even if a caller passes nonsense.
    #[must_use]
    pub fn new(id: SessionId, subject: impl Into<String>, issued_at: u64, expires_at: u64) -> Self {
        Self {
            id,
            subject: subject.into(),
            issued_at,
            expires_at: expires_at.max(issued_at.saturating_add(1)),
        }
    }

    /// The session id.
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// The subject the session belongs to, as defined by the application.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Unix seconds when the session was created.
    #[must_use]
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Unix seconds when the session expires.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Whether the session has expired at `now` (Unix seconds).
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// The same session with a new expiry.
    #[must_use]
    pub fn with_expires_at(mut self, expires_at: u64) -> Self {
        self.expires_at = expires_at.max(self.issued_at.saturating_add(1));
        self
    }

    /// The same session under a new id.
    #[must_use]
    pub fn with_id(mut self, id: SessionId) -> Self {
        self.id = id;
        self
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("id", &self.id)
            .field("subject", &self.subject)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Storage for sessions.
///
/// Implementations own their error type, so a SQL adapter can keep its own
/// errors. The manager boxes them into one type at its boundary.
///
/// The trait is async without `async-trait`: methods return `impl Future`
/// directly. That costs dynamic dispatch (`dyn SessionStore` is not usable), so
/// hold adapters behind a concrete type or `Arc<S>` with a concrete `S`.
pub trait SessionStore: Send + Sync {
    /// Error returned by this adapter.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Store a new session. Replacing an existing id is up to the adapter.
    fn insert(&self, session: Session) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Look a session up.
    fn get(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Result<Option<Session>, Self::Error>> + Send;

    /// Update the expiry of an existing session.
    ///
    /// Returns `false` when the session is gone, which lets a caller treat a
    /// concurrent revocation as a miss.
    fn touch(
        &self,
        id: &SessionId,
        expires_at: u64,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Delete a session, returning whether it existed.
    fn delete(&self, id: &SessionId) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Delete every session expired at `now`, returning how many were removed.
    fn delete_expired(&self, now: u64) -> impl Future<Output = Result<usize, Self::Error>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> SessionId {
        SessionId::new("abcdefghijklmnop").unwrap()
    }

    #[test]
    fn validates_ids() {
        assert!(is_valid_session_id("abcdefghijklmnop"));
        assert!(!is_valid_session_id("short"));
        assert!(!is_valid_session_id("has space here!"));
        assert!(!is_valid_session_id(&"a".repeat(MAX_SESSION_ID_BYTES + 1)));
        assert!(SessionId::new("bad!").is_err());
    }

    #[test]
    fn ids_are_redacted_in_debug_output() {
        assert_eq!(format!("{:?}", id()), "SessionId(<redacted>)");
        assert_eq!(
            SessionId::new("abcdefghijklmnop").unwrap().as_str(),
            "abcdefghijklmnop"
        );
    }

    #[test]
    fn expiry_never_precedes_issue_time() {
        let session = Session::new(id(), "user-1", 100, 50);
        assert_eq!(session.expires_at(), 101);
        assert!(session.is_expired(101));
        assert!(!session.is_expired(100));
    }

    #[test]
    fn cloning_keeps_identity() {
        let session = Session::new(id(), "user-1", 10, 20);
        let copy = session.clone().with_expires_at(30);
        assert_eq!(copy.id(), session.id());
        assert_eq!(copy.expires_at(), 30);
        assert_eq!(session.expires_at(), 20);
    }
}

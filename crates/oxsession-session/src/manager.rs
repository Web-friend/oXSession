//! Session lifecycle rules.

use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use oxsession_core::{Session, SessionId, SessionStore};

use crate::error::Error;

/// Default idle lifetime: seven days.
pub const DEFAULT_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Default absolute lifetime: thirty days, regardless of activity.
pub const DEFAULT_ABSOLUTE_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Session id length in bytes, before base64url encoding.
const SESSION_ID_BYTES: usize = 32;

/// Wall-clock seconds since the Unix epoch.
///
/// Returns `0` if the system clock is before the epoch, which no real clock is;
/// callers pass this value explicitly so tests and batch jobs can supply their
/// own time.
#[must_use]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// How long sessions last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    ttl: u64,
    absolute_ttl: u64,
}

impl Policy {
    /// Build a policy.
    ///
    /// `ttl` is the idle lifetime refreshed on every valid use; `absolute_ttl`
    /// caps the lifetime from creation no matter how active the session is.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPolicy`] when `ttl` is zero or `absolute_ttl` is
    /// shorter than `ttl`.
    pub fn new(ttl: u64, absolute_ttl: u64) -> Result<Self, InvalidPolicy> {
        if ttl == 0 || absolute_ttl < ttl {
            return Err(InvalidPolicy);
        }
        Ok(Self { ttl, absolute_ttl })
    }

    /// Idle lifetime in seconds.
    #[must_use]
    pub fn ttl(&self) -> u64 {
        self.ttl
    }

    /// Absolute lifetime in seconds.
    #[must_use]
    pub fn absolute_ttl(&self) -> u64 {
        self.absolute_ttl
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_TTL_SECONDS,
            absolute_ttl: DEFAULT_ABSOLUTE_TTL_SECONDS,
        }
    }
}

/// Why a policy was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidPolicy;

impl fmt::Display for InvalidPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ttl must be non-zero and absolute_ttl must be at least ttl")
    }
}

impl std::error::Error for InvalidPolicy {}

/// Creates, validates, refreshes, and revokes sessions for any
/// [`SessionStore`].
pub struct SessionManager<S> {
    store: S,
    policy: Policy,
}

impl<S> SessionManager<S> {
    /// Build a manager over `store`.
    #[must_use]
    pub fn new(store: S, policy: Policy) -> Self {
        Self { store, policy }
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// The backing store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }
}

impl<S> fmt::Debug for SessionManager<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionManager")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<S: SessionStore> SessionManager<S> {
    /// Create a session for `subject`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSubject`] for an empty or whitespace-only subject,
    /// [`Error::Entropy`] when randomness is unavailable, and [`Error::Store`]
    /// when the adapter fails.
    pub async fn create(&self, subject: &str, now: u64) -> Result<Session, Error> {
        if subject.trim().is_empty() {
            return Err(Error::InvalidSubject);
        }

        let id = generate_id()?;
        let lifetime = self.policy.ttl.min(self.policy.absolute_ttl);
        let session = Session::new(id, subject, now, now.saturating_add(lifetime));

        self.store
            .insert(session.clone())
            .await
            .map_err(Error::store)?;

        Ok(session)
    }

    /// Validate a session id, sliding its expiry forward when it is used.
    ///
    /// Expired sessions are deleted before the error is returned, so a client
    /// hammering a dead id cannot keep it alive.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the id is unknown, [`Error::Expired`] when it is
    /// past its idle or absolute deadline, [`Error::Store`] on adapter failure.
    pub async fn validate(&self, id: &SessionId, now: u64) -> Result<Session, Error> {
        let Some(mut session) = self.store.get(id).await.map_err(Error::store)? else {
            return Err(Error::NotFound);
        };

        let absolute_deadline = session.issued_at().saturating_add(self.policy.absolute_ttl);
        if now >= session.expires_at() || now >= absolute_deadline {
            self.store.delete(id).await.map_err(Error::store)?;
            return Err(Error::Expired);
        }

        let refreshed = now.saturating_add(self.policy.ttl).min(absolute_deadline);
        if refreshed > session.expires_at() {
            if !self
                .store
                .touch(id, refreshed)
                .await
                .map_err(Error::store)?
            {
                // Revoked between the read and the touch.
                return Err(Error::NotFound);
            }
            session = session.with_expires_at(refreshed);
        }

        Ok(session)
    }

    /// Revoke a session, returning whether it existed.
    ///
    /// # Errors
    ///
    /// [`Error::Store`] on adapter failure.
    pub async fn revoke(&self, id: &SessionId) -> Result<bool, Error> {
        self.store.delete(id).await.map_err(Error::store)
    }

    /// Replace a session with a fresh id for the same subject.
    ///
    /// Use after a privilege change (password change, MFA enrolment): the old
    /// id stops working immediately.
    ///
    /// # Errors
    ///
    /// Any error from [`SessionManager::validate`] or [`SessionManager::create`].
    pub async fn rotate(&self, id: &SessionId, now: u64) -> Result<Session, Error> {
        let existing = self.validate(id, now).await?;
        let replacement = self.create(existing.subject(), now).await?;
        self.store.delete(id).await.map_err(Error::store)?;
        Ok(replacement)
    }

    /// Delete every session expired at `now`.
    ///
    /// # Errors
    ///
    /// [`Error::Store`] on adapter failure.
    pub async fn purge_expired(&self, now: u64) -> Result<usize, Error> {
        self.store.delete_expired(now).await.map_err(Error::store)
    }
}

fn generate_id() -> Result<SessionId, Error> {
    let mut bytes = [0u8; SESSION_ID_BYTES];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Entropy)?;
    SessionId::new(URL_SAFE_NO_PAD.encode(bytes)).map_err(|_| Error::Entropy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;

    fn manager(policy: Policy) -> SessionManager<MemoryStore> {
        SessionManager::new(MemoryStore::new(), policy)
    }

    fn short_policy() -> Policy {
        Policy::new(100, 1000).unwrap()
    }

    #[tokio::test]
    async fn creates_and_validates() {
        let manager = manager(short_policy());
        let session = manager.create("user-1", 1_000).await.unwrap();
        assert_eq!(session.subject(), "user-1");
        assert_eq!(session.expires_at(), 1_100);

        let validated = manager.validate(session.id(), 1_050).await.unwrap();
        assert_eq!(validated.id(), session.id());
    }

    #[tokio::test]
    async fn unknown_ids_are_not_found() {
        let manager = manager(short_policy());
        let id = SessionId::new("abcdefghijklmnop").unwrap();
        assert!(matches!(
            manager.validate(&id, 0).await,
            Err(Error::NotFound)
        ));
    }

    #[tokio::test]
    async fn idle_sessions_expire_and_are_deleted() {
        let manager = manager(short_policy());
        let session = manager.create("user-1", 1_000).await.unwrap();

        assert!(matches!(
            manager.validate(session.id(), 1_100).await,
            Err(Error::Expired)
        ));
        // The expired session is gone, not merely reported as expired.
        assert!(matches!(
            manager.validate(session.id(), 1_050).await,
            Err(Error::NotFound)
        ));
    }

    #[tokio::test]
    async fn activity_slides_the_expiry() {
        let manager = manager(short_policy());
        let session = manager.create("user-1", 1_000).await.unwrap();

        let refreshed = manager.validate(session.id(), 1_090).await.unwrap();
        assert_eq!(refreshed.expires_at(), 1_190);

        // Still valid past the original expiry.
        assert!(manager.validate(session.id(), 1_150).await.is_ok());
    }

    #[tokio::test]
    async fn absolute_lifetime_caps_sliding() {
        let manager = manager(short_policy());
        let session = manager.create("user-1", 1_000).await.unwrap();

        // Keep the session busy; the absolute deadline is issued_at + 1000.
        for tick in (1_000..1_950).step_by(50) {
            let _ = manager.validate(session.id(), tick).await;
        }

        let last = manager.validate(session.id(), 1_950).await.unwrap();
        assert_eq!(last.expires_at(), 2_000);

        assert!(matches!(
            manager.validate(session.id(), 2_000).await,
            Err(Error::Expired)
        ));
    }

    #[tokio::test]
    async fn revoke_stops_validation() {
        let manager = manager(short_policy());
        let session = manager.create("user-1", 1_000).await.unwrap();

        assert!(manager.revoke(session.id()).await.unwrap());
        assert!(!manager.revoke(session.id()).await.unwrap());
        assert!(matches!(
            manager.validate(session.id(), 1_001).await,
            Err(Error::NotFound)
        ));
    }

    #[tokio::test]
    async fn rotate_issues_a_new_id_and_kills_the_old_one() {
        let manager = manager(short_policy());
        let session = manager.create("user-1", 1_000).await.unwrap();

        let replacement = manager.rotate(session.id(), 1_010).await.unwrap();
        assert_ne!(replacement.id(), session.id());
        assert_eq!(replacement.subject(), "user-1");

        assert!(matches!(
            manager.validate(session.id(), 1_011).await,
            Err(Error::NotFound)
        ));
        assert!(manager.validate(replacement.id(), 1_011).await.is_ok());
    }

    #[tokio::test]
    async fn rejects_empty_subjects() {
        let manager = manager(short_policy());
        assert!(matches!(
            manager.create("   ", 1_000).await,
            Err(Error::InvalidSubject)
        ));
    }

    #[tokio::test]
    async fn purge_removes_only_expired_sessions() {
        let manager = manager(short_policy());
        let stale = manager.create("stale", 1_000).await.unwrap();
        let fresh = manager.create("fresh", 1_000).await.unwrap();

        // Make `fresh` live longer by sliding it before the original expiry.
        manager.validate(fresh.id(), 1_050).await.unwrap();

        assert_eq!(manager.purge_expired(1_100).await.unwrap(), 1);
        assert!(matches!(
            manager.validate(stale.id(), 1_101).await,
            Err(Error::NotFound)
        ));
        assert!(manager.validate(fresh.id(), 1_101).await.is_ok());
    }

    #[tokio::test]
    async fn ids_are_unique_and_cookie_safe() {
        let manager = manager(short_policy());
        let first = manager.create("a", 0).await.unwrap();
        let second = manager.create("a", 0).await.unwrap();

        assert_ne!(first.id(), second.id());
        assert!(oxsession_core::is_valid_value(first.id().as_str()));
        assert_eq!(first.id().as_str().len(), 43);
    }

    #[test]
    fn policy_validation() {
        assert!(Policy::new(1, 1).is_ok());
        assert_eq!(Policy::new(0, 10).unwrap_err(), InvalidPolicy);
        assert_eq!(Policy::new(10, 5).unwrap_err(), InvalidPolicy);
        assert_eq!(Policy::default().ttl(), DEFAULT_TTL_SECONDS);
    }
}

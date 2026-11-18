//! In-memory [`SessionStore`] used by tests, examples, and single-process
//! deployments.

use std::collections::HashMap;
use std::sync::RwLock;

use oxsession_core::{Session, SessionId, SessionStore};

/// Default number of sessions kept in memory.
pub const DEFAULT_CAPACITY: usize = 10_000;

/// A process-local session store.
///
/// Data is lost on restart and never shared between processes, so this is a
/// development and single-node adapter, not a production database. It is,
/// however, a complete implementation of the [`SessionStore`] contract: tests
/// written against it apply to any adapter.
///
/// When the store is full, the session closest to expiry is evicted to make
/// room. That keeps a burst of logins from failing while bounding memory.
pub struct MemoryStore {
    sessions: RwLock<HashMap<SessionId, Session>>,
    capacity: usize,
}

impl MemoryStore {
    /// A store holding up to [`DEFAULT_CAPACITY`] sessions.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// A store holding up to `capacity` sessions.
    ///
    /// A capacity of zero is treated as one: the store is never unable to hold
    /// the session it was just asked to insert.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Number of sessions currently held.
    ///
    /// # Panics
    ///
    /// Panics if the lock was poisoned, which only happens when another thread
    /// panicked while holding it.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions
            .read()
            .expect("session store lock poisoned")
            .len()
    }

    /// Whether the store holds no sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemoryStore")
            .field("capacity", &self.capacity)
            .field("len", &self.len())
            .finish()
    }
}

impl SessionStore for MemoryStore {
    type Error = MemoryStoreError;

    async fn insert(&self, session: Session) -> Result<(), Self::Error> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| MemoryStoreError::Poisoned)?;

        if !sessions.contains_key(session.id()) && sessions.len() >= self.capacity {
            let evicted = sessions
                .values()
                .min_by_key(|stored| stored.expires_at())
                .map(|stored| stored.id().clone());
            if let Some(evicted) = evicted {
                sessions.remove(&evicted);
            }
        }

        sessions.insert(session.id().clone(), session);
        Ok(())
    }

    async fn get(&self, id: &SessionId) -> Result<Option<Session>, Self::Error> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| MemoryStoreError::Poisoned)?;
        Ok(sessions.get(id).cloned())
    }

    async fn touch(&self, id: &SessionId, expires_at: u64) -> Result<bool, Self::Error> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| MemoryStoreError::Poisoned)?;
        match sessions.get_mut(id) {
            Some(session) => {
                *session = session.clone().with_expires_at(expires_at);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn delete(&self, id: &SessionId) -> Result<bool, Self::Error> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| MemoryStoreError::Poisoned)?;
        Ok(sessions.remove(id).is_some())
    }

    async fn delete_expired(&self, now: u64) -> Result<usize, Self::Error> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| MemoryStoreError::Poisoned)?;
        let before = sessions.len();
        sessions.retain(|_, session| !session.is_expired(now));
        Ok(before - sessions.len())
    }
}

/// Failure mode of [`MemoryStore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryStoreError {
    /// Another thread panicked while holding the store lock.
    Poisoned,
}

impl std::fmt::Display for MemoryStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("in-memory session store lock is poisoned")
    }
}

impl std::error::Error for MemoryStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(id: &str, expires_at: u64) -> Session {
        Session::new(SessionId::new(id).unwrap(), "user-1", 0, expires_at)
    }

    fn id(value: &str) -> SessionId {
        SessionId::new(value).unwrap()
    }

    #[tokio::test]
    async fn stores_and_reads_sessions() {
        let store = MemoryStore::new();
        store
            .insert(session("abcdefghijklmnop", 100))
            .await
            .unwrap();

        let found = store.get(&id("abcdefghijklmnop")).await.unwrap().unwrap();
        assert_eq!(found.subject(), "user-1");
        assert!(store.get(&id("ponmlkjihgfedcba")).await.unwrap().is_none());
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn touch_updates_the_expiry() {
        let store = MemoryStore::new();
        store
            .insert(session("abcdefghijklmnop", 100))
            .await
            .unwrap();

        assert!(store.touch(&id("abcdefghijklmnop"), 500).await.unwrap());
        let found = store.get(&id("abcdefghijklmnop")).await.unwrap().unwrap();
        assert_eq!(found.expires_at(), 500);

        assert!(!store.touch(&id("ponmlkjihgfedcba"), 500).await.unwrap());
    }

    #[tokio::test]
    async fn delete_reports_whether_it_existed() {
        let store = MemoryStore::new();
        store
            .insert(session("abcdefghijklmnop", 100))
            .await
            .unwrap();

        assert!(store.delete(&id("abcdefghijklmnop")).await.unwrap());
        assert!(!store.delete(&id("abcdefghijklmnop")).await.unwrap());
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn delete_expired_removes_only_expired() {
        let store = MemoryStore::new();
        store
            .insert(session("abcdefghijklmnop", 100))
            .await
            .unwrap();
        store
            .insert(session("ponmlkjihgfedcba", 300))
            .await
            .unwrap();

        assert_eq!(store.delete_expired(150).await.unwrap(), 1);
        assert!(store.get(&id("abcdefghijklmnop")).await.unwrap().is_none());
        assert!(store.get(&id("ponmlkjihgfedcba")).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn evicts_the_session_closest_to_expiry_when_full() {
        let store = MemoryStore::with_capacity(2);
        store
            .insert(session("aaaaaaaaaaaaaaaa", 100))
            .await
            .unwrap();
        store
            .insert(session("bbbbbbbbbbbbbbbb", 200))
            .await
            .unwrap();
        store
            .insert(session("cccccccccccccccc", 300))
            .await
            .unwrap();

        assert_eq!(store.len(), 2);
        assert!(store.get(&id("aaaaaaaaaaaaaaaa")).await.unwrap().is_none());
        assert!(store.get(&id("bbbbbbbbbbbbbbbb")).await.unwrap().is_some());
        assert!(store.get(&id("cccccccccccccccc")).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn zero_capacity_still_holds_one_session() {
        let store = MemoryStore::with_capacity(0);
        store
            .insert(session("abcdefghijklmnop", 100))
            .await
            .unwrap();
        assert_eq!(store.len(), 1);
    }
}

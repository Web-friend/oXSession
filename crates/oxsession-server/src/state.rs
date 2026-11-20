use std::sync::Arc;

use oxsession_core::SessionStore;
use oxsession_session::{MemoryStore, SessionManager};

use crate::config::Config;

/// Everything a handler needs.
///
/// The store is process-local for now; swapping in a SQL adapter changes the
/// type parameter and nothing else, because handlers only see [`SessionManager`].
#[derive(Debug)]
pub struct AppState<S: SessionStore> {
    pub config: Config,
    pub sessions: Arc<SessionManager<S>>,
}

impl<S: SessionStore> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            sessions: Arc::clone(&self.sessions),
        }
    }
}

impl<S: SessionStore> AppState<S> {
    /// Build state over `store`, deriving the policy from `config`.
    #[must_use]
    pub fn new(config: Config, store: S) -> Self {
        let sessions = SessionManager::new(store, config.policy);
        Self {
            config,
            sessions: Arc::new(sessions),
        }
    }
}

/// The in-memory deployment of [`AppState`].
pub type MemoryAppState = AppState<MemoryStore>;

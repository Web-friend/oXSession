use std::sync::Arc;

use oxsession_session::{MemoryStore, SessionManager};

use crate::config::Config;

/// Everything a handler needs.
///
/// The store is process-local for now; swapping in a SQL adapter changes this
/// field and nothing else, because handlers only see `SessionManager`.
#[derive(Clone, Debug)]
pub struct AppState {
    pub config: Config,
    pub sessions: Arc<SessionManager<MemoryStore>>,
}

impl AppState {
    #[must_use]
    pub fn new(config: Config) -> Self {
        let sessions = SessionManager::new(MemoryStore::new(), config.policy);
        Self {
            config,
            sessions: Arc::new(sessions),
        }
    }
}

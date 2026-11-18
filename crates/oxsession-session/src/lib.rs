//! Session lifecycle for oXSession.
//!
//! [`SessionManager`] owns the rules — how long a session lives, when it
//! slides, when it is revoked — and delegates storage to any
//! [`SessionStore`](oxsession_core::SessionStore).
//!
//! [`MemoryStore`] is the reference adapter: correct, dependency-free, and
//! process-local. It exists so the rest of the stack (and its tests) can run
//! without a database; production deployments are expected to use a durable
//! adapter with the same contract.
//!
//! ```
//! use oxsession_session::{MemoryStore, Policy, SessionManager};
//!
//! # async fn demo() {
//! let manager = SessionManager::new(MemoryStore::new(), Policy::default());
//! let session = manager
//!     .create("user-42", oxsession_session::now())
//!     .await
//!     .unwrap();
//! assert_eq!(session.subject(), "user-42");
//! # }
//! ```
#![warn(missing_docs)]

mod error;
mod manager;
mod memory;

pub use error::Error;
pub use manager::{
    DEFAULT_ABSOLUTE_TTL_SECONDS, DEFAULT_TTL_SECONDS, InvalidPolicy, Policy, SessionManager, now,
};
pub use memory::{DEFAULT_CAPACITY, MemoryStore, MemoryStoreError};

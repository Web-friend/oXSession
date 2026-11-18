//! Optional standalone HTTP server for oXSession.
//!
//! The binary in `main.rs` is a thin wrapper: [`config`] reads the environment
//! and [`routes`] builds the router, so both are testable without binding a
//! socket.

pub mod config;
pub mod routes;
pub mod state;

pub use state::AppState;

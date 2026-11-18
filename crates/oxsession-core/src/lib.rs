//! Framework-agnostic core for oXSession.
//!
//! This crate deliberately knows nothing about Axum, Actix, Hyper, SQL, or
//! environment variables. It owns the parts that every integration must agree
//! on, so that adapters cannot drift apart:
//!
//! - [`Pairs`] parses the wire format of `Cookie` request headers.
//! - [`SetCookie`] validates and serializes `Set-Cookie` response headers,
//!   including the `__Host-` and `__Secure-` rules.
//! - [`Credentials`] resolves a session credential from a `Bearer` token or a
//!   cookie, in one place, for every framework and every non-browser client.
//!
//! Adapters live in sibling crates (`oxsession-axum`, ...) and are expected to
//! be thin: map request parts into the types here, and map [`Error`] back into
//! their own response type.
#![warn(missing_docs)]

mod cookies;
mod credentials;
mod error;
mod set_cookie;

pub use cookies::{
    Ambiguous, Iter, MAX_COOKIE_HEADER_BYTES, MAX_COOKIE_PAIRS, Pair, Pairs, Stats, is_valid_name,
    is_valid_value,
};
pub use credentials::{Credentials, resolve};
pub use error::{Error, Result};
pub use set_cookie::{Prefix, SameSite, SetCookie, SetCookieBuilder};

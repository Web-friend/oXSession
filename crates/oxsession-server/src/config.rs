use std::{
    env,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use oxsession_session::Policy;
use oxsession_sign::{CookieSigner, KeyId, SecretKey};

/// Configuration of the standalone server.
///
/// This lives in the server crate on purpose: the library is configured
/// programmatically, and only the optional binary reads the environment.
#[derive(Clone, Debug)]
pub struct Config {
    pub bind_address: SocketAddr,
    pub session_cookie: String,
    pub policy: Policy,
    /// Send the session cookie with `Secure`. Off by default so `http://localhost`
    /// works; turn it on anywhere else.
    pub session_cookie_secure: bool,
    /// Enables `POST /sessions`, which mints a session for any subject without
    /// authentication. Development only.
    pub dev_login: bool,
    /// How a minted session credential reaches the client.
    ///
    /// See [`SessionDelivery`]. Defaults to [`SessionDelivery::Cookie`].
    pub session_delivery: SessionDelivery,
    /// `None` when `AUTH_COOKIE_KEYS` is unset: the session id then travels as
    /// an opaque cookie instead of a signed one.
    pub signer: Option<Arc<CookieSigner>>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let host = env::var("AUTH_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".to_owned());
        let ip: IpAddr = host
            .parse()
            .with_context(|| format!("AUTH_BIND_ADDR must be a valid IP address, got {host:?}"))?;

        let port = match env::var("AUTH_PORT") {
            Ok(value) => value.parse::<u16>().with_context(|| {
                format!("AUTH_PORT must be an integer from 0 to 65535, got {value:?}")
            })?,
            Err(env::VarError::NotPresent) => 3000,
            Err(error) => return Err(error).context("AUTH_PORT is not valid Unicode"),
        };

        if port == 0 {
            bail!("AUTH_PORT must be between 1 and 65535");
        }

        let session_cookie =
            env::var("AUTH_SESSION_COOKIE").unwrap_or_else(|_| "session".to_owned());
        if !oxsession_core::is_valid_name(&session_cookie) {
            bail!(
                "AUTH_SESSION_COOKIE must be a valid cookie name (RFC 7230 token), got {session_cookie:?}"
            );
        }

        let ttl = seconds(
            "AUTH_SESSION_TTL_SECONDS",
            oxsession_session::DEFAULT_TTL_SECONDS,
        )?;
        let absolute = seconds(
            "AUTH_SESSION_ABSOLUTE_TTL_SECONDS",
            oxsession_session::DEFAULT_ABSOLUTE_TTL_SECONDS,
        )?;
        let policy = Policy::new(ttl, absolute)
            .with_context(|| {
                format!(
                    "AUTH_SESSION_TTL_SECONDS ({ttl}) must be non-zero and no larger than AUTH_SESSION_ABSOLUTE_TTL_SECONDS ({absolute})"
                )
            })?;

        let signer = match env::var("AUTH_COOKIE_KEYS") {
            Ok(value) if !value.trim().is_empty() => Some(Arc::new(
                parse_signer(&value).context("AUTH_COOKIE_KEYS is invalid")?,
            )),
            _ => None,
        };

        let session_delivery = match env::var("AUTH_SESSION_DELIVERY") {
            Ok(value) => value.parse().with_context(|| {
                format!(
                    "AUTH_SESSION_DELIVERY must be `cookie`, `token`, or `both`, got {value:?}"
                )
            })?,
            Err(env::VarError::NotPresent) => SessionDelivery::Cookie,
            Err(error) => return Err(error).context("AUTH_SESSION_DELIVERY is not valid Unicode"),
        };

        Ok(Self {
            bind_address: SocketAddr::new(ip, port),
            session_cookie,
            policy,
            session_cookie_secure: flag("AUTH_SESSION_COOKIE_SECURE"),
            dev_login: flag("AUTH_DEV_LOGIN"),
            session_delivery,
            signer,
        })
    }
}

/// Where `POST /sessions` puts the credential it just minted.
///
/// The session id is a bearer credential either way; this only decides which
/// carrier a client should look at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SessionDelivery {
    /// `Set-Cookie` only. The id never appears in a response body, so scripts
    /// cannot read it and it stays out of application logs and caches.
    #[default]
    Cookie,
    /// Response body only, for clients that keep the id themselves — a browser
    /// storing it in `localStorage`, a mobile app, a CLI — and present it as
    /// `Authorization: Bearer`.
    ///
    /// This trades `HttpOnly` protection for portability: any script able to
    /// read `localStorage` (including one injected via XSS) can steal the id.
    Token,
    /// Both carriers, for migrating an existing cookie client to tokens or the
    /// reverse. Sockets with both present prefer the `Authorization` header.
    Both,
}

impl SessionDelivery {
    /// Whether a minted session should also be set as a cookie.
    #[must_use]
    pub fn sends_cookie(self) -> bool {
        matches!(self, Self::Cookie | Self::Both)
    }

    /// Whether a minted session should also be returned in the response body.
    #[must_use]
    pub fn sends_token(self) -> bool {
        matches!(self, Self::Token | Self::Both)
    }
}

impl std::str::FromStr for SessionDelivery {
    type Err = InvalidSessionDelivery;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "cookie" => Ok(Self::Cookie),
            "token" => Ok(Self::Token),
            "both" => Ok(Self::Both),
            _ => Err(InvalidSessionDelivery),
        }
    }
}

/// Why `AUTH_SESSION_DELIVERY` was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidSessionDelivery;

impl std::fmt::Display for InvalidSessionDelivery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("expected `cookie`, `token`, or `both`")
    }
}

impl std::error::Error for InvalidSessionDelivery {}

fn seconds(name: &str, default: u64) -> Result<u64> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .with_context(|| format!("{name} must be a non-negative integer, got {value:?}")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).context(format!("{name} is not valid Unicode")),
    }
}

fn flag(name: &str) -> bool {
    matches!(env::var(name).as_deref(), Ok("1") | Ok("true") | Ok("yes"))
}

/// Parse `keyid:base64url,keyid:base64url,...`; the first entry signs and the
/// rest are retained for verification.
fn parse_signer(value: &str) -> Result<CookieSigner> {
    let mut entries = value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty());

    let first = entries
        .next()
        .context("at least one `keyid:base64url` entry is required")?;
    let (id, key) = split_entry(first)?;

    let mut signer = CookieSigner::new(key_id(id)?, secret(key)?);
    for entry in entries {
        let (id, key) = split_entry(entry)?;
        signer = signer.with_previous(key_id(id)?, secret(key)?)?;
    }
    Ok(signer)
}

fn split_entry(entry: &str) -> Result<(&str, &str)> {
    entry
        .split_once(':')
        .with_context(|| format!("expected `keyid:base64url`, got {entry:?}"))
}

fn key_id(id: &str) -> Result<KeyId> {
    KeyId::new(id).with_context(|| format!("invalid key id {id:?}"))
}

fn secret(encoded: &str) -> Result<SecretKey> {
    SecretKey::from_base64url(encoded)
        .context("invalid key material, expected 32 bytes of unpadded base64url")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    fn encode(bytes: impl AsRef<[u8]>) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn parses_a_single_key() {
        let value = format!("k1:{}", encode([7; 32]));
        let signer = parse_signer(&value).unwrap();
        assert_eq!(signer.key_id(), "k1");
    }

    #[test]
    fn parses_current_and_previous_keys() {
        let value = format!("k2:{},k1:{}", encode([2; 32]), encode([1; 32]));
        let signer = parse_signer(&value).unwrap();
        assert_eq!(signer.key_id(), "k2");
    }

    #[test]
    fn rejects_malformed_entries() {
        assert!(parse_signer("").is_err());
        assert!(parse_signer("k1").is_err());
        assert!(parse_signer("k1:not-base64!").is_err());
        assert!(parse_signer(&format!("has space:{}", encode([1; 32]))).is_err());
        assert!(parse_signer(&format!("k1:{}", encode([1; 16]))).is_err());
    }

    #[test]
    fn flags_accept_common_truthy_values() {
        // The helper only reads the process environment, so this asserts the
        // shape rather than mutating global state.
        assert!(matches!("true", "1" | "true" | "yes"));
        assert!(!matches!("0", "1" | "true" | "yes"));
    }

    #[test]
    fn parses_delivery_modes() {
        assert_eq!(
            "cookie".parse::<SessionDelivery>().unwrap(),
            SessionDelivery::Cookie
        );
        assert_eq!(
            " Token ".parse::<SessionDelivery>().unwrap(),
            SessionDelivery::Token
        );
        assert_eq!(
            "BOTH".parse::<SessionDelivery>().unwrap(),
            SessionDelivery::Both
        );
        assert!("bearer".parse::<SessionDelivery>().is_err());
        assert_eq!(SessionDelivery::default(), SessionDelivery::Cookie);
    }

    #[test]
    fn delivery_decides_carriers() {
        assert!(SessionDelivery::Cookie.sends_cookie());
        assert!(!SessionDelivery::Cookie.sends_token());

        assert!(!SessionDelivery::Token.sends_cookie());
        assert!(SessionDelivery::Token.sends_token());

        assert!(SessionDelivery::Both.sends_cookie());
        assert!(SessionDelivery::Both.sends_token());
    }
}

use std::{
    env,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use oxsession_sign::{CookieSigner, KeyId, SecretKey};

/// Configuration of the standalone server.
///
/// This lives in the server crate on purpose: the library is configured
/// programmatically, and only the optional binary reads the environment.
#[derive(Clone, Debug)]
pub struct Config {
    pub bind_address: SocketAddr,
    pub session_cookie: String,
    /// `None` when `AUTH_COOKIE_KEYS` is unset: session cookies are then read
    /// as opaque tokens, exactly as before signing existed.
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

        let signer = match env::var("AUTH_COOKIE_KEYS") {
            Ok(value) if !value.trim().is_empty() => Some(Arc::new(
                parse_signer(&value).context("AUTH_COOKIE_KEYS is invalid")?,
            )),
            _ => None,
        };

        Ok(Self {
            bind_address: SocketAddr::new(ip, port),
            session_cookie,
            signer,
        })
    }
}

/// Parse `keyid:base64url,keyid:base64url,...`; the first entry is the current
/// signing key and the rest are retained for verification.
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
        .with_context(|| "invalid key material, expected 32 bytes of unpadded base64url")
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
}

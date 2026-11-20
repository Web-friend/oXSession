//! HMAC-signed cookies for oXSession.
//!
//! Signing is opt-in and per cookie: build a [`CookieSigner`] from your own key
//! and pass the cookies you care about through [`CookieSigner::sign`] and
//! [`CookieSigner::verify`].
//!
//! # Wire format
//!
//! ```text
//! os1.<keyid>.<payload>.<mac>
//! ```
//!
//! - `os1` is the format version.
//! - `<keyid>` is `[A-Za-z0-9_-]{1,16}` and exists so keys can be rotated
//!   without invalidating every cookie in the wild.
//! - `<payload>` is the caller's value and must consist of cookie-octets
//!   (RFC 6265bis) and contain no `.`.
//! - `<mac>` is the unpadded base64url encoding of
//!   `HMAC-SHA256(key, "os1." + keyid + "." + name + "." + payload)`.
//!
//! The cookie *name* is signed along with the value, so a value issued for
//! `session` cannot be replayed as `admin`.
//!
//! # What signing does not do
//!
//! Signing proves authenticity, not secrecy: the payload stays readable by the
//! client. Do not store secrets in a signed cookie.
//!
//! # Example
//!
//! ```
//! use oxsession_sign::{CookieSigner, KeyId, SecretKey};
//!
//! let signer = CookieSigner::new(
//!     KeyId::new("k1").unwrap(),
//!     SecretKey::from_slice(&[7; 32]).unwrap(),
//! );
//!
//! let wire = signer.sign("session", "dXNlcj00Mg").unwrap();
//! assert_eq!(signer.verify("session", &wire).unwrap(), "dXNlcj00Mg");
//! assert!(signer.verify("admin", &wire).is_err());
//! ```
#![warn(missing_docs)]

mod error;
mod format;
mod key;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub use error::{Error, ErrorCategory};
pub use key::{KEY_BYTES, KeyId, MAX_KEY_ID_BYTES, SecretKey};

type HmacSha256 = Hmac<Sha256>;

/// How many retired keys are kept for verification.
///
/// Every retained key is a key that still authenticates cookies, so the window
/// stays deliberately small: rotate more than this many times without letting
/// the oldest cookies expire and you have a key you cannot retire.
pub const MAX_PREVIOUS_KEYS: usize = 2;

/// Signs and verifies cookie values, with key rotation.
pub struct CookieSigner {
    current: SigningKey,
    previous: Vec<SigningKey>,
}

struct SigningKey {
    id: KeyId,
    secret: SecretKey,
}

impl CookieSigner {
    /// Create a signer whose current key is `key_id`.
    #[must_use]
    pub fn new(key_id: KeyId, key: SecretKey) -> Self {
        Self {
            current: SigningKey {
                id: key_id,
                secret: key,
            },
            previous: Vec::new(),
        }
    }

    /// Convenience constructor from raw configuration values.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyId`] or [`Error::KeySize`].
    pub fn from_parts(key_id: &str, key: &[u8]) -> Result<Self, Error> {
        Ok(Self::new(KeyId::new(key_id)?, SecretKey::from_slice(key)?))
    }

    /// Retain an older key for verification, keeping newer keys as current.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooManyKeys`] once [`MAX_PREVIOUS_KEYS`] retired keys
    /// are already stored, or [`Error::DuplicateKeyId`] if `key_id` is already
    /// in the ring.
    pub fn with_previous(mut self, key_id: KeyId, key: SecretKey) -> Result<Self, Error> {
        self.add_previous(key_id, key)?;
        Ok(self)
    }

    /// Retain an older key for verification, keeping newer keys as current.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooManyKeys`] once [`MAX_PREVIOUS_KEYS`] retired keys
    /// are already stored, or [`Error::DuplicateKeyId`] if `key_id` is already
    /// in the ring. On error, the signer is unchanged.
    pub fn add_previous(&mut self, key_id: KeyId, key: SecretKey) -> Result<(), Error> {
        if self.contains_key_id(key_id.as_str()) {
            return Err(Error::DuplicateKeyId);
        }
        if self.previous.len() == MAX_PREVIOUS_KEYS {
            return Err(Error::TooManyKeys);
        }
        self.previous.push(SigningKey {
            id: key_id,
            secret: key,
        });
        Ok(())
    }

    /// Promote a new current key, retiring the old one for verification.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DuplicateKeyId`] if `key_id` is already in the ring.
    pub fn rotate(&mut self, key_id: KeyId, key: SecretKey) -> Result<(), Error> {
        if self.contains_key_id(key_id.as_str()) {
            return Err(Error::DuplicateKeyId);
        }
        let retired = std::mem::replace(
            &mut self.current,
            SigningKey {
                id: key_id,
                secret: key,
            },
        );
        self.previous.insert(0, retired);
        self.previous.truncate(MAX_PREVIOUS_KEYS);
        Ok(())
    }

    /// The id of the key used for signing.
    #[must_use]
    pub fn key_id(&self) -> &str {
        self.current.id.as_str()
    }

    /// Sign `payload` for the cookie called `name`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidCookieName`] when `name` is not an RFC 7230 token.
    /// - [`Error::PayloadNotEncodable`] when `payload` is empty, contains `.`,
    ///   or has bytes that cannot appear in a cookie value.
    /// - [`Error::TooLong`] when the result would exceed 4096 bytes.
    pub fn sign(&self, name: &str, payload: &str) -> Result<String, Error> {
        if !oxsession_core::is_valid_name(name) {
            return Err(Error::InvalidCookieName);
        }
        if payload.is_empty() || payload.contains('.') || !oxsession_core::is_valid_value(payload) {
            return Err(Error::PayloadNotEncodable);
        }

        let mac = mac(
            &self.current.secret,
            self.current.id.as_str(),
            name,
            payload,
        );
        let wire = format::render(self.current.id.as_str(), payload, &mac);

        if wire.len() > format::MAX_WIRE_BYTES {
            return Err(Error::TooLong);
        }
        Ok(wire)
    }

    /// Verify a cookie value for `name` and return its payload.
    ///
    /// An unsigned value, a value signed for a different cookie name, an
    /// unknown key id, and a corrupted signature all fail. There is no
    /// fallback to accepting the value as-is.
    ///
    /// # Errors
    ///
    /// See [`Error`]. Callers should not expose the difference between
    /// [`Error::BadMac`] and [`Error::UnknownKey`] to clients: a distinguishable
    /// failure is a signature-check oracle.
    pub fn verify<'a>(&self, name: &str, wire: &'a str) -> Result<&'a str, Error> {
        if !oxsession_core::is_valid_name(name) {
            return Err(Error::InvalidCookieName);
        }
        if wire.len() > format::MAX_WIRE_BYTES {
            return Err(Error::TooLong);
        }

        let parts = format::parse(wire)?;
        let secret = self.signing_key(parts.key_id).ok_or(Error::UnknownKey)?;

        let expected = mac(secret, parts.key_id, name, parts.payload);
        if !bool::from(expected.ct_eq(&parts.mac)) {
            return Err(Error::BadMac);
        }
        Ok(parts.payload)
    }

    fn signing_key(&self, key_id: &str) -> Option<&SecretKey> {
        if self.current.id.as_str() == key_id {
            return Some(&self.current.secret);
        }
        self.previous
            .iter()
            .find(|key| key.id.as_str() == key_id)
            .map(|key| &key.secret)
    }

    fn contains_key_id(&self, key_id: &str) -> bool {
        self.current.id.as_str() == key_id
            || self.previous.iter().any(|key| key.id.as_str() == key_id)
    }
}

impl std::fmt::Debug for CookieSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CookieSigner")
            .field("key_id", &self.current.id)
            .field("previous", &self.previous.len())
            .finish()
    }
}

fn mac(secret: &SecretKey, key_id: &str, name: &str, payload: &str) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(format::VERSION.as_bytes());
    mac.update(b".");
    mac.update(key_id.as_bytes());
    mac.update(b".");
    mac.update(name.as_bytes());
    mac.update(b".");
    mac.update(payload.as_bytes());

    let bytes = mac.finalize().into_bytes();
    let mut signature = [0u8; 32];
    signature.copy_from_slice(&bytes);
    signature
}

//! Key material and key identifiers.

use core::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use crate::error::Error;

/// Length of a signing key in bytes.
pub const KEY_BYTES: usize = 32;

/// Largest accepted key identifier, in bytes.
pub const MAX_KEY_ID_BYTES: usize = 16;

/// Identifies which key produced a signature.
///
/// Ids are public: they travel in every signed cookie so that old keys can
/// still verify while a new key signs.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(Box<str>);

impl KeyId {
    /// Create an id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyId`] unless `value` is 1–16 bytes of
    /// `[A-Za-z0-9_-]`.
    pub fn new(value: &str) -> Result<Self, Error> {
        if !is_valid_key_id(value) {
            return Err(Error::InvalidKeyId);
        }
        Ok(Self(value.into()))
    }

    /// The id as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "KeyId({:?})", self.0)
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<&str> for KeyId {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Whether `value` can be used as a key id.
#[must_use]
pub fn is_valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KEY_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// A 256-bit HMAC key.
///
/// The bytes are zeroized on drop and never appear in `Debug` output.
#[derive(Clone)]
pub struct SecretKey(Zeroizing<[u8; KEY_BYTES]>);

impl SecretKey {
    /// Wrap exactly [`KEY_BYTES`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeySize`] when `bytes` has any other length. Short keys
    /// are rejected rather than padded: a 16-byte "key" is a mistake, not a
    /// preference.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let array: [u8; KEY_BYTES] = bytes.try_into().map_err(|_| Error::KeySize)?;
        Ok(Self(Zeroizing::new(array)))
    }

    /// Decode an unpadded base64url key, as used in configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyEncoding`] when `encoded` is not base64url, or
    /// [`Error::KeySize`] when it does not decode to [`KEY_BYTES`] bytes.
    pub fn from_base64url(encoded: &str) -> Result<Self, Error> {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .map_err(|_| Error::InvalidKeyEncoding)?;
        Self::from_slice(&bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &*self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_key_ids() {
        assert!(KeyId::new("k1").is_ok());
        assert!(KeyId::new("2024-11_rotation").is_ok());
        assert_eq!(KeyId::new("").unwrap_err(), Error::InvalidKeyId);
        assert_eq!(KeyId::new("has space").unwrap_err(), Error::InvalidKeyId);
        assert_eq!(KeyId::new("has.dot").unwrap_err(), Error::InvalidKeyId);
        assert_eq!(
            KeyId::new(&"x".repeat(MAX_KEY_ID_BYTES + 1)).unwrap_err(),
            Error::InvalidKeyId
        );
    }

    #[test]
    fn requires_exactly_32_key_bytes() {
        assert!(SecretKey::from_slice(&[0; 32]).is_ok());
        assert_eq!(SecretKey::from_slice(&[0; 16]).unwrap_err(), Error::KeySize);
        assert_eq!(SecretKey::from_slice(&[0; 33]).unwrap_err(), Error::KeySize);
    }

    #[test]
    fn decodes_base64url_keys() {
        let encoded = URL_SAFE_NO_PAD.encode([7u8; 32]);
        assert!(SecretKey::from_base64url(&encoded).is_ok());
        assert_eq!(
            SecretKey::from_base64url("not base64!").unwrap_err(),
            Error::InvalidKeyEncoding
        );
        assert_eq!(
            SecretKey::from_base64url(&URL_SAFE_NO_PAD.encode([7u8; 16])).unwrap_err(),
            Error::KeySize
        );
    }

    #[test]
    fn secrets_never_appear_in_debug_output() {
        let key = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "SecretKey(<redacted>)");
    }
}

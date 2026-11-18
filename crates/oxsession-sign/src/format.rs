//! The signed-cookie wire format: `os1.<keyid>.<payload>.<mac>`.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::error::Error;
use crate::key::is_valid_key_id;

/// Version prefix of the format described in the crate docs.
pub(crate) const VERSION: &str = "os1";

/// Largest accepted signed value, in bytes.
pub(crate) const MAX_WIRE_BYTES: usize = 4096;

/// Length of an encoded MAC: 32 bytes of base64url without padding.
const MAC_ENCODED_BYTES: usize = 43;

/// A parsed signed value.
#[derive(Debug)]
pub(crate) struct Parts<'a> {
    pub(crate) key_id: &'a str,
    pub(crate) payload: &'a str,
    pub(crate) mac: [u8; 32],
}

/// Split and validate a signed value.
///
/// Nothing here authenticates anything: the MAC is compared by the caller, in
/// constant time, against a recomputed value.
pub(crate) fn parse(wire: &str) -> Result<Parts<'_>, Error> {
    if wire.len() > MAX_WIRE_BYTES {
        return Err(Error::TooLong);
    }

    let mut fields = wire.split('.');
    let (Some(version), Some(key_id), Some(payload), Some(mac), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(Error::Malformed);
    };

    if version != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if !is_valid_key_id(key_id) {
        return Err(Error::Malformed);
    }
    if payload.is_empty() || !oxsession_core::is_valid_value(payload) {
        return Err(Error::Malformed);
    }

    Ok(Parts {
        key_id,
        payload,
        mac: decode_mac(mac)?,
    })
}

/// Render a signed value.
pub(crate) fn render(key_id: &str, payload: &str, mac: &[u8; 32]) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(mac);

    let mut wire =
        String::with_capacity(VERSION.len() + key_id.len() + payload.len() + encoded.len() + 3);
    wire.push_str(VERSION);
    wire.push('.');
    wire.push_str(key_id);
    wire.push('.');
    wire.push_str(payload);
    wire.push('.');
    wire.push_str(&encoded);
    wire
}

fn decode_mac(encoded: &str) -> Result<[u8; 32], Error> {
    if encoded.len() != MAC_ENCODED_BYTES {
        return Err(Error::Malformed);
    }

    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::Malformed)?;

    bytes.try_into().map_err(|_| Error::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let mac = [3u8; 32];
        let wire = render("k1", "abc", &mac);
        let parts = parse(&wire).unwrap();
        assert_eq!(parts.key_id, "k1");
        assert_eq!(parts.payload, "abc");
        assert_eq!(parts.mac, mac);
    }

    #[test]
    fn rejects_wrong_shapes() {
        assert_eq!(parse("").unwrap_err(), Error::Malformed);
        assert_eq!(parse("os1").unwrap_err(), Error::Malformed);
        assert_eq!(parse("os1.k1.abc").unwrap_err(), Error::Malformed);
        assert_eq!(parse("os1.k1.abc.mac.extra").unwrap_err(), Error::Malformed);
        assert_eq!(
            parse("os1..abc.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap_err(),
            Error::Malformed
        );
        assert_eq!(
            parse("os2.k1.abc.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap_err(),
            Error::UnsupportedVersion
        );
    }

    #[test]
    fn rejects_bad_payloads_and_macs() {
        let good_mac = "A".repeat(MAC_ENCODED_BYTES);
        assert_eq!(
            parse(&format!("os1.k1..{good_mac}")).unwrap_err(),
            Error::Malformed
        );
        assert_eq!(
            parse(&format!("os1.k1.a b.{good_mac}")).unwrap_err(),
            Error::Malformed
        );
        assert_eq!(parse("os1.k1.abc.short").unwrap_err(), Error::Malformed);
        assert_eq!(
            parse(&format!("os1.k1.abc.{}", "!".repeat(MAC_ENCODED_BYTES))).unwrap_err(),
            Error::Malformed
        );
    }

    #[test]
    fn rejects_oversized_values_before_parsing() {
        let wire = format!("os1.k1.{}", "a".repeat(MAX_WIRE_BYTES));
        assert_eq!(parse(&wire).unwrap_err(), Error::TooLong);
    }
}

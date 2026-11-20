//! Interoperability tests for the signed-cookie format.
//!
//! The vector below is published in `docs/signing.md`. A client implemented in
//! another language must reproduce it exactly; if these literals change, the
//! wire format changed and every existing cookie is invalidated.

use oxsession_sign::{CookieSigner, Error, KeyId, SecretKey};

/// Bytes 0x00..0x1f.
const KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

const PAYLOAD: &str = "dXNlcj00Mg";

fn signer() -> CookieSigner {
    CookieSigner::new(
        KeyId::new("k1").unwrap(),
        SecretKey::from_slice(&KEY).unwrap(),
    )
}

fn key_id(value: &str) -> KeyId {
    KeyId::new(value).unwrap()
}

fn secret(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap()
}

#[test]
fn matches_the_published_vector() {
    assert_eq!(
        signer().sign("session", PAYLOAD).unwrap(),
        "os1.k1.dXNlcj00Mg.jFXRwvjzXLIZFL-SyIwwPuGKD5ehMEcrvK6D8A4SNtY"
    );
}

#[test]
fn round_trips() {
    let wire = signer().sign("session", PAYLOAD).unwrap();
    assert_eq!(signer().verify("session", &wire).unwrap(), PAYLOAD);
}

#[test]
fn signatures_are_bound_to_the_cookie_name() {
    let wire = signer().sign("session", PAYLOAD).unwrap();
    assert_eq!(signer().verify("admin", &wire).unwrap_err(), Error::BadMac);
}

#[test]
fn tampering_is_rejected() {
    let wire = signer().sign("session", PAYLOAD).unwrap();

    // Payload byte flipped: same length, valid cookie-octets.
    let tampered = wire.replace("dXNlcj00Mg", "dXNlcj00Mh");
    assert_eq!(
        signer().verify("session", &tampered).unwrap_err(),
        Error::BadMac
    );

    // MAC byte flipped.
    let mut tampered = wire.clone();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    assert_eq!(
        signer().verify("session", &tampered).unwrap_err(),
        Error::BadMac
    );

    // Key id swapped for another valid id.
    let tampered = wire.replace("os1.k1.", "os1.k2.");
    assert_eq!(
        signer().verify("session", &tampered).unwrap_err(),
        Error::UnknownKey
    );

    // Version swapped.
    let tampered = wire.replace("os1.", "os2.");
    assert_eq!(
        signer().verify("session", &tampered).unwrap_err(),
        Error::UnsupportedVersion
    );
}

#[test]
fn unsigned_values_are_never_accepted() {
    assert_eq!(
        signer().verify("session", PAYLOAD).unwrap_err(),
        Error::Malformed
    );
    assert_eq!(
        signer().verify("session", "session=abc").unwrap_err(),
        Error::Malformed
    );
    assert_eq!(
        signer().verify("session", "").unwrap_err(),
        Error::Malformed
    );
}

#[test]
fn rotation_keeps_old_cookies_valid() {
    let old_wire = signer().sign("session", "old").unwrap();

    let mut rotated = signer();
    rotated.rotate(key_id("k2"), secret(2)).unwrap();

    assert_eq!(rotated.key_id(), "k2");
    assert_eq!(rotated.verify("session", &old_wire).unwrap(), "old");

    let new_wire = rotated.sign("session", "new").unwrap();
    assert!(new_wire.starts_with("os1.k2."));
    assert_eq!(rotated.verify("session", &new_wire).unwrap(), "new");
}

#[test]
fn retired_keys_are_bounded() {
    let mut signer = signer();
    let with_k1 = CookieSigner::new(key_id("k1"), SecretKey::from_slice(&KEY).unwrap())
        .sign("session", "x")
        .unwrap();

    signer.rotate(key_id("k2"), secret(2)).unwrap();
    signer.rotate(key_id("k3"), secret(3)).unwrap();
    assert_eq!(signer.verify("session", &with_k1).unwrap(), "x");

    // A third rotation pushes k1 out of the ring: only one key id may be
    // unknown to verify anymore.
    signer.rotate(key_id("k4"), secret(4)).unwrap();
    assert_eq!(
        signer.verify("session", &with_k1).unwrap_err(),
        Error::UnknownKey
    );

    let too_many = CookieSigner::new(key_id("k1"), secret(1))
        .with_previous(key_id("k0"), secret(2))
        .unwrap()
        .with_previous(key_id("k9"), secret(3))
        .unwrap()
        .with_previous(key_id("k8"), secret(4));
    assert_eq!(too_many.unwrap_err(), Error::TooManyKeys);
}

#[test]
fn duplicate_ids_are_rejected_during_construction_and_rotation() {
    let duplicate =
        CookieSigner::new(key_id("k1"), secret(1)).with_previous(key_id("k1"), secret(2));
    assert_eq!(duplicate.unwrap_err(), Error::DuplicateKeyId);

    let mut signer = signer().with_previous(key_id("k0"), secret(0)).unwrap();
    assert_eq!(
        signer.rotate(key_id("k0"), secret(3)),
        Err(Error::DuplicateKeyId)
    );
    assert_eq!(
        signer.rotate(key_id("k1"), secret(3)),
        Err(Error::DuplicateKeyId)
    );
    assert_eq!(signer.key_id(), "k1");
}

#[test]
fn rejects_payloads_that_cannot_be_signed() {
    let signer = signer();
    assert_eq!(
        signer.sign("session", "").unwrap_err(),
        Error::PayloadNotEncodable
    );
    assert_eq!(
        signer.sign("session", "a.b").unwrap_err(),
        Error::PayloadNotEncodable
    );
    assert_eq!(
        signer.sign("session", "a b").unwrap_err(),
        Error::PayloadNotEncodable
    );
    assert_eq!(
        signer.sign("session", "a;b").unwrap_err(),
        Error::PayloadNotEncodable
    );
    assert_eq!(
        signer.sign("bad name", PAYLOAD).unwrap_err(),
        Error::InvalidCookieName
    );
}

#[test]
fn rejects_oversized_values() {
    let payload = "a".repeat(4096);
    assert_eq!(
        signer().sign("session", &payload).unwrap_err(),
        Error::TooLong
    );

    let wire = format!("os1.k1.{}.{}", "a".repeat(4200), "A".repeat(43));
    assert_eq!(
        signer().verify("session", &wire).unwrap_err(),
        Error::TooLong
    );
}

#[test]
fn unsigned_payload_is_readable_not_secret() {
    // Signing is authenticity only: the payload travels in clear. This test
    // exists so nobody mistakes it for encryption.
    let wire = signer().sign("session", PAYLOAD).unwrap();
    assert!(wire.contains(PAYLOAD));
}

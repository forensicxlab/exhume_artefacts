//! Exercise the reusable recovery boundary as an external library consumer.

use exhume_artefacts::formats::keychain::{KeychainError, LegacyKeychain};

#[test]
fn recovers_a_selected_value_without_platform_apis_or_parser_records() {
    let bytes = include_bytes!("../src/formats/keychain/fixtures/synthetic.keychain-db");
    let unlocked = LegacyKeychain::parse(bytes)
        .unwrap()
        .unlock_password(b"exhume synthetic fixture password", None)
        .unwrap();
    let recovered = unlocked
        .recover_generic_password(b"Exhume Keychain Fixture", b"fixture-alpha", None)
        .unwrap();
    assert_eq!(recovered.expose(), b"SYNTHETIC-ALPHA-SECRET");
    assert_eq!(recovered.record_offset(), 0x5598);
    assert_eq!(recovered.wrapping_key_record_offset(), 0x4b4c);
    assert_eq!(
        unlocked
            .recover_generic_password(b"Exhume Keychain Fixture", b"absent", None)
            .unwrap_err(),
        KeychainError::ItemNotFound
    );
}

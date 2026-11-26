use super::*;

const NATIVE: &[u8] = include_bytes!("fixtures/gnome-48-encrypted.keyring");

#[test]
fn decodes_gnomes_native_collection_and_selects_exact_decrypted_attributes() {
    let original = NATIVE.to_vec();
    let keyring = GnomeKeyring::parse(NATIVE).unwrap();
    assert_eq!(
        keyring.metadata().display_name.as_deref(),
        Some("unit-test-keyring")
    );
    assert_eq!(keyring.indexed_items().len(), 2);
    let unlocked = keyring
        .unlock_password(b"my-keyring-password", None)
        .unwrap();
    let items: Vec<_> = unlocked.items().collect();
    assert_eq!(items[0].created_at_unix_seconds, 1198027852);
    let secret = unlocked
        .recover_secret(&[("dog", "woof"), ("bird", "cheep")], None)
        .unwrap();
    assert_eq!(secret.expose(), b"item-secret");
    assert_eq!(secret.item_id(), 3);
    assert!(secret.index_offset() < keyring.metadata().encrypted_offset);
    assert!(secret.decrypted_offset() >= 16);
    assert!(!format!("{unlocked:?} {secret:?}").contains("item-secret"));
    assert!(matches!(
        unlocked.recover_secret(&[("dog", "WOOF")], None),
        Err(KeyringError::ItemNotFound)
    ));
    assert!(matches!(
        unlocked.recover_secret(&[], None),
        Err(KeyringError::InvalidSelector)
    ));
    assert!(matches!(
        unlocked.recover_secret(&[("dog", "woof"), ("dog", "woof")], None),
        Err(KeyringError::InvalidSelector)
    ));
    assert_eq!(NATIVE, original);
}

#[test]
fn rejects_wrong_passwords_damage_limits_truncation_and_cancellation() {
    let keyring = GnomeKeyring::parse(NATIVE).unwrap();
    assert!(matches!(
        keyring.unlock_password(b"wrong", None),
        Err(KeyringError::ChecksumFailed)
    ));
    let mut damaged = NATIVE.to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        GnomeKeyring::parse(&damaged)
            .unwrap()
            .unlock_password(b"my-keyring-password", None),
        Err(KeyringError::ChecksumFailed)
    ));
    for end in 0..NATIVE.len() {
        assert!(
            GnomeKeyring::parse(&NATIVE[..end]).is_err(),
            "accepted prefix {end}"
        );
    }
    let mut version = NATIVE.to_vec();
    version[16] = 1;
    assert!(matches!(
        GnomeKeyring::parse(&version),
        Err(KeyringError::UnsupportedProtection)
    ));
    let mut too_large = NATIVE.to_vec();
    too_large[20..24].copy_from_slice(&(2_000_000u32).to_be_bytes());
    assert!(matches!(
        GnomeKeyring::parse(&too_large),
        Err(KeyringError::LimitExceeded { .. })
    ));
    let mut trailing = NATIVE.to_vec();
    trailing.push(0);
    assert!(GnomeKeyring::parse(&trailing).is_err());
    assert!(matches!(
        keyring.unlock_password(b"my-keyring-password", Some(&AtomicBool::new(true))),
        Err(KeyringError::Cancelled)
    ));
}

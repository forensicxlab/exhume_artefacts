use super::fixtures::*;
use super::*;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicBool;

const SERVICE: &[u8] = b"Exhume Keychain Fixture";
const ALPHA: usize = 0x5598;
const BETA: usize = 0x569c;
const ALPHA_KEY: usize = 0x4b4c;
const BETA_KEY: usize = 0x4e88;
const DB_BLOB: usize = 0x5b14;

fn u32_at(bytes: &[u8], offset: usize) -> usize {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}
fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn unlock(bytes: &[u8]) -> UnlockedKeychain<'_> {
    LegacyKeychain::parse(bytes)
        .unwrap()
        .unlock_password(PASSWORD, None)
        .unwrap()
}

#[test]
fn recovers_native_security_cli_ground_truth_and_source_offsets() {
    assert_eq!(
        hex::encode(Sha256::digest(FIXTURE)),
        "ff504cabb9b81fbe19562ea453f679bc9d5bdf81f45c2441bdc6d4ca5d5685b6"
    );
    let file = LegacyKeychain::parse(FIXTURE).unwrap();
    let metadata = file.metadata();
    assert_eq!(metadata.file_version, 0x10000);
    assert_eq!(metadata.blob_version, Some(0x100));
    assert_eq!(metadata.database_blob_offset, Some(DB_BLOB));
    assert_eq!(metadata.generic_password_count, 2);
    assert_eq!(metadata.symmetric_key_count, 2);
    let selectors = file.generic_passwords().unwrap();
    assert_eq!(selectors.len(), 2);
    assert_eq!(selectors[0].service(), Some(SERVICE));
    assert_eq!(selectors[0].account(), Some(b"fixture-alpha".as_slice()));
    assert_eq!(selectors[1].record_number(), 1);
    let unlocked = file.unlock_password(PASSWORD, None).unwrap();
    for (account, secret, offset, key_offset) in [
        (
            b"fixture-alpha".as_slice(),
            b"SYNTHETIC-ALPHA-SECRET".as_slice(),
            ALPHA,
            ALPHA_KEY,
        ),
        (
            b"fixture-beta".as_slice(),
            b"SYNTHETIC-BETA-SECRET".as_slice(),
            BETA,
            BETA_KEY,
        ),
    ] {
        let recovered = unlocked
            .recover_generic_password(SERVICE, account, None)
            .unwrap();
        assert_eq!(recovered.expose(), secret);
        assert_eq!(recovered.record_offset(), offset);
        assert_eq!(recovered.wrapping_key_record_offset(), key_offset);
        assert!(!format!("{recovered:?}").contains(std::str::from_utf8(secret).unwrap()));
    }
    assert!(format!("{unlocked:?}").contains("[REDACTED]"));
    assert!(!format!("{unlocked:?}").contains(std::str::from_utf8(PASSWORD).unwrap()));
}

#[test]
fn recovers_native_partition_version_ground_truth() {
    let bytes = include_bytes!("fixtures/synthetic-partition.keychain-db");
    assert_eq!(
        hex::encode(Sha256::digest(bytes)),
        "e06fb192d0a15de49724a13fc3d6aefc424ea192c1194596579da132be55dc60"
    );
    let file = LegacyKeychain::parse(bytes).unwrap();
    assert_eq!(file.metadata().blob_version, Some(0x200));
    let candidate = file
        .unlock_password(PASSWORD, None)
        .unwrap()
        .recover_generic_password(b"Exhume Partition Fixture", b"fixture-partition", None)
        .unwrap();
    assert_eq!(candidate.expose(), b"SYNTHETIC-PARTITION-SECRET");
}

#[test]
fn authenticates_the_independent_indirect_password_vector() {
    let bytes = indirect_fixture();
    let file = LegacyKeychain::parse(&bytes).unwrap();
    let identifier = file.protected_entropy_identifier().unwrap();
    assert_eq!(identifier.len(), 40);
    assert!(identifier.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(file.metadata().blob_version, Some(0x200));
    assert_eq!(
        file.unlock_password(LOGIN_PASSWORD, None).unwrap_err(),
        KeychainError::AuthenticationFailed
    );
    let unlocked = LegacyKeychain::parse(&bytes)
        .unwrap()
        .unlock_login_password(LOGIN_PASSWORD, &PROTECTED_ENTROPY, None)
        .unwrap();
    assert_eq!(
        unlocked
            .recover_generic_password(b"Exhume Partition Fixture", b"fixture-partition", None)
            .unwrap()
            .expose(),
        b"SYNTHETIC-PARTITION-SECRET"
    );
    let storage = unlocked
        .recover_generic_password(b"Exhume Partition Fixture", b"fixture-partition", None)
        .unwrap();
    let candidate = crate::formats::os_crypt::decrypt_macos_v10(
        &hex::decode(SIGNAL_KEY_ENVELOPE).unwrap(),
        storage.expose(),
        None,
    )
    .unwrap();
    assert_eq!(
        candidate.expose(),
        b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    );
    for (password, entropy) in [
        (b"wrong".as_slice(), PROTECTED_ENTROPY),
        (LOGIN_PASSWORD, [0; 32]),
    ] {
        assert_eq!(
            LegacyKeychain::parse(&bytes)
                .unwrap()
                .unlock_login_password(password, &entropy, None)
                .unwrap_err(),
            KeychainError::AuthenticationFailed
        );
    }
    assert_eq!(
        LegacyKeychain::parse(&bytes)
            .unwrap()
            .unlock_login_password(
                LOGIN_PASSWORD,
                &PROTECTED_ENTROPY,
                Some(&AtomicBool::new(true))
            )
            .unwrap_err(),
        KeychainError::Cancelled
    );
}

#[test]
fn refuses_wrong_passwords_and_does_not_trim_or_normalize() {
    for password in [
        b"wrong".as_slice(),
        b"exhume synthetic fixture password\n",
        b"",
        b"\xff",
    ] {
        let error = LegacyKeychain::parse(FIXTURE)
            .unwrap()
            .unlock_password(password, None)
            .unwrap_err();
        assert_eq!(error, KeychainError::AuthenticationFailed);
        assert!(!error.to_string().contains("synthetic fixture"));
    }
}

#[test]
fn authenticates_entire_database_blob_and_wrapping_key_blob() {
    // Public ACL, signature, IV and ciphertext all participate in authentication.
    for relative in [64, 72, 92, 120] {
        let mut bytes = FIXTURE.to_vec();
        bytes[DB_BLOB + relative] ^= 1;
        assert_eq!(
            LegacyKeychain::parse(&bytes)
                .unwrap()
                .unlock_password(PASSWORD, None)
                .unwrap_err(),
            KeychainError::AuthenticationFailed
        );
    }
    for relative in [16, 116, 136, 444] {
        let mut bytes = FIXTURE.to_vec();
        bytes[ALPHA_KEY + 132 + relative] ^= 1;
        let error = unlock(&bytes)
            .recover_generic_password(SERVICE, b"fixture-alpha", None)
            .unwrap_err();
        assert_eq!(error, KeychainError::AuthenticationFailed);
    }
}

#[test]
fn exposes_the_unauthenticated_payload_limitation() {
    // Alter an IV bit without affecting padding. Database/key MACs remain valid;
    // application-level verification must reject this changed candidate value.
    let mut bytes = FIXTURE.to_vec();
    bytes[ALPHA + 88 + 20] ^= 1;
    let candidate = unlock(&bytes)
        .recover_generic_password(SERVICE, b"fixture-alpha", None)
        .unwrap();
    assert_ne!(candidate.expose(), b"SYNTHETIC-ALPHA-SECRET");
    assert_eq!(candidate.expose().len(), b"SYNTHETIC-ALPHA-SECRET".len());
}

#[test]
fn selects_exactly_and_distinguishes_missing_and_ambiguous_items_and_keys() {
    let unlocked = unlock(FIXTURE);
    for (service, account) in [
        (SERVICE, b"fixture-alpha ".as_slice()),
        (b"exhume keychain fixture".as_slice(), b"fixture-alpha"),
    ] {
        assert_eq!(
            unlocked
                .recover_generic_password(service, account, None)
                .unwrap_err(),
            KeychainError::ItemNotFound
        );
    }
    let mut missing = FIXTURE.to_vec();
    missing[ALPHA + 88 + 4] ^= 1;
    assert_eq!(
        unlock(&missing)
            .recover_generic_password(SERVICE, b"fixture-alpha", None)
            .unwrap_err(),
        KeychainError::MissingWrappingKey
    );

    let mut duplicate = FIXTURE.to_vec();
    let label_a = ALPHA_KEY + (u32_at(&duplicate, ALPHA_KEY + 48) & !1) + 4;
    let label_b = BETA_KEY + (u32_at(&duplicate, BETA_KEY + 48) & !1) + 4;
    let label = duplicate[label_a..label_a + 20].to_vec();
    duplicate[label_b..label_b + 20].copy_from_slice(&label);
    assert_eq!(
        unlock(&duplicate)
            .recover_generic_password(SERVICE, b"fixture-alpha", None)
            .unwrap_err(),
        KeychainError::AmbiguousWrappingKey
    );

    let mut duplicate = FIXTURE.to_vec();
    for record in [ALPHA, BETA] {
        let account = record + (u32_at(&duplicate, record + 76) & !1);
        put(&mut duplicate, account, 12);
        duplicate[account + 4..account + 16].copy_from_slice(b"same-account");
    }
    assert_eq!(
        unlock(&duplicate)
            .recover_generic_password(SERVICE, b"same-account", None)
            .unwrap_err(),
        KeychainError::AmbiguousItem
    );
}

#[test]
fn rejects_every_truncated_prefix_and_unbounded_counts_or_offsets() {
    for length in 0..FIXTURE.len() {
        assert!(
            LegacyKeychain::parse(&FIXTURE[..length]).is_err(),
            "prefix {length}"
        );
    }
    for offset in [
        12,
        24,
        28,
        0x5574 + 8,
        0x5574 + 24,
        0x5574 + 28,
        ALPHA,
        DB_BLOB + 12,
    ] {
        let mut bytes = FIXTURE.to_vec();
        put(&mut bytes, offset, u32::MAX);
        assert!(LegacyKeychain::parse(&bytes).is_err(), "field {offset:#x}");
    }
    let mut bytes = FIXTURE.to_vec();
    put(&mut bytes, ALPHA + 76, u32::MAX);
    assert!(
        LegacyKeychain::parse(&bytes)
            .unwrap()
            .generic_passwords()
            .is_err()
    );
    // A length spanning the next record must not be accepted as an attribute.
    let mut bytes = FIXTURE.to_vec();
    let account = ALPHA + (u32_at(&bytes, ALPHA + 76) & !1);
    put(&mut bytes, account, 1024);
    assert!(
        LegacyKeychain::parse(&bytes)
            .unwrap()
            .generic_passwords()
            .is_err()
    );
}

#[test]
fn respects_limits_cancellation_and_unsupported_formats() {
    let cancelled = AtomicBool::new(true);
    assert_eq!(
        LegacyKeychain::parse(FIXTURE)
            .unwrap()
            .unlock_password(PASSWORD, Some(&cancelled))
            .unwrap_err(),
        KeychainError::Cancelled
    );
    assert_eq!(
        unlock(FIXTURE)
            .recover_generic_password(SERVICE, b"fixture-alpha", Some(&cancelled))
            .unwrap_err(),
        KeychainError::Cancelled
    );
    assert!(matches!(
        LegacyKeychain::parse(&vec![0; MAX_INPUT_BYTES + 1]),
        Err(KeychainError::LimitExceeded { .. })
    ));
    assert!(matches!(
        LegacyKeychain::parse(FIXTURE)
            .unwrap()
            .unlock_password(&vec![0; MAX_PASSWORD_BYTES + 1], None),
        Err(KeychainError::LimitExceeded { .. })
    ));
    assert!(matches!(
        LegacyKeychain::parse(b"SQLite format 3\0"),
        Err(KeychainError::UnsupportedFormat)
    ));
    let mut bytes = FIXTURE.to_vec();
    put(&mut bytes, DB_BLOB + 4, 0x999);
    let file = LegacyKeychain::parse(&bytes).unwrap();
    assert_eq!(file.metadata().blob_version, Some(0x999));
    assert!(matches!(
        file.unlock_password(PASSWORD, None),
        Err(KeychainError::UnsupportedVersion { .. })
    ));
}

#[test]
fn supports_standard_hmac_variants_without_accepting_the_legacy_mac() {
    // Convert the known synthetic fixture's authenticated blobs to the versions
    // using standard HMAC-SHA1. These are constructed variants, not native captures.
    let s = Section {
        bytes: &FIXTURE[DB_BLOB..DB_BLOB + 168],
        offset: DB_BLOB,
    };
    let blob = crypto::Blob::parse(s, 92).unwrap();
    let mut master = zeroize::Zeroizing::new([0; 24]);
    pbkdf2::pbkdf2_hmac::<Sha1>(PASSWORD, &s.bytes[44..64], 1000, master.as_mut());
    let private = crypto::decrypt(&master, &s.bytes[64..72], blob.ciphertext()).unwrap();
    for version in [0x101, 0x200] {
        let mut bytes = FIXTURE.to_vec();
        for (start, header) in [(DB_BLOB, 92), (ALPHA_KEY + 132, 136), (BETA_KEY + 132, 136)] {
            put(&mut bytes, start + 4, version);
            let total = u32_at(&bytes, start + 12);
            let mut mac = Hmac::<Sha1>::new_from_slice(&private[24..44]).unwrap();
            mac.update(&bytes[start..start + header - 20]);
            mac.update(&bytes[start + header..start + total]);
            bytes[start + header - 20..start + header]
                .copy_from_slice(&mac.finalize().into_bytes());
        }
        assert_eq!(
            unlock(&bytes)
                .recover_generic_password(SERVICE, b"fixture-alpha", None)
                .unwrap()
                .expose(),
            b"SYNTHETIC-ALPHA-SECRET"
        );
        put(&mut bytes, DB_BLOB + 4, 0x100);
        assert_eq!(
            LegacyKeychain::parse(&bytes)
                .unwrap()
                .unlock_password(PASSWORD, None)
                .unwrap_err(),
            KeychainError::AuthenticationFailed
        );
    }
}

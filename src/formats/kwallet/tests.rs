use super::*;
use std::sync::atomic::AtomicBool;

const WALLET: &[u8] = include_bytes!("fixtures/synthetic-signal.kwl");
const EMPTY: &[u8] = include_bytes!("fixtures/synthetic-empty.kwl");
const SALT: &[u8] = include_bytes!("fixtures/synthetic-signal.salt");
const PASSWORD: &[u8] = b"SYNTHETIC-GNOME-PASSWORD\n";
const STORAGE: &[u8] = b"SYNTHETIC+Safe/Storage==\n";

#[test]
fn repeated_folder_names_cannot_amplify_metadata_without_a_bound() -> Result<()> {
    use cbc::cipher::BlockEncryptMut;
    fn text(value: &str, output: &mut Vec<u8>) {
        let bytes: Vec<u8> = value.encode_utf16().flat_map(u16::to_be_bytes).collect();
        output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        output.extend(bytes);
    }
    let folder = "f".repeat(64 * 1024);
    let mut file = b"KWALLET\n\r\0\r\n\0\x01\x03\x02".to_vec();
    file.extend_from_slice(&1u32.to_be_bytes());
    file.extend_from_slice(&md5::compute(folder.as_bytes()).0);
    file.extend_from_slice(&257u32.to_be_bytes());
    let mut payload = Vec::new();
    text(&folder, &mut payload);
    payload.extend_from_slice(&257u32.to_be_bytes());
    for index in 0..257 {
        let name = format!("name{index}");
        file.extend_from_slice(&md5::compute(name.as_bytes()).0);
        text(&name, &mut payload);
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
    }
    let mut framed = vec![0u8; 8];
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(&payload);
    framed.extend(vec![0; 8 - (payload.len() + 32) % 8]);
    framed.extend_from_slice(&checksum::little_endian(&payload, None)?);
    let mut key = Zeroizing::new([0u8; 56]);
    pbkdf2::pbkdf2_hmac::<Sha512>(PASSWORD, SALT, ITERATIONS, key.as_mut());
    let length = framed.len();
    cbc::Encryptor::<Blowfish>::new_from_slices(key.as_slice(), &[0; 8])
        .unwrap()
        .encrypt_padded_mut::<NoPadding>(&mut framed, length)
        .unwrap();
    file.extend(framed);
    assert!(matches!(
        KWallet::parse(&file)?.unlock_password(PASSWORD, SALT, None),
        Err(WalletError::LimitExceeded {
            field: "entry metadata bytes"
        })
    ));
    Ok(())
}

#[test]
fn checksum_matches_upstream_kde_at_block_and_padding_boundaries() -> Result<()> {
    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/checksum-vectors.json")).unwrap();
    for vector in vectors {
        let length = vector["length"].as_u64().unwrap() as usize;
        let data: Vec<u8> = (0..length).map(|i| (i % 256) as u8).collect();
        assert_eq!(
            hex::encode(checksum::little_endian(&data, None)?),
            vector["checksum"].as_str().unwrap(),
            "length {length}"
        );
    }
    Ok(())
}

#[test]
fn independent_vector_decodes_nested_password_and_preserves_metadata() -> Result<()> {
    let wallet = KWallet::parse(WALLET)?;
    assert_eq!(wallet.indexed_folders().len(), 3);
    assert_eq!(wallet.indexed_folders()[0].index_offset, 20);
    assert_eq!(wallet.metadata().iterations, 50_000);
    let unlocked = wallet.unlock_password(PASSWORD, SALT, None)?;
    let entries: Vec<_> = unlocked.entries().collect();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].folder, "Chromium Keys");
    assert_eq!(entries[0].name, "Chromium Safe Storage");
    assert_eq!(entries[0].entry_type, 1);
    assert_eq!(entries[0].index_offset, 40);
    assert_eq!(entries[0].decrypted_offset, 34);
    assert_eq!(entries[2].folder, "Unicode 🗝️");
    assert_eq!(entries[2].name, "Non-ASCII é");
    let recovered = unlocked.recover_password("Chromium Keys", "Chromium Safe Storage", None)?;
    assert_eq!(recovered.expose(), STORAGE);
    assert_eq!(recovered.metadata().index_offset, 40);
    assert_eq!(
        unlocked
            .recover_password("Unicode 🗝️", "Non-ASCII é", None)?
            .expose(),
        b"SYNTHETIC-UNICODE-SECRET\n"
    );
    let debug = format!("{unlocked:?} {recovered:?}");
    assert!(!debug.contains("SYNTHETIC"));
    assert!(
        !serde_json::to_string(&entries)
            .unwrap()
            .contains("SYNTHETIC")
    );
    Ok(())
}

#[test]
fn empty_wallets_and_exact_selection_have_explicit_results() -> Result<()> {
    let empty = KWallet::parse(EMPTY)?.unlock_password(PASSWORD, SALT, None)?;
    assert_eq!(empty.entries().count(), 0);
    assert!(matches!(
        empty.recover_password("Chromium Keys", "Chromium Safe Storage", None),
        Err(WalletError::EntryNotFound)
    ));
    let wallet = KWallet::parse(WALLET)?.unlock_password(PASSWORD, SALT, None)?;
    assert!(matches!(
        wallet.recover_password("chromium keys", "Chromium Safe Storage", None),
        Err(WalletError::EntryNotFound)
    ));
    assert!(matches!(
        wallet.recover_password("Chromium Keys", "An unrelated stream", None),
        Err(WalletError::UnsupportedEntryType)
    ));
    Ok(())
}

#[test]
fn wrong_credentials_and_damage_never_expose_partial_secrets() -> Result<()> {
    let wallet = KWallet::parse(WALLET)?;
    assert!(matches!(
        wallet.unlock_password(b"wrong", SALT, None),
        Err(WalletError::ChecksumFailed)
    ));
    assert!(matches!(
        wallet.unlock_password(PASSWORD.strip_suffix(b"\n").unwrap(), SALT, None),
        Err(WalletError::ChecksumFailed)
    ));
    assert!(matches!(
        wallet.unlock_password(PASSWORD, &[0; 56], None),
        Err(WalletError::ChecksumFailed)
    ));
    assert!(matches!(
        wallet.unlock_password(PASSWORD, &SALT[..55], None),
        Err(WalletError::InvalidSalt)
    ));
    let mut damaged = WALLET.to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        KWallet::parse(&damaged)?.unlock_password(PASSWORD, SALT, None),
        Err(WalletError::ChecksumFailed)
    ));
    let mut index = WALLET.to_vec();
    index[20] ^= 1; // Outside the encrypted checksum; must be checked separately.
    assert!(matches!(
        KWallet::parse(&index)?.unlock_password(PASSWORD, SALT, None),
        Err(WalletError::IndexMismatch)
    ));
    Ok(())
}

#[test]
fn rejects_unsupported_protection_and_bounded_untrusted_lengths() {
    assert_eq!(Reader::new(&[0xff; 4]).i32("entry type").unwrap(), -1);
    for header in [[0, 0, 0, 0], [0, 1, 2, 0], [0, 1, 3, 1], [1, 1, 3, 2]] {
        let mut bytes = WALLET.to_vec();
        bytes[12..16].copy_from_slice(&header);
        assert!(matches!(
            KWallet::parse(&bytes),
            Err(WalletError::UnsupportedProtection)
        ));
    }
    for length in 0..40 {
        assert!(KWallet::parse(&WALLET[..length]).is_err());
    }
    let mut oversized = WALLET.to_vec();
    oversized[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        KWallet::parse(&oversized),
        Err(WalletError::LimitExceeded { .. })
    ));
    oversized[16..20].copy_from_slice(&1u32.to_be_bytes());
    oversized[36..40].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        KWallet::parse(&oversized),
        Err(WalletError::LimitExceeded { .. })
    ));
    let mut reader = Reader::new(&[0xff, 0xff, 0xff, 0xfe]);
    assert!(matches!(
        reader.text("test"),
        Err(WalletError::LimitExceeded { .. })
    ));
    for bytes in [&[0, 0, 0, 1, 0][..], &[0, 0, 0, 2, 0xd8, 0][..]] {
        assert!(matches!(
            Reader::new(bytes).secret_text("test"),
            Err(WalletError::Malformed { .. })
        ));
    }
}

#[test]
fn cancellation_is_observed_before_kdf_and_secret_selection() -> Result<()> {
    let cancel = AtomicBool::new(true);
    let wallet = KWallet::parse(WALLET)?;
    assert!(matches!(
        wallet.unlock_password(PASSWORD, SALT, Some(&cancel)),
        Err(WalletError::Cancelled)
    ));
    let unlocked = wallet.unlock_password(PASSWORD, SALT, None)?;
    assert!(matches!(
        unlocked.recover_password("Chromium Keys", "Chromium Safe Storage", Some(&cancel)),
        Err(WalletError::Cancelled)
    ));
    Ok(())
}

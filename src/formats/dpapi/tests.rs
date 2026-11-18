use super::{fixtures::*, *};
use std::sync::atomic::AtomicBool;

#[test]
fn independent_vectors_recover_exact_payload_and_metadata() {
    let data = hex::decode(MASTER_FILE).unwrap();
    let file = MasterKeyFile::parse(&data).unwrap();
    assert_eq!(file.metadata().guid, GUID);
    assert_eq!(file.metadata().version, 2);
    assert_eq!(file.metadata().primary.as_ref().unwrap().rounds, 4);
    let key = file.unlock_local_password(SID, PASSWORD, None).unwrap();
    assert_eq!(key.guid(), GUID);
    for vector in [BLOB, BLOB_LEGACY_SIGNATURE] {
        let data = hex::decode(vector).unwrap();
        let blob = Blob::parse(&data).unwrap();
        assert_eq!(blob.metadata().description, "Synthetic");
        assert_eq!(blob.metadata().master_key_guid, GUID);
        assert_eq!(
            blob.decrypt(&key, None, None).unwrap().as_slice(),
            b"synthetic authenticated payload"
        );
    }
    let data = hex::decode(BLOB_ENTROPY).unwrap();
    let blob = Blob::parse(&data).unwrap();
    assert_eq!(
        blob.decrypt(&key, Some(b"context"), None)
            .unwrap()
            .as_slice(),
        b"synthetic authenticated payload"
    );
    assert_eq!(
        blob.decrypt(&key, None, None).unwrap_err(),
        DpapiError::AuthenticationFailed
    );
    assert_eq!(
        blob.decrypt(&key, Some(b"other"), None).unwrap_err(),
        DpapiError::AuthenticationFailed
    );
}

#[test]
fn wrong_credentials_and_damage_preserve_authentication_uncertainty() {
    let data = hex::decode(MASTER_FILE).unwrap();
    let file = MasterKeyFile::parse(&data).unwrap();
    for password in ["wrong", "fixture password ☃\n", "fixture password ☃ "] {
        let error = file.unlock_local_password(SID, password, None).unwrap_err();
        assert_eq!(error, DpapiError::AuthenticationFailed);
        assert!(!error.to_string().contains(password));
    }
    assert_eq!(
        file.unlock_local_password("S-1-5-21-123-456-789-1002", PASSWORD, None)
            .unwrap_err(),
        DpapiError::AuthenticationFailed
    );
    let key = file.unlock_local_password(SID, PASSWORD, None).unwrap();
    let mut blob = hex::decode(BLOB).unwrap();
    blob[40] ^= 1;
    assert_eq!(
        Blob::parse(&blob)
            .unwrap()
            .decrypt(&key, None, None)
            .unwrap_err(),
        DpapiError::AuthenticationFailed
    );
    let mut damaged = data;
    damaged[170] ^= 1;
    assert_eq!(
        MasterKeyFile::parse(&damaged)
            .unwrap()
            .unlock_local_password(SID, PASSWORD, None)
            .unwrap_err(),
        DpapiError::AuthenticationFailed
    );
}

#[test]
fn rejects_every_truncated_prefix_and_trailing_bytes() {
    let master = hex::decode(MASTER_FILE).unwrap();
    for length in 0..master.len() {
        assert!(
            MasterKeyFile::parse(&master[..length]).is_err(),
            "master-key prefix {length}"
        );
    }
    let blob = hex::decode(BLOB).unwrap();
    for length in 0..blob.len() {
        assert!(
            Blob::parse(&blob[..length]).is_err(),
            "blob prefix {length}"
        );
    }
    let mut trailing = master;
    trailing.push(0);
    assert!(matches!(
        MasterKeyFile::parse(&trailing),
        Err(DpapiError::Malformed { .. })
    ));
    let mut trailing = blob;
    trailing.push(0);
    assert!(matches!(
        Blob::parse(&trailing),
        Err(DpapiError::Malformed { .. })
    ));
}

#[test]
fn bounds_lengths_rounds_and_passwords_before_expensive_work() {
    let mut data = hex::decode(MASTER_FILE).unwrap();
    data[96..104].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(MasterKeyFile::parse(&data).is_err());
    let mut data = hex::decode(MASTER_FILE).unwrap();
    data[148..152].copy_from_slice(&(MAX_KDF_ROUNDS + 1).to_le_bytes());
    let file = MasterKeyFile::parse(&data).unwrap();
    assert_eq!(
        file.unlock_local_password(SID, PASSWORD, None).unwrap_err(),
        DpapiError::LimitExceeded {
            field: "derivation rounds"
        }
    );
    data[148..152].copy_from_slice(&0_u32.to_le_bytes());
    assert_eq!(
        MasterKeyFile::parse(&data)
            .unwrap()
            .unlock_local_password(SID, PASSWORD, None)
            .unwrap_err(),
        DpapiError::Malformed {
            field: "zero protection rounds"
        }
    );
    let data = hex::decode(MASTER_FILE).unwrap();
    let file = MasterKeyFile::parse(&data).unwrap();
    assert!(matches!(
        file.unlock_local_password(SID, &"x".repeat(16 * 1024 + 1), None),
        Err(DpapiError::LimitExceeded { .. })
    ));
    let oversized = vec![0; MAX_INPUT_BYTES + 1];
    assert!(matches!(
        MasterKeyFile::parse(&oversized),
        Err(DpapiError::LimitExceeded { .. })
    ));
    assert!(matches!(
        Blob::parse(&oversized),
        Err(DpapiError::LimitExceeded { .. })
    ));
}

#[test]
fn unsupported_algorithms_are_inspectable_and_not_password_rejections() {
    let mut data = hex::decode(MASTER_FILE).unwrap();
    data[152..156].copy_from_slice(&0x8004_u32.to_le_bytes());
    let file = MasterKeyFile::parse(&data).unwrap();
    assert_eq!(
        file.metadata().primary.as_ref().unwrap().hash_algorithm,
        0x8004
    );
    assert!(matches!(
        file.unlock_local_password(SID, PASSWORD, None),
        Err(DpapiError::UnsupportedAlgorithms { .. })
    ));
}

#[test]
fn cancellation_and_key_identity_are_explicit() {
    let data = hex::decode(MASTER_FILE).unwrap();
    let file = MasterKeyFile::parse(&data).unwrap();
    let cancelled = AtomicBool::new(true);
    assert_eq!(
        file.unlock_local_password(SID, PASSWORD, Some(&cancelled))
            .unwrap_err(),
        DpapiError::Cancelled
    );
    let key = file.unlock_local_password(SID, PASSWORD, None).unwrap();
    let data = hex::decode(BLOB).unwrap();
    let blob = Blob::parse(&data).unwrap();
    assert_eq!(
        blob.decrypt(&key, None, Some(&cancelled)).unwrap_err(),
        DpapiError::Cancelled
    );
    let other = MasterKey::from_bytes("ffffffff-ffff-ffff-ffff-ffffffffffff", [0; 64]).unwrap();
    assert_eq!(
        blob.decrypt(&other, None, None).unwrap_err(),
        DpapiError::WrongMasterKey
    );
    let wrong = MasterKey::from_bytes(GUID, [0; 64]).unwrap();
    assert_eq!(
        blob.decrypt(&wrong, None, None).unwrap_err(),
        DpapiError::AuthenticationFailed
    );
}

#[test]
fn validates_account_identity_and_redacts_secret_debug() {
    let data = hex::decode(MASTER_FILE).unwrap();
    let file = MasterKeyFile::parse(&data).unwrap();
    for sid in [
        "",
        "S-2-5-21",
        "S-1-5-",
        "S-1-5--1",
        "S-1-5-4294967296",
        "S-1-+5-1",
    ] {
        assert_eq!(
            file.unlock_local_password(sid, PASSWORD, None).unwrap_err(),
            DpapiError::InvalidSid
        );
    }
    let key = file.unlock_local_password(SID, PASSWORD, None).unwrap();
    let debug = format!("{key:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(PASSWORD));
    assert!(!debug.contains(&hex::encode(key.bytes.as_slice())));
}

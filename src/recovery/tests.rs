use super::signal::*;
use crate::formats::{dpapi::MasterKeyFile, keychain::LegacyKeychain};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/signal-keys.json")).unwrap()
}

#[test]
fn independent_windows_vectors_resolve_guid_and_authenticate_both_envelopes() {
    let fixture = vectors();
    let bytes = hex::decode(fixture["master_key_file"].as_str().unwrap()).unwrap();
    let master = MasterKeyFile::parse(&bytes)
        .unwrap()
        .unlock_local_password(
            fixture["windows_sid"].as_str().unwrap(),
            fixture["windows_password"].as_str().unwrap(),
            None,
        )
        .unwrap();
    let local = serde_json::to_vec(&fixture["windows_local_state"]).unwrap();
    for field in ["windows_config", "windows_direct_config"] {
        let config =
            SignalKeyEnvelope::parse(&serde_json::to_vec(&fixture[field]).unwrap()).unwrap();
        assert_eq!(
            config.windows_master_key_guid(Some(&local)).unwrap(),
            fixture["master_key_guid"]
        );
        let recovered = config.recover_windows(Some(&local), &master, None).unwrap();
        assert_eq!(
            recovered.expose(),
            fixture["database_key"].as_str().unwrap().as_bytes()
        );
        assert!(!format!("{config:?}").contains(fixture["database_key"].as_str().unwrap()));
    }
}

#[test]
fn macos_candidate_uses_the_exact_recovered_safe_storage_value() {
    let fixture = vectors();
    let keychain = LegacyKeychain::parse(include_bytes!("fixtures/signal-macos.keychain-db"))
        .unwrap()
        .unlock_password(fixture["macos_password"].as_str().unwrap().as_bytes(), None)
        .unwrap();
    let storage = keychain
        .recover_generic_password(b"Signal Safe Storage", b"Signal Key", None)
        .unwrap();
    let config =
        SignalKeyEnvelope::parse(&serde_json::to_vec(&fixture["macos_config"]).unwrap()).unwrap();
    assert_eq!(
        config
            .recover_macos(storage.expose(), None)
            .unwrap()
            .expose(),
        fixture["database_key"].as_str().unwrap().as_bytes()
    );
}

#[test]
fn protected_fields_never_fall_back_and_diagnostics_do_not_echo_values() {
    let key = vectors()["database_key"].as_str().unwrap().to_owned();
    for value in [
        serde_json::json!({"encryptedKey": null, "key": key}),
        serde_json::json!({"encryptedKey": "invalid-secret", "key": key}),
        serde_json::json!({"encryptedKey": [], "key": key}),
    ] {
        let error = SignalKeyEnvelope::parse(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert!(!format!("{error:?} {error}").contains(&key));
        assert!(!error.to_string().contains("invalid-secret"));
    }
    let protected = SignalKeyEnvelope::parse(
        &serde_json::to_vec(&serde_json::json!({"encryptedKey": "763230", "key": key})).unwrap(),
    )
    .unwrap();
    assert_eq!(protected.kind(), EnvelopeKind::Unsupported);
    assert!(protected.plaintext_key().is_none());
    let plaintext =
        SignalKeyEnvelope::parse(&serde_json::to_vec(&serde_json::json!({"key": key})).unwrap())
            .unwrap();
    assert_eq!(plaintext.plaintext_key().unwrap().expose(), key.as_bytes());
    assert!(SignalKeyEnvelope::parse(&vec![0; MAX_CONFIG_BYTES + 1]).is_err());
    assert!(
        SignalKeyEnvelope::parse(format!(r#"{{"key":"{key}","key":"{key}"}}"#).as_bytes()).is_err()
    );
}

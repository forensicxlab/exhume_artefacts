//! GNOME Keyring → Linux OS Crypt → SQLCipher → shared Signal parser.

#![cfg(feature = "sqlcipher")]

use anyhow::Result;
use exhume_artefacts::{
    ObjectParsed, ParserInput, ParserOptions,
    formats::gnome_keyring::{GnomeKeyring, KeyringError},
    parsers::build_registry,
    recovery::signal::SignalKeyEnvelope,
    run_parser_by_name_with_options,
};
use serde_json::Value;

fn values() -> Value {
    serde_json::from_str(include_str!("../src/recovery/fixtures/signal-linux.json")).unwrap()
}

fn parse(bytes: Vec<u8>, options: ParserOptions) -> Result<Vec<ObjectParsed>> {
    let mut records = Vec::new();
    run_parser_by_name_with_options(
        &build_registry(),
        "desktop_signal",
        ParserInput::Bytes(bytes),
        options,
        &mut |record| {
            records.push(record);
            Ok(())
        },
        &mut |_| anyhow::bail!("unexpected parser diagnostic"),
    )?;
    Ok(records)
}
fn content(records: &[ObjectParsed]) -> Vec<Value> {
    records
        .iter()
        .map(|record| {
            let mut json = record.json.clone();
            json.as_object_mut().unwrap().remove("source");
            json
        })
        .collect()
}

#[test]
fn recovered_linux_keys_parse_like_the_plaintext_copy() -> Result<()> {
    let values = values();
    let bytes = include_bytes!("../src/formats/gnome_keyring/fixtures/synthetic-signal.keyring");
    let keyring = GnomeKeyring::parse(bytes)?
        .unlock_password(values["password"].as_str().unwrap().as_bytes(), None)?;
    let storage = keyring.recover_secret(&[("application", "signal")], None)?;
    assert_eq!(
        storage.expose(),
        values["safe_storage"].as_str().unwrap().as_bytes()
    );
    let encrypted = include_bytes!("../src/recovery/fixtures/signal-linux-encrypted.sqlite");
    let expected = parse(
        include_bytes!("../src/recovery/fixtures/signal-linux-plaintext.sqlite").to_vec(),
        ParserOptions::default(),
    )?;
    for field in ["legacy_config", "v10_config", "v11_config"] {
        let config = SignalKeyEnvelope::parse(&serde_json::to_vec(&values[field])?)?;
        let candidate = match config.plaintext_key() {
            Some(key) => key,
            None => config.recover_linux(Some(storage.expose()), None)?,
        };
        assert_eq!(
            candidate.expose(),
            values["database_key"].as_str().unwrap().as_bytes()
        );
        let mut options = ParserOptions::default();
        options.insert_secret("database_key", candidate)?;
        let actual = parse(encrypted.to_vec(), options)?;
        assert_eq!(
            actual
                .iter()
                .filter(|record| record.kind == "mobile.communication.message")
                .count(),
            17
        );
        assert_eq!(content(&actual), content(&expected));
    }
    Ok(())
}

#[test]
fn ambiguous_stores_and_failed_envelopes_never_select_a_fallback_key() -> Result<()> {
    let values = values();
    let bytes = include_bytes!("../src/formats/gnome_keyring/fixtures/synthetic-ambiguous.keyring");
    let keyring = GnomeKeyring::parse(bytes)?
        .unlock_password(values["password"].as_str().unwrap().as_bytes(), None)?;
    assert!(matches!(
        keyring.recover_secret(&[("application", "signal")], None),
        Err(KeyringError::AmbiguousItem)
    ));
    let mut config = values["v11_config"].clone();
    config["key"] = values["database_key"].clone();
    let envelope = SignalKeyEnvelope::parse(&serde_json::to_vec(&config)?)?;
    assert!(envelope.plaintext_key().is_none());
    assert!(envelope.recover_linux(None, None).is_err());
    assert!(envelope.recover_linux(Some(b"incorrect"), None).is_err());
    Ok(())
}

#[test]
fn kwallet_recovery_parses_the_same_records_as_the_plaintext_database() -> Result<()> {
    use exhume_artefacts::formats::kwallet::KWallet;
    let values = values();
    let wallet = KWallet::parse(include_bytes!(
        "../src/formats/kwallet/fixtures/synthetic-signal.kwl"
    ))?
    .unlock_password(
        values["password"].as_str().unwrap().as_bytes(),
        include_bytes!("../src/formats/kwallet/fixtures/synthetic-signal.salt"),
        None,
    )?;
    let storage = wallet.recover_password("Chromium Keys", "Chromium Safe Storage", None)?;
    assert_eq!(
        storage.expose(),
        values["safe_storage"].as_str().unwrap().as_bytes()
    );
    let mut config_value = values["v11_config"].clone();
    config_value["safeStorageBackend"] = "kwallet6".into();
    let envelope = SignalKeyEnvelope::parse(&serde_json::to_vec(&config_value)?)?;
    let candidate = envelope.recover_linux(Some(storage.expose()), None)?;
    let mut options = ParserOptions::default();
    options.insert_secret("database_key", candidate)?;
    let actual = parse(
        include_bytes!("../src/recovery/fixtures/signal-linux-encrypted.sqlite").to_vec(),
        options,
    )?;
    let expected = parse(
        include_bytes!("../src/recovery/fixtures/signal-linux-plaintext.sqlite").to_vec(),
        ParserOptions::default(),
    )?;
    assert_eq!(content(&actual), content(&expected));
    Ok(())
}

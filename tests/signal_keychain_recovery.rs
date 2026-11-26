//! Exercise Keychain → macOS OSCrypt → Signal through the public library APIs.

#![cfg(feature = "sqlcipher")]

use anyhow::{Context, Result, ensure};
use exhume_artefacts::{
    ObjectParsed, ParserInput, ParserOptions, formats::keychain::LegacyKeychain,
    formats::os_crypt::decrypt_macos_v10, parsers::build_registry, run_parser_by_name_with_options,
};
use libsqlite3_sys as ffi;
use serde_json::Value;
use std::ffi::CString;
use std::path::Path;
use std::ptr;

const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const SCHEMA: &str = include_str!("fixtures/signal_keychain_recovery.sql");

#[test]
fn reads_through_indirect_keychain_and_macos_envelope_recovery() -> Result<()> {
    let keychain = indirect_keychain()?;
    let before_keychain = keychain.clone();
    let protected_entropy = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let unlocked = LegacyKeychain::parse(&keychain)?.unlock_login_password(
        b"SYNTHETIC-LOGIN-PASSWORD\n",
        &protected_entropy,
        None,
    )?;
    let storage = unlocked.recover_generic_password(
        b"Exhume Partition Fixture",
        b"fixture-partition",
        None,
    )?;
    // Independently generated with Python hashlib/hmac and PyCryptodome.
    let envelope = hex::decode(
        "76313021ba560892f7ae52bd08a6bd238040a435a94b9fe95b8a787be17e5486be929185edd976b91aa7d9878b6941b5b7dd32e6af22bc6644e1416c79b47e6a4e4d724d2509d9b2886ac79e6b9a6058caeb22",
    )?;
    let candidate = decrypt_macos_v10(&envelope, storage.expose(), None)?;

    let temporary = tempfile::tempdir()?;
    let encrypted = temporary.path().join("encrypted.sqlite");
    let plaintext = temporary.path().join("plaintext.sqlite");
    create_database(&encrypted, Some(KEY))?;
    create_database(&plaintext, None)?;
    let before_encrypted = std::fs::read(&encrypted)?;
    let before_plaintext = std::fs::read(&plaintext)?;
    assert!(!before_encrypted.starts_with(b"SQLite format 3"));
    assert!(
        !before_encrypted
            .windows(10)
            .any(|bytes| bytes == b"unread one")
    );

    let mut options = ParserOptions::default();
    options.insert_secret("database_key", candidate)?;
    let recovered = parse(encrypted.clone(), options)?;
    let expected = parse(plaintext.clone(), ParserOptions::default())?;
    assert_eq!(
        recovered
            .iter()
            .filter(|record| record.kind == "mobile.communication.message")
            .count(),
        17,
    );
    assert_eq!(content(&recovered)?, content(&expected)?);
    assert_eq!(std::fs::read(encrypted)?, before_encrypted);
    assert_eq!(std::fs::read(plaintext)?, before_plaintext);
    assert_eq!(keychain, before_keychain);
    Ok(())
}

fn parse(path: std::path::PathBuf, options: ParserOptions) -> Result<Vec<ObjectParsed>> {
    let mut records = Vec::new();
    let mut issues = Vec::new();
    run_parser_by_name_with_options(
        &build_registry(),
        "desktop_signal",
        ParserInput::Path(path),
        options,
        &mut |record| {
            records.push(record);
            Ok(())
        },
        &mut |issue| {
            issues.push(issue);
            Ok(())
        },
    )?;
    assert!(issues.is_empty(), "unexpected parser issues: {issues:?}");
    Ok(records)
}

fn content(records: &[ObjectParsed]) -> Result<Vec<(&'static str, String, Value)>> {
    records
        .iter()
        .map(|record| {
            let mut json = record.json.clone();
            // Only provenance differs between the encrypted and plaintext files.
            json.as_object_mut()
                .context("record must be a JSON object")?
                .remove("source");
            Ok((record.kind, record.text.clone(), json))
        })
        .collect()
}

fn indirect_keychain() -> Result<Vec<u8>> {
    let mut bytes =
        include_bytes!("../src/formats/keychain/fixtures/synthetic-partition.keychain-db").to_vec();
    let start = LegacyKeychain::parse(&bytes)?
        .metadata()
        .database_blob_offset
        .context("fixture must contain a database protection blob")?;
    // Independently rewrapped synthetic database blob. Native item/group-key
    // records stay intact; these invented credentials are public test values.
    let blob = hex::decode(
        "fade07110000020000000078000000a8c7533ede5f8569413b35e0d5647f093f000000000000012c0100000046dedf8d809c2e21629a6aed0e1e7725ef44d1ad80ed62ff899ab9c9fb6167f3815d30d5b157e1eb46a62a78989255550000000000000001000000010000000000000001000000000100000069006ce29a1eed8b3c150c10f407010d3c506b619e3a0e7e4420b64a6465909964b6a302dc5f1ca455d22ab408438173",
    )?;
    let end = start
        .checked_add(blob.len())
        .context("fixture blob offset overflow")?;
    bytes
        .get_mut(start..end)
        .context("fixture blob exceeds file")?
        .copy_from_slice(&blob);
    Ok(bytes)
}

// The library's SQLite writer is private. This test-only owner uses the existing
// FFI dependency solely to create temporary fixtures, without exposing internals
// or adding a second SQLite dependency to the crate.
struct FixtureDatabase(*mut ffi::sqlite3);

impl Drop for FixtureDatabase {
    fn drop(&mut self) {
        // SAFETY: this owner holds one non-null SQLite handle. sqlite3_exec has
        // finished and left no outstanding statements when the owner is dropped.
        unsafe { ffi::sqlite3_close(self.0) };
    }
}

fn create_database(path: &Path, key: Option<&str>) -> Result<()> {
    let path = CString::new(path.to_str().context("fixture path must be UTF-8")?)?;
    let mut handle = ptr::null_mut();
    // SAFETY: path is NUL-terminated and the output pointer is valid for the call.
    let status = unsafe { ffi::sqlite3_open(path.as_ptr(), &mut handle) };
    ensure!(
        !handle.is_null(),
        "SQLite could not allocate a fixture connection"
    );
    let connection = FixtureDatabase(handle);
    ensure!(
        status == ffi::SQLITE_OK,
        "SQLite fixture open failed: {status}"
    );
    let prefix = key.map_or_else(String::new, |key| {
        format!("PRAGMA key = \"x'{key}'\"; PRAGMA cipher_compatibility = 4;")
    });
    let sql = CString::new(format!("{prefix}\n{SCHEMA}"))?;
    // SAFETY: connection owns a live handle and sql is NUL-terminated. No
    // callback or context is installed; the optional error-message output is null.
    let status = unsafe {
        ffi::sqlite3_exec(
            connection.0,
            sql.as_ptr(),
            None,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    ensure!(
        status == ffi::SQLITE_OK,
        "SQLite fixture creation failed: {status}"
    );
    Ok(())
}

use crate::core::{
    CompoundParserInput, ObjectParsed, Parser, ParserFileProvider, ParserInput, ParserIssue,
    ParserIssueCode, ParserOptions, ParserSecret, ParserSource,
};
use crate::formats::keychain::KeychainError;
use crate::formats::sqlite::SqliteConnection;
use crate::parsers::macos::MacosKeychainParser;
use anyhow::Result;
use std::io::{Cursor, Write};

const FIXTURE: &[u8] = include_bytes!("../../../formats/keychain/fixtures/synthetic.keychain-db");
const PASSWORD: &[u8] = b"exhume synthetic fixture password";

fn options(password: Option<&[u8]>) -> ParserOptions {
    let mut options = ParserOptions::default();
    if let Some(password) = password {
        options
            .insert_secret("password", ParserSecret::new(password.to_vec()))
            .unwrap();
    }
    options
}
fn run(
    input: ParserInput,
    password: Option<&[u8]>,
) -> (Result<()>, Vec<ObjectParsed>, Vec<ParserIssue>) {
    let mut objects = Vec::new();
    let mut issues = Vec::new();
    let result = crate::run_parser_with_options(
        &MacosKeychainParser,
        input,
        options(password),
        &mut |object| {
            objects.push(object);
            Ok(())
        },
        &mut |issue| {
            issues.push(issue);
            Ok(())
        },
    );
    (result, objects, issues)
}

#[test]
fn preserves_metadata_and_authentication_scope_without_emitting_secrets() {
    for password in [None, Some(PASSWORD)] {
        let (result, objects, issues) = run(ParserInput::Bytes(FIXTURE.to_vec()), password);
        result.unwrap();
        assert!(issues.is_empty());
        assert_eq!(objects.len(), 3);
        assert!(objects.iter().all(|obj| obj.json["class"] != "certificate"));
        let items: Vec<_> = objects
            .iter()
            .filter(|obj| obj.json["class"] == "generic_password")
            .collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].json["item"]["service"], "Exhume Keychain Fixture");
        assert_eq!(items[0].json["item"]["account"], "fixture-alpha");
        assert_eq!(items[0].json["source"]["byte_offset"], 0x5598);
        assert_eq!(items[1].json["source"]["record_number"], 1);
        assert!(items[0].json["timestamps"]["created"]["rfc3339"].is_string());
        for object in objects {
            assert_eq!(object.parser, "macos_keychain");
            assert_eq!(
                object.json["recovery"]["status"],
                if password.is_some() {
                    "database_keys_authenticated"
                } else {
                    "not_attempted"
                }
            );
            assert_eq!(object.json["recovery"]["scope"], "database_blob_only");
            assert_eq!(object.json["recovery"]["item_payload_authenticated"], false);
            let output = format!("{object:?}");
            assert!(!output.contains("SYNTHETIC-ALPHA-SECRET"));
            assert!(!output.contains("SYNTHETIC-BETA-SECRET"));
            assert!(!output.contains(std::str::from_utf8(PASSWORD).unwrap()));
        }
    }
    let (result, objects, _) = run(ParserInput::Bytes(FIXTURE.to_vec()), Some(b"wrong"));
    assert_eq!(
        result.unwrap_err().downcast_ref::<KeychainError>(),
        Some(&KeychainError::AuthenticationFailed)
    );
    assert!(objects.is_empty());
}

#[test]
fn reads_native_internet_metadata_protocol_and_integer_port() {
    let fixture =
        include_bytes!("../../../formats/keychain/fixtures/synthetic-internet.keychain-db");
    let (result, objects, issues) = run(ParserInput::Bytes(fixture.to_vec()), Some(PASSWORD));
    result.unwrap();
    assert!(issues.is_empty());
    assert_eq!(objects.len(), 2);
    let object = objects
        .iter()
        .find(|obj| obj.json["class"] == "internet_password")
        .unwrap();
    assert_eq!(object.json["item"]["server"], "fixture.invalid");
    assert_eq!(object.json["item"]["account"], "fixture-internet");
    assert_eq!(object.json["item"]["protocol"], "htps");
    assert_eq!(object.json["item"]["port"], 443);
    assert_eq!(object.json["item"]["path"], "/exhume-fixture");
    assert!(object.json["item"]["comment"].is_null());
    assert!(!format!("{objects:?}").contains("SYNTHETIC-INTERNET-SECRET"));
}

#[test]
fn authenticates_indirect_protection_and_checks_conditional_inputs() {
    use crate::core::ParserInputError;
    use crate::formats::keychain::fixtures::{LOGIN_PASSWORD, PROTECTED_ENTROPY, indirect_fixture};
    let mut settings = options(Some(LOGIN_PASSWORD));
    settings
        .insert_secret(
            "protected_entropy",
            ParserSecret::new(hex::encode(PROTECTED_ENTROPY).into_bytes()),
        )
        .unwrap();
    let mut objects = Vec::new();
    crate::run_parser_with_options(
        &MacosKeychainParser,
        ParserInput::Bytes(indirect_fixture()),
        settings,
        &mut |object| {
            objects.push(object);
            Ok(())
        },
        &mut |_| Ok(()),
    )
    .unwrap();
    assert!(
        objects
            .iter()
            .all(|o| o.json["recovery"]["method"] == "login_password_protected_entropy")
    );
    let serialized = format!("{objects:?}");
    assert!(!serialized.contains("SYNTHETIC-LOGIN-PASSWORD"));
    assert!(!serialized.contains(&hex::encode(PROTECTED_ENTROPY)));
    let mut settings = options(None);
    settings
        .insert_secret(
            "protected_entropy",
            ParserSecret::new(hex::encode(PROTECTED_ENTROPY).into_bytes()),
        )
        .unwrap();
    let error = crate::run_parser_with_options(
        &MacosKeychainParser,
        ParserInput::Bytes(Vec::new()),
        settings,
        &mut |_| anyhow::bail!("must not emit"),
        &mut |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<ParserInputError>(),
        Some(ParserInputError::NeedsInput { .. })
    ));
    let mut settings = options(Some(LOGIN_PASSWORD));
    settings
        .insert_secret(
            "protected_entropy",
            ParserSecret::new(b"bad entropy".to_vec()),
        )
        .unwrap();
    let error = crate::run_parser_with_options(
        &MacosKeychainParser,
        ParserInput::Bytes(Vec::new()),
        settings,
        &mut |_| anyhow::bail!("must not emit"),
        &mut |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<ParserInputError>(),
        Some(ParserInputError::InvalidConfiguration { .. })
    ));
    assert!(!error.to_string().contains("bad entropy"));
}

struct Provider(Vec<u8>);
impl ParserFileProvider for Provider {
    fn copy_to(&mut self, _: &ParserSource, output: &mut dyn Write) -> Result<()> {
        output.write_all(&self.0)?;
        Ok(())
    }
}

#[test]
fn supports_paths_streams_providers_and_preserves_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("login.keychain-db");
    std::fs::write(&path, FIXTURE).unwrap();
    for input in [
        ParserInput::Path(path),
        ParserInput::ReadSeek(Box::new(Cursor::new(FIXTURE.to_vec()))),
    ] {
        let (result, objects, issues) = run(input, Some(PASSWORD));
        result.unwrap();
        assert_eq!(objects.len(), 3);
        assert!(issues.is_empty());
    }
    let input = ParserInput::Compound(CompoundParserInput {
        primary: ParserSource::new(
            "primary",
            "/Users/lab/Library/Keychains/login.keychain-db",
            Some(7),
            Some(8),
            Some(9),
        ),
        companions: Vec::new(),
        provider: Box::new(Provider(FIXTURE.to_vec())),
    });
    let (result, objects, _) = run(input, None);
    result.unwrap();
    assert_eq!(objects[0].json["source"]["files"][0]["artifact_id"], 7);
    assert_eq!(objects[0].json["source"]["files"][0]["fs_identifier"], 9);
}

fn damaged_attribute() -> Vec<u8> {
    let mut bytes = FIXTURE.to_vec();
    bytes[0x5598 + 76..0x5598 + 80].copy_from_slice(&u32::MAX.to_be_bytes());
    bytes
}

#[test]
fn damaged_rows_report_source_locations_in_both_invocation_paths() {
    let (result, objects, issues) = run(ParserInput::Bytes(damaged_attribute()), None);
    result.unwrap();
    assert_eq!(objects.len(), 2);
    assert_eq!(issues.len(), 1);
    assert!(matches!(issues[0].code, ParserIssueCode::RecordParse));
    assert_eq!(issues[0].unit, Some(0x5598));
    assert!(issues[0].message.contains("record 0"));
    assert!(issues[0].message.contains("0x80000000"));
    let mut issues = Vec::new();
    MacosKeychainParser
        .run_into_with_diagnostics(
            ParserInput::Bytes(damaged_attribute()),
            &mut |_| Ok(()),
            &mut |issue| {
                issues.push(issue);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(issues.len(), 1);
    let error = MacosKeychainParser
        .run_into_with_diagnostics(
            ParserInput::Bytes(damaged_attribute()),
            &mut |_| Ok(()),
            &mut |_| anyhow::bail!("diagnostic failed"),
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "diagnostic failed");
    let error = MacosKeychainParser
        .run_into(ParserInput::Bytes(FIXTURE.to_vec()), &mut |_| {
            anyhow::bail!("sink failed")
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "sink failed");
}

#[test]
fn sqlite_metadata_and_wal_remain_supported_but_password_recovery_is_explicitly_unsupported() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("keychain-2.db");
    let connection = SqliteConnection::create_for_test(&path).unwrap();
    connection.execute_batch("PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0; CREATE TABLE genp(svce TEXT, acct TEXT); INSERT INTO genp VALUES ('Synthetic service', 'Synthetic account');").unwrap();
    // Keep the writer open so the row/schema still require the live WAL.
    let (result, objects, issues) = run(ParserInput::Path(path.clone()), None);
    result.unwrap();
    assert!(issues.is_empty());
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].json["item"]["account"], "Synthetic account");
    assert!(
        objects[0].json["source"]["copied_sidecars"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "wal")
    );
    let (result, objects, _) = run(ParserInput::Path(path), Some(PASSWORD));
    assert_eq!(
        result.unwrap_err().downcast_ref::<KeychainError>(),
        Some(&KeychainError::UnsupportedFormat)
    );
    assert!(objects.is_empty());
}

#[test]
fn bounds_stream_provider_and_companion_materialization() {
    use crate::formats::sqlite::SqliteEvidence;
    for input in [
        ParserInput::ReadSeek(Box::new(Cursor::new(vec![0; 1025]))),
        ParserInput::Compound(CompoundParserInput {
            primary: ParserSource::new("primary", "oversized", None, None, None),
            companions: Vec::new(),
            provider: Box::new(Provider(vec![0; 1025])),
        }),
    ] {
        assert!(SqliteEvidence::from_input_bounded(input, "keychain", 1024).is_err());
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("keychain-2.db");
    std::fs::write(&path, vec![0; 1024]).unwrap();
    let wal = directory.path().join("keychain-2.db-wal");
    std::fs::write(&wal, vec![0; 1025]).unwrap();
    assert!(SqliteEvidence::from_input_bounded(ParserInput::Path(path), "keychain", 1024).is_err());
    assert_eq!(std::fs::metadata(wal).unwrap().len(), 1025);
}

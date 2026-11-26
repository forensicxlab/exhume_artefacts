use crate::{
    CompoundParserInput, ObjectParsed, ParserFileProvider, ParserInput, ParserOptions,
    ParserSecret, ParserSource,
    input::{self, CompanionOverride},
    parsers::build_registry,
    run_parser_by_name_with_options,
};
use anyhow::Result;
use std::io::Write;

const WALLET: &[u8] = include_bytes!("../../../formats/kwallet/fixtures/synthetic-signal.kwl");
const SALT: &[u8] = include_bytes!("../../../formats/kwallet/fixtures/synthetic-signal.salt");
const PASSWORD: &[u8] = b"SYNTHETIC-GNOME-PASSWORD\n";

fn options(password: Option<&[u8]>) -> ParserOptions {
    let mut options = ParserOptions::default();
    if let Some(password) = password {
        options
            .insert_secret("password", ParserSecret::new(password.to_vec()))
            .unwrap();
    }
    options
}
fn parse(
    input: ParserInput,
    password: Option<&[u8]>,
    records: &mut Vec<ObjectParsed>,
) -> Result<()> {
    run_parser_by_name_with_options(
        &build_registry(),
        "linux_kwallet",
        input,
        options(password),
        &mut |record| {
            records.push(record);
            Ok(())
        },
        &mut |_| anyhow::bail!("unexpected diagnostic"),
    )
}

#[test]
fn discovered_and_explicit_salts_unlock_without_emitting_secrets() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("my.wallet.kwl");
    let salt = path.with_extension("salt");
    std::fs::write(&path, WALLET)?;
    std::fs::write(&salt, SALT)?;
    for override_salt in [false, true] {
        let alternate = dir.path().join("acquired-salt.bin");
        let overrides = if override_salt {
            std::fs::rename(&salt, &alternate)?;
            vec![CompanionOverride {
                role: "salt".into(),
                path: alternate.to_str().unwrap().into(),
            }]
        } else {
            Vec::new()
        };
        let registry = build_registry();
        let parser = registry.get("linux_kwallet").unwrap();
        let input = input::local_input(&**parser, &path, &overrides)?;
        let mut records = Vec::new();
        parse(input, Some(PASSWORD), &mut records)?;
        assert_eq!(records.len(), 4);
        assert_eq!(
            records[0].json["recovery"]["status"],
            "payload_sha1_verified"
        );
        assert_eq!(
            records[0].json["recovery"]["outer_index_authenticated"],
            false
        );
        assert_eq!(records[1].json["entry"]["index_offset"], 40);
        assert_eq!(records[1].json["entry"]["folder"], "Chromium Keys");
        let files = records[0].json["source"]["files"].as_array().unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[1]["role"], "salt");
        assert_eq!(
            files[1]["path"],
            if override_salt { &alternate } else { &salt }
                .to_str()
                .unwrap()
        );
        let serialized =
            serde_json::to_string(&records.iter().map(|r| &r.json).collect::<Vec<_>>())?;
        for value in [
            "SYNTHETIC-GNOME-PASSWORD",
            "SYNTHETIC+Safe/Storage",
            "SYNTHETIC-STREAM-SECRET",
            "SYNTHETIC-UNICODE-SECRET",
        ] {
            assert!(!serialized.contains(value));
        }
    }
    Ok(())
}

#[test]
fn metadata_needs_no_salt_but_unlock_failures_emit_nothing() -> Result<()> {
    let mut records = Vec::new();
    parse(ParserInput::Bytes(WALLET.to_vec()), None, &mut records)?;
    assert_eq!(records.len(), 4);
    assert_eq!(records[1].kind, "linux.kwallet.folder");
    assert_eq!(records[1].json["metadata_state"], "hashed_index");
    assert!(!serde_json::to_string(&records[1].json)?.contains("Chromium"));
    records.clear();
    assert!(
        parse(
            ParserInput::Bytes(WALLET.to_vec()),
            Some(PASSWORD),
            &mut records
        )
        .is_err()
    );
    assert!(records.is_empty());
    for salt in [SALT.to_vec(), vec![0; 56], vec![0; 55], vec![0; 57]] {
        let input = compound(salt, false);
        assert!(parse(input, Some(b"incorrect"), &mut records).is_err());
        assert!(records.is_empty());
    }
    Ok(())
}

struct Provider {
    salt: Vec<u8>,
    fail: bool,
}
impl ParserFileProvider for Provider {
    fn copy_to(&mut self, source: &ParserSource, writer: &mut dyn Write) -> Result<()> {
        if source.role == "salt" {
            if self.fail {
                anyhow::bail!("test salt provider failure");
            }
            writer.write_all(&self.salt)?;
        } else {
            writer.write_all(WALLET)?;
        }
        Ok(())
    }
}
fn compound(salt: Vec<u8>, fail: bool) -> ParserInput<'static> {
    ParserInput::Compound(CompoundParserInput {
        primary: ParserSource::new(
            "primary",
            "/evidence/wallet.kwl",
            Some(10),
            Some(20),
            Some(30),
        ),
        companions: vec![ParserSource::new(
            "salt",
            "/evidence/wallet.salt",
            Some(11),
            Some(21),
            Some(31),
        )],
        provider: Box::new(Provider { salt, fail }),
    })
}

#[test]
fn provider_provenance_bounds_and_sink_failures_survive_the_adapter() -> Result<()> {
    let mut records = Vec::new();
    parse(compound(SALT.to_vec(), false), Some(PASSWORD), &mut records)?;
    let files = &records[0].json["source"]["files"];
    assert_eq!(files[0]["artifact_id"], 10);
    assert_eq!(files[1]["system_file_id"], 21);
    assert_eq!(files[1]["fs_identifier"], 31);
    records.clear();
    let error = parse(compound(SALT.to_vec(), true), Some(PASSWORD), &mut records).unwrap_err();
    assert!(format!("{error:#}").contains("test salt provider failure"));
    assert!(records.is_empty());
    assert!(parse(compound(vec![0; 57], false), None, &mut records).is_err());
    assert!(records.is_empty());
    let mut duplicate = match compound(SALT.to_vec(), false) {
        ParserInput::Compound(c) => c,
        _ => unreachable!(),
    };
    duplicate.companions.push(duplicate.companions[0].clone());
    assert!(parse(ParserInput::Compound(duplicate), None, &mut records).is_err());
    assert!(records.is_empty());
    let error = run_parser_by_name_with_options(
        &build_registry(),
        "linux_kwallet",
        compound(SALT.to_vec(), false),
        options(Some(PASSWORD)),
        &mut |_| anyhow::bail!("test wallet sink failure"),
        &mut |_| Ok(()),
    )
    .unwrap_err();
    assert!(error.to_string().contains("test wallet sink failure"));
    Ok(())
}

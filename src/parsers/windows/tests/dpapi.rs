use crate::core::{
    CompoundParserInput, ObjectParsed, Parser, ParserFileProvider, ParserInput, ParserInputError,
    ParserOptionValue, ParserOptions, ParserSecret, ParserSource,
};
use crate::formats::dpapi::{DpapiError, MAX_INPUT_BYTES, fixtures::*};
use crate::parsers::windows::WindowsDpapiMasterKeyParser;
use anyhow::Result;
use std::io::{Cursor, Write};

fn options(password: Option<&str>) -> ParserOptions {
    let mut options = ParserOptions::default();
    options
        .insert("account_sid", ParserOptionValue::String(SID.to_owned()))
        .unwrap();
    if let Some(password) = password {
        options
            .insert_secret("password", ParserSecret::new(password.as_bytes().to_vec()))
            .unwrap();
    }
    options
}
fn run(input: ParserInput, options: ParserOptions) -> (Result<()>, Vec<ObjectParsed>) {
    let mut objects = Vec::new();
    let result = crate::run_parser_with_options(
        &WindowsDpapiMasterKeyParser,
        input,
        options,
        &mut |object| {
            objects.push(object);
            Ok(())
        },
        &mut |_| Ok(()),
    );
    (result, objects)
}

#[test]
fn emits_metadata_and_authentication_status_without_key_material() {
    for password in [None, Some(PASSWORD)] {
        let (result, objects) = run(
            ParserInput::Bytes(hex::decode(MASTER_FILE).unwrap()),
            options(password),
        );
        result.unwrap();
        assert_eq!(objects.len(), 1);
        let object = &objects[0];
        assert_eq!(object.kind, "windows.dpapi.master_key");
        assert_eq!(object.json["master_key"]["guid"], GUID);
        assert_eq!(
            object.json["recovery"]["status"],
            if password.is_some() {
                "authenticated"
            } else {
                "not_attempted"
            }
        );
        assert!(!object.json.to_string().contains(PASSWORD));
        assert!(
            !object
                .json
                .to_string()
                .contains("0102030405060708090a0b0c0d0e0f10")
        );
    }
}

#[test]
fn retains_input_requests_and_authentication_failures_before_emitting() {
    let mut missing = ParserOptions::default();
    missing
        .insert_secret("password", ParserSecret::new(PASSWORD.as_bytes().to_vec()))
        .unwrap();
    let (result, objects) = run(ParserInput::Bytes(Vec::new()), missing);
    assert!(objects.is_empty());
    assert!(matches!(
        result.unwrap_err().downcast_ref::<ParserInputError>(),
        Some(ParserInputError::NeedsInput { .. })
    ));
    let (result, objects) = run(
        ParserInput::Bytes(hex::decode(MASTER_FILE).unwrap()),
        options(Some("incorrect")),
    );
    assert!(objects.is_empty());
    assert_eq!(
        result.unwrap_err().downcast_ref::<DpapiError>(),
        Some(&DpapiError::AuthenticationFailed)
    );
}

struct Provider(Vec<u8>);
impl ParserFileProvider for Provider {
    fn copy_to(&mut self, _: &ParserSource, output: &mut dyn Write) -> Result<()> {
        output.write_all(&self.0)?;
        Ok(())
    }
}

#[test]
fn accepts_provider_sources_and_preserves_provenance_and_sink_failures() {
    let input = ParserInput::Compound(CompoundParserInput {
        primary: ParserSource::new(
            "primary",
            "/Users/test/Protect/master-key",
            Some(7),
            Some(8),
            Some(9),
        ),
        companions: Vec::new(),
        provider: Box::new(Provider(hex::decode(MASTER_FILE).unwrap())),
    });
    let (result, objects) = run(input, ParserOptions::default());
    result.unwrap();
    assert_eq!(objects[0].json["source"]["files"][0]["artifact_id"], 7);
    assert_eq!(objects[0].json["source"]["files"][0]["fs_identifier"], 9);
    let result = WindowsDpapiMasterKeyParser.run_into(
        ParserInput::ReadSeek(Box::new(Cursor::new(hex::decode(MASTER_FILE).unwrap()))),
        &mut |_| anyhow::bail!("sink failed"),
    );
    assert_eq!(result.unwrap_err().to_string(), "sink failed");
}

#[test]
fn enforces_the_byte_limit_for_stream_and_provider_inputs() {
    let data = vec![0; MAX_INPUT_BYTES + 1];
    let (result, objects) = run(
        ParserInput::ReadSeek(Box::new(Cursor::new(data.clone()))),
        ParserOptions::default(),
    );
    assert!(result.is_err());
    assert!(objects.is_empty());
    let input = ParserInput::Compound(CompoundParserInput {
        primary: ParserSource::new("primary", "oversized", None, None, None),
        companions: Vec::new(),
        provider: Box::new(Provider(data)),
    });
    let (result, objects) = run(input, ParserOptions::default());
    assert!(result.is_err());
    assert!(objects.is_empty());
}

use crate::{
    ParserInput, ParserOptions, ParserSecret, parsers::build_registry,
    run_parser_by_name_with_options,
};

const NATIVE: &[u8] =
    include_bytes!("../../../formats/gnome_keyring/fixtures/gnome-48-encrypted.keyring");

#[test]
fn metadata_and_password_modes_preserve_provenance_and_never_emit_secrets() {
    for password in [None, Some(b"my-keyring-password".as_slice())] {
        let mut options = ParserOptions::default();
        if let Some(password) = password {
            options
                .insert_secret("password", ParserSecret::new(password.to_vec()))
                .unwrap();
        }
        let mut records = Vec::new();
        run_parser_by_name_with_options(
            &build_registry(),
            "linux_gnome_keyring",
            ParserInput::Bytes(NATIVE.to_vec()),
            options,
            &mut |record| {
                records.push(record);
                Ok(())
            },
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].kind, "linux.gnome_keyring.collection");
        assert_eq!(
            records[0].json["recovery"]["status"],
            if password.is_some() {
                "payload_md5_verified"
            } else {
                "not_attempted"
            }
        );
        assert_eq!(records[1].json["source"]["index"], 2);
        let json =
            serde_json::to_string(&records.iter().map(|r| &r.json).collect::<Vec<_>>()).unwrap();
        for secret in ["my-keyring-password", "item-secret"] {
            assert!(!json.contains(secret));
        }
        if password.is_some() {
            assert!(json.contains("woof"));
        } else {
            assert!(!json.contains("woof"));
        }
    }
}

#[test]
fn failed_passwords_and_sink_failures_do_not_report_success() {
    let mut options = ParserOptions::default();
    options
        .insert_secret("password", ParserSecret::new(b"incorrect".to_vec()))
        .unwrap();
    let mut count = 0;
    assert!(
        run_parser_by_name_with_options(
            &build_registry(),
            "linux_gnome_keyring",
            ParserInput::Bytes(NATIVE.to_vec()),
            options,
            &mut |_| {
                count += 1;
                Ok(())
            },
            &mut |_| Ok(())
        )
        .is_err()
    );
    assert_eq!(count, 0);
    let error = run_parser_by_name_with_options(
        &build_registry(),
        "linux_gnome_keyring",
        ParserInput::Bytes(NATIVE.to_vec()),
        ParserOptions::default(),
        &mut |_| anyhow::bail!("test sink failure"),
        &mut |_| Ok(()),
    )
    .unwrap_err();
    assert!(error.to_string().contains("test sink failure"));
}

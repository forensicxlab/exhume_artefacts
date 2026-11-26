use base64::{Engine, engine::general_purpose::STANDARD};
use exhume_artefacts::{assets::*, recovery::signal::attachment::*};
use serde_json::{Value, json};
use std::{
    io::{Cursor, Read},
    sync::atomic::{AtomicBool, Ordering},
};

fn vector() -> Value {
    serde_json::from_str(include_str!("fixtures/signal-attachment.json")).unwrap()
}
fn record() -> Value {
    let v = vector();
    json!({"attachment":{"local_path":"ab/image","mime":"image/png"},"details":{"version":2,"local_key":v["key"],"size":v["size"],"plaintext_hash":v["plaintext_sha256"],"digest":"unrelated-transit-digest"}})
}
fn ciphertext() -> Cursor<Vec<u8>> {
    Cursor::new(
        STANDARD
            .decode(vector()["ciphertext"].as_str().unwrap())
            .unwrap(),
    )
}
#[test]
fn recovers_reference_vector_and_removes_signals_extra_padding() {
    let spec = AttachmentSpec::from_record(&record(), Rendition::Original).unwrap();
    let mut output = Vec::new();
    let proof = recover_attachment(&mut ciphertext(), &mut output, &spec, 4096, None).unwrap();
    let v = vector();
    assert_eq!(
        output,
        STANDARD.decode(v["plaintext"].as_str().unwrap()).unwrap()
    );
    assert_eq!(proof.plaintext_sha256, v["plaintext_sha256"]);
    assert_eq!(proof.source_sha256, v["ciphertext_sha256"]);
    assert_eq!(proof.authentication, "hmac_sha256");
    assert!(proof.metadata_hash_checked);
    assert!(!format!("{spec:?}").contains(v["key"].as_str().unwrap()));
}
#[test]
fn corrupt_or_wrong_key_input_never_writes_plaintext() {
    for wrong_key in [false, true] {
        let mut row = record();
        let mut input = ciphertext();
        if wrong_key {
            row["details"]["local_key"] = STANDARD.encode([9; 64]).into();
        } else {
            input.get_mut()[17] ^= 1;
        }
        let spec = AttachmentSpec::from_record(&row, Rendition::Original).unwrap();
        let mut output = Vec::new();
        assert_eq!(
            recover_attachment(&mut input, &mut output, &spec, 4096, None)
                .unwrap_err()
                .code,
            AssetErrorCode::AuthenticationFailed
        );
        assert!(output.is_empty());
    }
}
#[test]
fn failed_size_hash_or_cancellation_leaves_no_published_file() {
    for (kind, code) in [
        ("size", AssetErrorCode::SizeMismatch),
        ("hash", AssetErrorCode::HashMismatch),
        ("cancel", AssetErrorCode::Cancelled),
    ] {
        let mut row = record();
        if kind == "size" {
            row["details"]["size"] = 2048.into();
        }
        if kind == "hash" {
            row["details"]["plaintext_hash"] = "00".repeat(32).into();
        }
        let spec = AttachmentSpec::from_record(&row, Rendition::Original).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(kind == "cancel");
        assert_eq!(
            dump_asset(&mut ciphertext(), &spec, dir.path(), 4096, Some(&cancel))
                .unwrap_err()
                .code,
            code
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
#[test]
fn validates_cache_and_separates_thumbnail_keys() {
    let dir = tempfile::tempdir().unwrap();
    let mut row = record();
    let v = vector();
    row["attachment"]["thumbnail_path"] = "cd/thumb".into();
    row["details"]["thumbnail_version"] = 2.into();
    row["details"]["thumbnail_local_key"] = v["key"].clone();
    row["details"]["thumbnail_size"] = v["size"].clone();
    let thumb = AttachmentSpec::from_record(&row, Rendition::Thumbnail).unwrap();
    assert_eq!(thumb.local_path, "cd/thumb");
    let asset = dump_asset(&mut ciphertext(), &thumb, dir.path(), 4096, None).unwrap();
    let mut file = open_dumped_asset(dir.path(), &asset, None).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes.len() as u64, asset.proof.plaintext_size);
    std::fs::write(dir.path().join(&asset.relative_path), vec![0; bytes.len()]).unwrap();
    assert_eq!(
        open_dumped_asset(dir.path(), &asset, None)
            .unwrap_err()
            .code,
        AssetErrorCode::HashMismatch
    );
    let malicious = DumpedAsset {
        relative_path: "../outside".into(),
        ..asset
    };
    assert_eq!(
        open_dumped_asset(dir.path(), &malicious, None)
            .unwrap_err()
            .code,
        AssetErrorCode::UnsafeDestination
    );
}
#[test]
fn legacy_plaintext_requires_consistent_metadata_and_v2_requires_a_key() {
    let mut row = record();
    row["details"]["version"] = 1.into();
    row["details"]["local_key"] = Value::Null;
    let spec = AttachmentSpec::from_record(&row, Rendition::Original).unwrap();
    let mut bytes = Cursor::new(
        STANDARD
            .decode(vector()["plaintext"].as_str().unwrap())
            .unwrap(),
    );
    let mut output = Vec::new();
    assert_eq!(
        recover_attachment(&mut bytes, &mut output, &spec, 4096, None)
            .unwrap()
            .authentication,
        "legacy_plaintext"
    );
    row["details"]["version"] = 2.into();
    assert_eq!(
        AttachmentSpec::from_record(&row, Rendition::Original)
            .unwrap_err()
            .code,
        AssetErrorCode::InvalidKey
    );
    row["details"]["version"] = 9.into();
    assert_eq!(
        AttachmentSpec::from_record(&row, Rendition::Original)
            .unwrap_err()
            .code,
        AssetErrorCode::UnsupportedVersion
    );
}
#[test]
fn validates_limits_destinations_and_source_traversal_before_writes() {
    let spec = AttachmentSpec::from_record(&record(), Rendition::Original).unwrap();
    let mut output = Vec::new();
    assert_eq!(
        recover_attachment(&mut ciphertext(), &mut output, &spec, 100, None)
            .unwrap_err()
            .code,
        AssetErrorCode::LimitExceeded
    );
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("not-created/assets");
    assert_eq!(
        validate_dump_destination(root.path(), &destination)
            .unwrap_err()
            .code,
        AssetErrorCode::UnsafeDestination
    );
    assert!(!destination.exists());
    std::fs::create_dir(root.path().join("attachments.noindex")).unwrap();
    assert!(
        local_asset_path(
            root.path(),
            &PlaintextSpec::from_record(
                &serde_json::json!({"attachment":{"local_path":"../outside"}}),
                Rendition::Original
            )
            .unwrap()
        )
        .is_err()
    );
}
#[test]
fn cancellation_interrupts_an_input_read_without_publishing() {
    struct Cancelling<'a> {
        bytes: Cursor<Vec<u8>>,
        cancel: &'a AtomicBool,
    }
    impl Read for Cancelling<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let count = self.bytes.read(out)?;
            self.cancel.store(true, Ordering::Relaxed);
            Ok(count)
        }
    }
    impl std::io::Seek for Cancelling<'_> {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.bytes.seek(pos)
        }
    }
    let cancel = AtomicBool::new(false);
    let mut input = Cancelling {
        bytes: ciphertext(),
        cancel: &cancel,
    };
    let dir = tempfile::tempdir().unwrap();
    let spec = AttachmentSpec::from_record(&record(), Rendition::Original).unwrap();
    assert_eq!(
        dump_asset(&mut input, &spec, dir.path(), 4096, Some(&cancel))
            .unwrap_err()
            .code,
        AssetErrorCode::Cancelled
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn a_source_changed_between_authentication_and_decoding_is_not_published() {
    struct Changing {
        bytes: Cursor<Vec<u8>>,
        starts: usize,
    }
    impl Read for Changing {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            self.bytes.read(output)
        }
    }
    impl std::io::Seek for Changing {
        fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
            if position == std::io::SeekFrom::Start(0) {
                self.starts += 1;
                if self.starts == 2 {
                    self.bytes.get_mut()[17] ^= 1;
                }
            }
            self.bytes.seek(position)
        }
    }
    let mut input = Changing {
        bytes: ciphertext(),
        starts: 0,
    };
    let mut row = record();
    row["details"]["plaintext_hash"] = Value::Null;
    let spec = AttachmentSpec::from_record(&row, Rendition::Original).unwrap();
    let directory = tempfile::tempdir().unwrap();
    assert_eq!(
        dump_asset(&mut input, &spec, directory.path(), 4096, None)
            .unwrap_err()
            .code,
        AssetErrorCode::AuthenticationFailed
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

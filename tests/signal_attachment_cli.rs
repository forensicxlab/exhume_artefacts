use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::{path::Path, process::Command};

fn vector() -> Value {
    serde_json::from_str(include_str!("fixtures/signal-attachment.json")).unwrap()
}
fn profile(root: &Path, corrupt: bool) -> std::path::PathBuf {
    let path = root.join("Signal");
    std::fs::create_dir_all(path.join("sql")).unwrap();
    std::fs::create_dir_all(path.join("attachments.noindex/ab")).unwrap();
    std::fs::write(
        path.join("sql/db.sqlite"),
        include_bytes!("fixtures/signal-attachments.sqlite"),
    )
    .unwrap();
    let mut bytes = STANDARD
        .decode(vector()["ciphertext"].as_str().unwrap())
        .unwrap();
    if corrupt {
        bytes[17] ^= 1;
    }
    std::fs::write(path.join("attachments.noindex/ab/photo"), bytes).unwrap();
    path
}
fn run(profile: &Path, dump: Option<&Path>, extra: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_exhume_artefacts"));
    command
        .args(["--parser", "desktop_signal", "--file"])
        .arg(profile.join("sql/db.sqlite"));
    if let Some(dump) = dump {
        command.arg("--dump-dir").arg(dump);
    }
    command.args(extra).output().unwrap()
}
fn records(output: &std::process::Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
#[test]
fn cli_opt_in_dump_recovers_media_outside_the_profile_and_retains_messages() {
    let directory = tempfile::tempdir().unwrap();
    let profile = profile(directory.path(), false);
    let before = std::fs::read(profile.join("sql/db.sqlite")).unwrap();
    let output = directory.path().join("derived");
    let ordinary = run(&profile, None, &[]);
    assert!(!output.exists());
    let ordinary = records(&ordinary);
    let dumped = run(&profile, Some(&output), &[]);
    let dumped = records(&dumped);
    assert_eq!(dumped.len(), ordinary.len());
    let attachment = dumped
        .iter()
        .find(|record| record["attachment"].is_object())
        .unwrap();
    let recovery = &attachment["attachment"]["recovery"];
    assert_eq!(recovery["status"], "ready");
    assert_eq!(recovery["asset"]["proof"]["authentication"], "hmac_sha256");
    let path = Path::new(recovery["output_file"].as_str().unwrap());
    assert_eq!(path.parent().unwrap(), output);
    assert_eq!(
        std::fs::read(path).unwrap(),
        STANDARD
            .decode(vector()["plaintext"].as_str().unwrap())
            .unwrap()
    );
    assert_eq!(
        std::fs::read(profile.join("sql/db.sqlite")).unwrap(),
        before
    );
    assert_eq!(std::fs::read_dir(output).unwrap().count(), 1);
    assert!(!directory.path().join("untrusted-name.png").exists());
    let inside = profile.join("new/assets");
    let rejected = run(&profile, Some(&inside), &[]);
    assert!(!rejected.status.success());
    assert!(!inside.exists());
}
#[test]
fn corrupt_or_limited_media_reports_an_issue_while_messages_remain_available() {
    for corrupt in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let profile = profile(directory.path(), corrupt);
        let output = directory.path().join("derived");
        let result = run(
            &profile,
            Some(&output),
            if corrupt {
                &[]
            } else {
                &["--dump-byte-limit", "1"]
            },
        );
        let records = records(&result);
        assert!(
            records
                .iter()
                .any(|record| record["body"] == "Synthetic retained message")
        );
        assert!(
            records
                .iter()
                .any(|record| record["attachment"]["recovery"]["status"] == "unavailable")
        );
        let errors = String::from_utf8_lossy(&result.stderr);
        assert!(errors.contains("record_parse"));
        assert!(!errors.contains(vector()["key"].as_str().unwrap()));
        assert!(!output.exists() || std::fs::read_dir(output).unwrap().count() == 0);
    }
}

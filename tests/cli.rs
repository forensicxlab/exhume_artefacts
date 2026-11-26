use std::process::Command;

#[test]
fn kwallet_cli_discovers_its_salt_and_keeps_secrets_out_of_output() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/formats/kwallet/fixtures/synthetic-signal.kwl"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_exhume_artefacts"))
        .args([
            "--parser",
            "linux_kwallet",
            "--file",
            fixture,
            "--option",
            "password=SYNTHETIC-GNOME-PASSWORD\n",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 4);
    assert_eq!(records[0]["source"]["files"][1]["role"], "salt");
    let output = serde_json::to_string(&records).unwrap();
    assert!(!output.contains("SYNTHETIC"));
    assert_eq!(records[0]["recovery"]["status"], "payload_sha1_verified");
}

#[test]
fn help_exposes_one_value_option() {
    let output = Command::new(env!("CARGO_BIN_EXE_exhume_artefacts"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--option <NAME=VALUE>"));
    assert!(!help.contains("--secret-file"));
    assert!(!help.contains("--secret-stdin"));
}

#[test]
fn description_is_available_without_a_file_and_lists_companions() {
    let output = Command::new(env!("CARGO_BIN_EXE_exhume_artefacts"))
        .args(["--describe-parser", "macos_chromium"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let description: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(description["name"], "macos_chromium");
    assert_eq!(description["options"], serde_json::json!([]));
    assert!(
        description["companions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["role"] == "sqlite_wal")
    );
}

#[test]
fn unsupported_option_fails_before_opening_input_and_does_not_echo_value() {
    let output = Command::new(env!("CARGO_BIN_EXE_exhume_artefacts"))
        .args([
            "--parser",
            "windows_evtx",
            "--file",
            "/nonexistent",
            "--option",
            "password=never-echo-me",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["code"], "invalid_configuration");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("never-echo-me"));
}

#[test]
fn keychain_authentication_is_available_standalone_without_emitting_secrets() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/formats/keychain/fixtures/synthetic.keychain-db"
    );
    for (password, succeeds) in [
        ("exhume synthetic fixture password", true),
        ("incorrect-keychain-password", false),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_exhume_artefacts"))
            .args([
                "--parser",
                "macos_keychain",
                "--file",
                fixture,
                "--option",
                &format!("password={password}"),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.success(), succeeds);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stdout.contains(password));
        assert!(!stderr.contains(password));
        assert!(!stdout.contains("SYNTHETIC-ALPHA-SECRET"));
        if succeeds {
            let records: Vec<serde_json::Value> = stdout
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(records.len(), 3);
            assert!(
                records
                    .iter()
                    .all(|record| record["recovery"]["status"] == "database_keys_authenticated")
            );
        } else {
            assert!(stdout.is_empty());
            assert!(stderr.contains("Keychain authentication failed"));
        }
    }
}

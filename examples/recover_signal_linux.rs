//! Recover a Linux Signal key from explicit acquired files and stream messages.
//! Password files contain exact bytes. Database companions are discovered by
//! the existing input adapter. Keys are passed in memory and never printed.

use anyhow::{Context, Result, ensure};
use clap::{Arg, ArgAction, Command};
use exhume_artefacts::{
    ParserOptions, cli,
    formats::{
        gnome_keyring::{self, GnomeKeyring},
        kwallet::{self, KWallet},
    },
    input,
    parsers::build_registry,
    recovery::signal::{EnvelopeKind, MAX_CONFIG_BYTES, SignalKeyEnvelope},
    run_parser_with_options,
};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

fn read_bounded(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)
        .with_context(|| format!("failed to open {}", path.display()))?
        .take(
            u64::try_from(maximum)?
                .checked_add(1)
                .context("input limit overflow")?,
        )
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "input exceeds the byte limit");
    Ok(bytes)
}

fn run() -> Result<()> {
    let matches = Command::new("recover_signal_linux")
        .about("Recover a Linux Signal key from an acquired configuration and optional GNOME Keyring or KDE KWallet, then parse the database")
        .arg(Arg::new("database").long("database").required(true).value_parser(clap::value_parser!(PathBuf)))
        .arg(Arg::new("config").long("config").required(true).value_parser(clap::value_parser!(PathBuf)))
        .arg(Arg::new("keyring").long("keyring").value_parser(clap::value_parser!(PathBuf)).conflicts_with("wallet"))
        .arg(Arg::new("wallet").long("wallet").value_parser(clap::value_parser!(PathBuf)).help("Acquired modern KDE KWallet .kwl file"))
        .arg(Arg::new("salt").long("salt").requires("wallet").value_parser(clap::value_parser!(PathBuf)).help("Matching KWallet salt; defaults to the wallet path with extension .salt"))
        .arg(Arg::new("wallet_folder").long("wallet-folder").requires("wallet").help("Exact decrypted KWallet folder name"))
        .arg(Arg::new("wallet_entry").long("wallet-entry").requires("wallet").help("Exact decrypted KWallet password entry name"))
        .arg(Arg::new("password_file").long("password-file").value_parser(clap::value_parser!(PathBuf)).help("Exact GNOME Keyring or KWallet password bytes; no newline trimming"))
        .arg(Arg::new("attribute").long("attribute").action(ArgAction::Append).value_name("NAME=VALUE").help("Exact decrypted Keyring text attribute to select; repeat to narrow selection"))
        .arg(Arg::new("cipher_version").long("cipher-version").value_parser(["3", "4"]).default_value("4"))
        .get_matches();
    let database = matches
        .get_one::<PathBuf>("database")
        .context("missing database")?;
    let config_path = matches
        .get_one::<PathBuf>("config")
        .context("missing configuration")?;
    let config_bytes = read_bounded(config_path, MAX_CONFIG_BYTES)?;
    let config = SignalKeyEnvelope::parse(&config_bytes)?;
    let key = if let Some(key) = config.plaintext_key() {
        eprintln!("recovery method: legacy_config_key");
        key
    } else if config.kind() == EnvelopeKind::V11 {
        let password = matches
            .get_one::<PathBuf>("password_file")
            .context("v11 recovery requires --password-file")?;
        let password = read_bounded(password, 1024 * 1024)?;
        if let Some(path) = matches.get_one::<PathBuf>("wallet") {
            let folder = matches
                .get_one::<String>("wallet_folder")
                .context("KWallet v11 recovery requires --wallet-folder")?;
            let entry = matches
                .get_one::<String>("wallet_entry")
                .context("KWallet v11 recovery requires --wallet-entry")?;
            let wallet_bytes = read_bounded(path, kwallet::MAX_INPUT_BYTES)?;
            let default_salt = path.with_extension("salt");
            let salt_path = matches.get_one::<PathBuf>("salt").unwrap_or(&default_salt);
            let salt = read_bounded(salt_path, kwallet::SALT_BYTES)?;
            let wallet = KWallet::parse(&wallet_bytes)?.unlock_password(&password, &salt, None)?;
            let storage = wallet.recover_password(folder, entry, None)?;
            let key = config.recover_linux(Some(storage.expose()), None)?;
            eprintln!(
                "recovery method: linux_v11_kwallet; entry index offset {}",
                storage.metadata().index_offset
            );
            key
        } else {
            let path = matches
                .get_one::<PathBuf>("keyring")
                .context("v11 recovery requires --keyring or --wallet")?;
            let keyring_bytes = read_bounded(path, gnome_keyring::MAX_INPUT_BYTES)?;
            let keyring = GnomeKeyring::parse(&keyring_bytes)?.unlock_password(&password, None)?;
            let attributes: Vec<_> = matches
                .get_many::<String>("attribute")
                .into_iter()
                .flatten()
                .map(|value| {
                    value
                        .split_once('=')
                        .context("attributes require NAME=VALUE")
                })
                .collect::<Result<_>>()?;
            let storage = keyring.recover_secret(&attributes, None)?;
            let key = config.recover_linux(Some(storage.expose()), None)?;
            eprintln!(
                "recovery method: linux_v11_gnome_keyring; item {}",
                storage.item_id()
            );
            key
        }
    } else {
        let key = config.recover_linux(None, None)?;
        eprintln!("recovery method: linux_v10_legacy_obfuscation");
        key
    };
    let registry = build_registry();
    let parser = registry
        .get("desktop_signal")
        .context("Signal parser is not registered")?;
    let source = input::local_input(&**parser, database, &[])?;
    let mut options = ParserOptions::default();
    options.insert_secret("database_key", key)?;
    let cipher_version = matches
        .get_one::<String>("cipher_version")
        .context("missing cipher version")?
        .parse::<i64>()?;
    options.insert(
        "cipher_version",
        exhume_artefacts::ParserOptionValue::Integer(cipher_version),
    )?;
    run_parser_with_options(
        &**parser,
        source,
        options,
        &mut |record| {
            println!("{}", record.json);
            Ok(())
        },
        &mut |issue| {
            eprintln!("{}", serde_json::to_string(&issue)?);
            Ok(())
        },
    )
}

fn main() -> std::process::ExitCode {
    cli::finish(run())
}

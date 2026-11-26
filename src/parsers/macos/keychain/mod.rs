//! macOS Keychain metadata and optional file-based password authentication.
//!
//! Handles both keychain formats found on macOS:
//! - **Legacy** `login.keychain-db` / `System.keychain` — the CSSM
//!   `AppleDatabase` binary format (magic `kych`). See [`legacy`].
//! - **Modern** `keychain-2.db` — a SQLite database used by `securityd`
//!   (`genp`/`inet`/`cert`/`keys` tables). See [`modern`].
//!
//! The optional `password` authenticates the database protection blob of a
//! file-based Keychain. Recovered secrets are available separately through
//! [`crate::formats::keychain`], never in artefact records. SQLite/SEP protection
//! is not unlocked by this parser.

pub(crate) mod legacy;
pub(crate) mod modern;

use crate::core::{
    CompanionSpec, ObjectParsed, Parser, ParserContext, ParserInput, ParserInputError, ParserIssue,
    ParserOptionSpec, ParserOptionType, ParserOptions,
};
use crate::formats::keychain::{KeychainError, LegacyKeychain, MAX_INPUT_BYTES};
use crate::formats::sqlite::SqliteEvidence;
use anyhow::{Context, Result, bail};
use std::fs;
use zeroize::Zeroizing;

const PARSER_NAME: &str = "macos_keychain";
const OPTIONS: &[ParserOptionSpec] = &[
    ParserOptionSpec {
        name: "password",
        label: "Keychain password",
        description: "Optional exact password bytes to authenticate a file-based Keychain; login Keychains may also need protected_entropy",
        value_type: ParserOptionType::Secret,
        required: false,
        default: None,
    },
    ParserOptionSpec {
        name: "protected_entropy",
        label: "Login Keychain protected entropy",
        description: "Optional 32-byte CFData value from the salt-matched SystemKeys plist, encoded as 64 hexadecimal characters; requires password and is never emitted",
        value_type: ParserOptionType::Secret,
        required: false,
        default: None,
    },
];

#[derive(Clone, Copy)]
pub(crate) enum Authentication {
    NotAttempted,
    DirectPassword,
    LoginPasswordProtectedEntropy,
}
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

/// Emitted object kind for every keychain item, both formats.
pub(crate) const KEYCHAIN_ITEM_KIND: &str = "macos.keychain.item";

#[derive(Default)]
pub struct MacosKeychainParser;

impl Parser for MacosKeychainParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse macOS Keychain metadata and optionally authenticate a file-based Keychain password; secrets are never emitted."
    }

    fn option_specs(&self) -> &'static [ParserOptionSpec] {
        OPTIONS
    }

    fn requires_source_metadata(&self) -> bool {
        true
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        self.run_into_with_diagnostics(input, sink, &mut |issue| {
            use std::io::Write;
            let mut stderr = std::io::stderr().lock();
            serde_json::to_writer(&mut stderr, &issue)?;
            writeln!(stderr)?;
            Ok(())
        })
    }

    fn run_into_with_diagnostics(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
    ) -> Result<()> {
        crate::run_parser_with_options(self, input, ParserOptions::default(), sink, diagnostic)
    }

    fn run_into_with_context(
        &self,
        input: ParserInput,
        context: &ParserContext,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
    ) -> Result<()> {
        if context.parser_name() != PARSER_NAME {
            return Err(ParserInputError::invalid("context", "parser context mismatch").into());
        }
        let entropy = context
            .secret("protected_entropy")
            .map(|encoded| {
                let mut bytes = Zeroizing::new([0; 32]);
                hex::decode_to_slice(encoded, bytes.as_mut()).map_err(|_| {
                    ParserInputError::invalid(
                        "protected_entropy",
                        "expected exactly 64 hexadecimal characters",
                    )
                })?;
                Ok::<_, ParserInputError>(bytes)
            })
            .transpose()?;
        if entropy.is_some() && context.secret("password").is_none() {
            return Err(context
                .request_input("password", crate::core::ParserInputReason::Missing)
                .into());
        }
        // Preserve WAL/SHM and indexed source identity for the SQLite path.
        // Each primary/companion copy is bounded to 64 MiB.
        let evidence = SqliteEvidence::from_input_bounded(input, "keychain", MAX_INPUT_BYTES)?;
        let header = read_header(evidence.path())?;

        if header.starts_with(b"kych") {
            let bytes = fs::read(evidence.path())?;
            let file = LegacyKeychain::parse(&bytes)
                .with_context(|| format!("failed to parse Keychain {}", evidence.source_label()))?;
            if let Some(password) = context.secret("password") {
                let authentication = if entropy.is_some() {
                    Authentication::LoginPasswordProtectedEntropy
                } else {
                    Authentication::DirectPassword
                };
                let result = match entropy.as_ref() {
                    Some(entropy) => file.unlock_login_password(password, entropy, None),
                    None => file.unlock_password(password, None),
                };
                let unlocked = result.with_context(|| {
                    format!(
                        "Keychain authentication failed for {}",
                        evidence.source_label()
                    )
                })?;
                legacy::parse(
                    unlocked.keychain(),
                    &evidence,
                    authentication,
                    sink,
                    diagnostic,
                )
            } else {
                legacy::parse(
                    &file,
                    &evidence,
                    Authentication::NotAttempted,
                    sink,
                    diagnostic,
                )
            }
        } else if header.starts_with(b"SQLite format 3\0") {
            if context.secret("password").is_some() {
                return Err(KeychainError::UnsupportedFormat.into());
            }
            modern::parse(&evidence, sink)
        } else {
            bail!("not a supported macOS keychain (unknown magic)");
        }
    }
}

fn read_header(path: &std::path::Path) -> Result<[u8; 16]> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut header = [0u8; 16];
    // A keychain is always larger than 16 bytes; a short read means it is not one.
    file.read_exact(&mut header)?;
    Ok(header)
}

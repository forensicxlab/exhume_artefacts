//! KDE KWallet metadata and optional password/checksum verification.

use crate::{
    CompanionSpec, ObjectParsed, Parser, ParserContext, ParserInput, ParserInputError, ParserIssue,
    ParserOptionSpec, ParserOptionType, ParserOptions,
    formats::kwallet::{KWallet, MAX_INPUT_BYTES, SALT_BYTES},
    input::file::FileEvidence,
};
use anyhow::{Context, Result};
use serde_json::json;

const NAME: &str = "linux_kwallet";
const SCHEMA: &str = "kwallet_0_1_blowfish_cbc_pbkdf2_sha512";
const COMPANIONS: &[CompanionSpec] = &[CompanionSpec::optional_extension("salt", "salt")];
const OPTIONS: &[ParserOptionSpec] = &[ParserOptionSpec {
    name: "password",
    label: "KWallet password",
    description: "Optional exact wallet password bytes. Requires the matching salt companion; decrypted entry metadata is emitted, secrets are never emitted",
    value_type: ParserOptionType::Secret,
    required: false,
    default: None,
}];

#[derive(Default)]
pub struct KWalletParser;
impl Parser for KWalletParser {
    fn name(&self) -> &'static str {
        NAME
    }
    fn description(&self) -> &'static str {
        "Parse modern KDE KWallet files and optionally verify password decoding with the matching salt; secrets remain in the recovery API."
    }
    fn option_specs(&self) -> &'static [ParserOptionSpec] {
        OPTIONS
    }
    fn companion_specs(&self) -> &'static [CompanionSpec] {
        COMPANIONS
    }
    fn requires_source_metadata(&self) -> bool {
        true
    }
    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        crate::run_parser_with_options(self, input, ParserOptions::default(), sink, &mut |_| Ok(()))
    }
    fn run_into_with_context(
        &self,
        input: ParserInput,
        context: &ParserContext,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        _diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
    ) -> Result<()> {
        if context.parser_name() != NAME {
            return Err(ParserInputError::invalid("context", "parser context mismatch").into());
        }
        let (evidence, salt) = FileEvidence::read_primary_with_companion_bounded(
            input,
            "salt",
            MAX_INPUT_BYTES,
            SALT_BYTES,
        )?;
        let wallet = KWallet::parse(&evidence.bytes)
            .with_context(|| format!("failed to parse KWallet {}", evidence.source_label))?;
        let unlocked = context
            .secret("password")
            .map(|password| {
                let salt = salt.as_deref().context(
                    "KWallet password verification requires the matching salt companion",
                )?;
                wallet
                    .unlock_password(password, salt, None)
                    .with_context(|| {
                        format!(
                            "KWallet password decoding failed for {}",
                            evidence.source_label
                        )
                    })
            })
            .transpose()?;
        let recovery = json!({
            "status": if unlocked.is_some() { "payload_sha1_verified" } else { "not_attempted" },
            "integrity": "encrypted_unkeyed_kwallet_sha1_checksum",
            "checksum_variant": "kde_legacy_little_endian_sha1",
            "outer_index_authenticated": false,
            "outer_index_matches_payload": unlocked.as_ref().map(|_| true),
        });
        sink(ObjectParsed {
            parser: NAME,
            kind: "linux.kwallet.wallet",
            text: "KWallet".to_string(),
            json: json!({
                "platform":"linux", "record_type":"kwallet",
                "source": evidence.source_json("wallet", 0, SCHEMA),
                "wallet": wallet.metadata(), "folder_count": wallet.indexed_folders().len(),
                "recovery": recovery,
            }),
        })?;
        if let Some(unlocked) = unlocked {
            for (index, entry) in unlocked.entries().enumerate() {
                sink(ObjectParsed {
                    parser: NAME,
                    kind: "linux.kwallet.entry",
                    text: format!("{} / {}", entry.folder, entry.name),
                    json: json!({
                        "platform":"linux", "record_type":"kwallet_entry",
                        "source":evidence.source_json("entry", i64::try_from(index)?, SCHEMA),
                        "entry":entry, "metadata_state":"decrypted", "recovery": recovery,
                    }),
                })?;
            }
        } else {
            for (index, folder) in wallet.indexed_folders().iter().enumerate() {
                sink(ObjectParsed {
                    parser: NAME,
                    kind: "linux.kwallet.folder",
                    text: folder.name_md5.clone(),
                    json: json!({
                        "platform":"linux", "record_type":"kwallet_folder",
                        "source":evidence.source_json("folder", i64::try_from(index)?, SCHEMA),
                        "folder":folder, "metadata_state":"hashed_index", "recovery": recovery,
                    }),
                })?;
            }
        }
        Ok(())
    }
}

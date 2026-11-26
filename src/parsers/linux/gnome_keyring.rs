//! GNOME binary Keyring metadata and optional password verification.

use crate::{
    ObjectParsed, Parser, ParserContext, ParserInput, ParserInputError, ParserIssue,
    ParserOptionSpec, ParserOptionType, ParserOptions,
    formats::gnome_keyring::{GnomeKeyring, MAX_INPUT_BYTES},
    input::file::FileEvidence,
};
use anyhow::{Context, Result};
use serde_json::json;

const NAME: &str = "linux_gnome_keyring";
const SCHEMA: &str = "gnome_keyring_binary_0_0";
const OPTIONS: &[ParserOptionSpec] = &[ParserOptionSpec {
    name: "password",
    label: "GNOME Keyring password",
    description: "Optional exact Keyring password bytes. Unlocks item metadata and checks the unkeyed payload MD5; recovered secrets are never emitted",
    value_type: ParserOptionType::Secret,
    required: false,
    default: None,
}];

#[derive(Default)]
pub struct GnomeKeyringParser;
impl Parser for GnomeKeyringParser {
    fn name(&self) -> &'static str {
        NAME
    }
    fn description(&self) -> &'static str {
        "Parse GNOME binary Keyring collections and optionally verify password decoding; secrets remain in the recovery API."
    }
    fn option_specs(&self) -> &'static [ParserOptionSpec] {
        OPTIONS
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
        let evidence = FileEvidence::read_primary_bounded(input, MAX_INPUT_BYTES)?;
        let keyring = GnomeKeyring::parse(&evidence.bytes)
            .with_context(|| format!("failed to parse GNOME Keyring {}", evidence.source_label))?;
        let unlocked = context
            .secret("password")
            .map(|password| keyring.unlock_password(password, None))
            .transpose()
            .with_context(|| {
                format!(
                    "GNOME Keyring password decoding failed for {}",
                    evidence.source_label
                )
            })?;
        let recovery = json!({
            "status": if unlocked.is_some() { "payload_md5_verified" } else { "not_attempted" },
            "integrity": "unkeyed_md5_checksum",
            "outer_index_authenticated": false,
        });
        sink(ObjectParsed {
            parser: NAME,
            kind: "linux.gnome_keyring.collection",
            text: keyring.metadata().display_name.clone().unwrap_or_default(),
            json: json!({
                "platform":"linux", "record_type":"gnome_keyring_collection",
                "source":evidence.source_json("keyring", 0, SCHEMA),
                "collection":keyring.metadata(), "item_count":keyring.indexed_items().len(),
                "recovery":recovery,
            }),
        })?;
        if let Some(unlocked) = unlocked {
            for item in unlocked.items() {
                sink(ObjectParsed {
                    parser: NAME,
                    kind: "linux.gnome_keyring.item",
                    text: item.display_name.clone().unwrap_or_default(),
                    json: json!({
                        "platform":"linux", "record_type":"gnome_keyring_item",
                        "source":evidence.source_json("item", i64::from(item.id), SCHEMA),
                        "item":item, "metadata_state":"decrypted", "recovery":recovery,
                    }),
                })?;
            }
        } else {
            for item in keyring.indexed_items() {
                sink(ObjectParsed {
                    parser: NAME,
                    kind: "linux.gnome_keyring.item",
                    text: item.id.to_string(),
                    json: json!({
                        "platform":"linux", "record_type":"gnome_keyring_item",
                        "source":evidence.source_json("item", i64::from(item.id), SCHEMA),
                        "item":item, "metadata_state":"hashed_index", "recovery":recovery,
                    }),
                })?;
            }
        }
        Ok(())
    }
}

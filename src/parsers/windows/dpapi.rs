//! DPAPI master-key metadata and optional local-password authentication.
//! Recovered keys stay in the library recovery API, never in artefact records.

use crate::core::{
    ObjectParsed, Parser, ParserContext, ParserInput, ParserInputError, ParserInputReason,
    ParserIssue, ParserOptionSpec, ParserOptionType, ParserOptionValue, ParserOptions,
};
use crate::formats::dpapi::{MAX_INPUT_BYTES, MasterKeyFile};
use crate::input::file::FileEvidence;
use anyhow::{Context, Result};
use serde_json::json;

const NAME: &str = "windows_dpapi_masterkey";
const OPTIONS: &[ParserOptionSpec] = &[
    ParserOptionSpec {
        name: "account_sid",
        label: "Windows account SID",
        description: "The account SID associated with this master-key file; required for password authentication",
        value_type: ParserOptionType::String,
        required: false,
        default: None,
    },
    ParserOptionSpec {
        name: "password",
        label: "Windows account password",
        description: "Optional exact UTF-8 local-account password. Keys and password are never emitted",
        value_type: ParserOptionType::Secret,
        required: false,
        default: None,
    },
];

#[derive(Default)]
pub struct WindowsDpapiMasterKeyParser;
impl Parser for WindowsDpapiMasterKeyParser {
    fn name(&self) -> &'static str {
        NAME
    }
    fn description(&self) -> &'static str {
        "Inspect DPAPI master-key files and optionally authenticate AES-256/SHA-512 protection with a local account password."
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
        let sid = match context.option("account_sid") {
            Some(ParserOptionValue::String(value)) => Some(value.as_str()),
            _ => None,
        };
        let password = context
            .secret("password")
            .map(|bytes| {
                std::str::from_utf8(bytes).map_err(|_| {
                    ParserInputError::invalid("password", "expected exact UTF-8 password bytes")
                })
            })
            .transpose()?;
        if password.is_some() && sid.is_none() {
            return Err(context
                .request_input("account_sid", ParserInputReason::Missing)
                .into());
        }
        let evidence = FileEvidence::read_primary_bounded(input, MAX_INPUT_BYTES)?;
        let file = MasterKeyFile::parse(&evidence.bytes).with_context(|| {
            format!(
                "failed to parse DPAPI master-key file {}",
                evidence.source_label
            )
        })?;
        let status = match (sid, password) {
            (Some(sid), Some(password)) => {
                let _key = file
                    .unlock_local_password(sid, password, None)
                    .with_context(|| {
                        format!("DPAPI authentication failed for {}", evidence.source_label)
                    })?;
                "authenticated"
            }
            _ => "not_attempted",
        };
        let metadata = file.metadata();
        sink(ObjectParsed {
            parser: NAME,
            kind: "windows.dpapi.master_key",
            text: metadata.guid.clone(),
            json: json!({
                "platform":"windows", "record_type":"dpapi_master_key",
                "source":evidence.source_json("master_key_file", 0, "windows_dpapi_masterkey_v1"),
                "master_key":metadata,
                "recovery":{"status":status,"method":if password.is_some() { Some("local_password_sha1") } else { None }},
            }),
        })
    }
}

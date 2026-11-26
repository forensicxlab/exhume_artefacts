//! File-based CSSM Keychain metadata. Structural validation and authentication
//! belong to `formats::keychain`; this adapter emits no recovered secrets.

use super::{Authentication, KEYCHAIN_ITEM_KIND, PARSER_NAME};
use crate::core::{ObjectParsed, ParserIssue, ParserIssueCode};
use crate::formats::keychain::LegacyKeychain;
use crate::formats::keychain::database::{GENERIC_HEADER_BYTES, Record};
use crate::formats::sqlite::{SqliteEvidence, sqlite_source_json};
use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use serde_json::{Value, json};

const SCHEMA_VARIANT: &str = "macos_legacy_keychain_cssm_v1";
const RECORD_GENERIC_PASSWORD: u32 = 0x8000_0000;
const RECORD_INTERNET_PASSWORD: u32 = 0x8000_0001;
const RECORD_APPLESHARE_PASSWORD: u32 = 0x8000_0002;
// 0x80008000 is database protection metadata, not a certificate table.
const RECORD_X509_CERTIFICATE: u32 = 0x8000_1000;
const RECORD_PUBLIC_KEY: u32 = 0x0000_000F;
const RECORD_PRIVATE_KEY: u32 = 0x0000_0010;
const RECORD_SYMMETRIC_KEY: u32 = 0x0000_0011;

pub(crate) fn parse(
    file: &LegacyKeychain<'_>,
    evidence: &SqliteEvidence,
    authentication: Authentication,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
) -> Result<()> {
    let mut index = 0i64;
    for table in &file.tables {
        let password_layout = match table.id {
            RECORD_GENERIC_PASSWORD => Some(("generic_password", &GENERIC)),
            RECORD_INTERNET_PASSWORD => Some(("internet_password", &INTERNET)),
            RECORD_APPLESHARE_PASSWORD => Some(("internet_password", &APPLESHARE)),
            _ => None,
        };
        if let Some((class, layout)) = password_layout {
            for record in &table.records {
                match password_object(record, evidence, class, layout, index, authentication) {
                    Ok(object) => sink(object)?,
                    Err(error) => diagnostic(ParserIssue {
                        code: ParserIssueCode::RecordParse,
                        unit: Some(record.section.offset as u64),
                        message: format!(
                            "{}: CSSM table {:#x}, record {}, byte {}: {error:#}",
                            evidence.source_label(),
                            table.id,
                            record.number,
                            record.section.offset
                        ),
                    })?,
                }
                index += 1;
            }
        } else if !table.records.is_empty() {
            let class = match table.id {
                RECORD_X509_CERTIFICATE => "certificate",
                RECORD_PUBLIC_KEY => "public_key",
                RECORD_PRIVATE_KEY => "private_key",
                RECORD_SYMMETRIC_KEY => "symmetric_key",
                _ => continue,
            };
            let mut source = sqlite_source_json(evidence, class, index, SCHEMA_VARIANT);
            source["byte_offset"] = json!(table.offset);
            sink(ObjectParsed {
                parser: PARSER_NAME,
                kind: KEYCHAIN_ITEM_KIND,
                text: format!("{class}: {} record(s)", table.records.len()),
                json: json!({
                    "platform": "macos", "app": "keychain",
                    "record_type": "keychain_table_summary", "format": "keychain-db", "class": class,
                    "source": source,
                    "summary": {"table_id": format!("0x{:08x}", table.id), "record_count": table.records.len()},
                    "recovery": recovery_json(authentication),
                }),
            })?;
            index += 1;
        }
    }
    Ok(())
}

struct PasswordLayout {
    header_size: usize,
    service_or_server: usize,
    protocol: usize,
    path: usize,
    port: usize,
}
const GENERIC: PasswordLayout = PasswordLayout {
    header_size: GENERIC_HEADER_BYTES,
    service_or_server: 14,
    protocol: usize::MAX,
    path: usize::MAX,
    port: usize::MAX,
};
const INTERNET: PasswordLayout = PasswordLayout {
    header_size: 104,
    service_or_server: 15,
    protocol: 16,
    path: 19,
    port: 18,
};
const APPLESHARE: PasswordLayout = PasswordLayout {
    header_size: 104,
    service_or_server: 15,
    protocol: 16,
    path: usize::MAX,
    port: usize::MAX,
};

fn recovery_json(authentication: Authentication) -> Value {
    let method = match authentication {
        Authentication::NotAttempted => None,
        Authentication::DirectPassword => Some("direct_password"),
        Authentication::LoginPasswordProtectedEntropy => Some("login_password_protected_entropy"),
    };
    json!({"status": if method.is_some() { "database_keys_authenticated" } else { "not_attempted" }, "method": method, "scope": "database_blob_only", "item_payload_authenticated": false})
}

fn password_object(
    record: &Record<'_>,
    evidence: &SqliteEvidence,
    class: &str,
    layout: &PasswordLayout,
    index: i64,
    authentication: Authentication,
) -> Result<ObjectParsed> {
    record.data(layout.header_size)?;
    let account = string_attr(record, layout, 13)?;
    let service = string_attr(record, layout, layout.service_or_server)?;
    let text = service
        .clone()
        .or_else(|| account.clone())
        .unwrap_or_default();
    let mut item = json!({
        "account": account,
        "label": string_attr(record, layout, 7)?,
        "description": string_attr(record, layout, 2)?,
        "comment": string_attr(record, layout, 3)?,
    });
    if class == "internet_password" {
        item["server"] = json!(service);
        item["protocol"] = match record.value(layout.protocol, layout.header_size)? {
            Some(value) => json!(
                std::str::from_utf8(value.part(0, 4, "protocol code")?.bytes)
                    .context("invalid protocol code")?
            ),
            None => Value::Null,
        };
        item["path"] = json!(string_attr(record, layout, layout.path)?);
        item["port"] = if layout.port == usize::MAX {
            Value::Null
        } else {
            match record.value(layout.port, layout.header_size)? {
                Some(value) => json!(value.u32(0, "integer attribute")?),
                None => Value::Null,
            }
        };
    } else {
        item["service"] = json!(service);
    }
    let mut source = sqlite_source_json(evidence, class, index, SCHEMA_VARIANT);
    source["byte_offset"] = json!(record.section.offset);
    source["record_number"] = json!(record.number);
    Ok(ObjectParsed {
        parser: PARSER_NAME,
        kind: KEYCHAIN_ITEM_KIND,
        text,
        json: json!({
            "platform": "macos", "app": "keychain", "record_type": "keychain_item",
            "format": "keychain-db", "class": class, "source": source,
            "timestamps": {
                "created": cssm_time_to_json(date_attr(record, layout, 0)?),
                "modified": cssm_time_to_json(date_attr(record, layout, 1)?),
            },
            "item": item,
            "recovery": recovery_json(authentication),
        }),
    })
}

fn string_attr(
    record: &Record<'_>,
    layout: &PasswordLayout,
    index: usize,
) -> Result<Option<String>> {
    if index == usize::MAX {
        return Ok(None);
    }
    let Some(value) = record.blob_attribute(index, layout.header_size)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(value.bytes)
        .context("invalid UTF-8 attribute")?
        .trim_end_matches('\0');
    Ok((!text.is_empty()).then(|| text.to_owned()))
}

fn date_attr(record: &Record<'_>, layout: &PasswordLayout, index: usize) -> Result<Option<String>> {
    record
        .value(index, layout.header_size)?
        .map(|value| {
            let bytes = value.part(0, 16, "CSSM date")?.bytes;
            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            Ok(std::str::from_utf8(&bytes[..end])
                .context("invalid UTF-8 date")?
                .to_owned())
        })
        .transpose()
}

/// Parse a CSSM `YYYYMMDDhhmmssZ` (Zulu/UTC) timestamp into the shared JSON
/// timestamp shape.
fn cssm_time_to_json(value: Option<String>) -> Value {
    let Some(text) = value else {
        return Value::Null;
    };
    let digits = text.trim_end_matches('Z');
    if digits.len() < 14 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Value::Null;
    }
    let parse = |a: usize, b: usize| digits[a..b].parse::<u32>().ok();
    let (Some(y), Some(mo), Some(da), Some(h), Some(mi), Some(s)) = (
        parse(0, 4),
        parse(4, 6),
        parse(6, 8),
        parse(8, 10),
        parse(10, 12),
        parse(12, 14),
    ) else {
        return Value::Null;
    };
    let Some(dt) = Utc.with_ymd_and_hms(y as i32, mo, da, h, mi, s).single() else {
        return Value::Null;
    };
    json!({
        "original": text,
        "original_epoch": "cssm_zulu",
        "unix_ms": dt.timestamp_millis(),
        "rfc3339": dt.to_rfc3339(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cssm_zulu_time() {
        let ts = cssm_time_to_json(Some("20240721061320Z".to_string()));
        assert_eq!(ts["rfc3339"], "2024-07-21T06:13:20+00:00");
        assert_eq!(ts["original_epoch"], "cssm_zulu");
    }

    #[test]
    fn rejects_bad_time() {
        assert!(cssm_time_to_json(Some("not-a-date".to_string())).is_null());
        assert!(cssm_time_to_json(None).is_null());
    }
}

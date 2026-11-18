//! Generic (non-SQLite) parser input reader.
//!
//! The SQLite parsers use [`crate::formats::sqlite::SqliteEvidence`],
//! which materializes a temp DB. Parsers of plist and binary formats
//! only need the primary file's bytes plus provenance, so this reads any
//! [`ParserInput`] into memory and records the source files for the `source`
//! block.

use crate::core::{ParserInput, ParserSource};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};

/// One source file described in a parser's provenance block.
#[derive(Debug, Clone)]
pub(crate) struct FileRef {
    pub role: String,
    pub path: String,
    pub artifact_id: Option<i64>,
    pub system_file_id: Option<i64>,
    pub fs_identifier: Option<u64>,
}

impl FileRef {
    fn primary(path: String) -> Self {
        Self {
            role: "primary".to_string(),
            path,
            artifact_id: None,
            system_file_id: None,
            fs_identifier: None,
        }
    }

    fn from_source(source: &ParserSource) -> Self {
        Self {
            role: source.role.clone(),
            path: source.original_path.clone(),
            artifact_id: source.artifact_id,
            system_file_id: source.system_file_id,
            fs_identifier: source.fs_identifier,
        }
    }
}

/// The primary file's bytes plus provenance, read from any input variant.
pub(crate) struct FileEvidence {
    pub bytes: Vec<u8>,
    pub source_label: String,
    pub source_files: Vec<FileRef>,
}

impl FileEvidence {
    /// Read only the primary input with an enforced byte limit, including
    /// provider-backed inputs whose length is not known before copying.
    pub(crate) fn read_primary_bounded(input: ParserInput, maximum: usize) -> Result<Self> {
        let (bytes, source_label, source_files) = match input {
            ParserInput::Path(path) => {
                let label = path.display().to_string();
                let mut file =
                    fs::File::open(&path).with_context(|| format!("failed to open {label}"))?;
                let bytes = bounded_read(&mut file, maximum)?;
                (bytes, label.clone(), vec![FileRef::primary(label)])
            }
            ParserInput::Bytes(bytes) => {
                if bytes.len() > maximum {
                    anyhow::bail!("primary input exceeds {maximum} bytes");
                }
                (
                    bytes,
                    "<in-memory>".to_string(),
                    vec![FileRef::primary("<in-memory>".to_string())],
                )
            }
            ParserInput::ReadSeek(mut reader) => {
                reader.seek(SeekFrom::Start(0))?;
                let bytes = bounded_read(&mut reader, maximum)?;
                (
                    bytes,
                    "<stream>".to_string(),
                    vec![FileRef::primary("<stream>".to_string())],
                )
            }
            ParserInput::Compound(mut compound) => {
                let mut writer = LimitedBytes {
                    bytes: Vec::new(),
                    maximum,
                };
                compound
                    .provider
                    .copy_to(&compound.primary, &mut writer)
                    .context("failed to read bounded primary compound input")?;
                let files = vec![FileRef::from_source(&compound.primary)];
                (writer.bytes, compound.primary.original_path, files)
            }
        };
        Ok(Self {
            bytes,
            source_label,
            source_files,
        })
    }

    pub(crate) fn read_primary(input: ParserInput) -> Result<Self> {
        match input {
            ParserInput::Path(path) => {
                let bytes = fs::read(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                let label = path.display().to_string();
                Ok(Self {
                    bytes,
                    source_files: vec![FileRef::primary(label.clone())],
                    source_label: label,
                })
            }
            ParserInput::Bytes(bytes) => Ok(Self {
                bytes,
                source_label: "<in-memory>".to_string(),
                source_files: vec![FileRef::primary("<in-memory>".to_string())],
            }),
            ParserInput::ReadSeek(mut reader) => {
                let mut bytes = Vec::new();
                reader.seek(SeekFrom::Start(0))?;
                reader.read_to_end(&mut bytes)?;
                Ok(Self {
                    bytes,
                    source_label: "<stream>".to_string(),
                    source_files: vec![FileRef::primary("<stream>".to_string())],
                })
            }
            ParserInput::Compound(mut compound) => {
                let mut bytes = Vec::new();
                compound
                    .provider
                    .copy_to(&compound.primary, &mut bytes)
                    .context("failed to read primary compound input")?;
                let mut source_files = vec![FileRef::from_source(&compound.primary)];
                source_files.extend(compound.companions.iter().map(FileRef::from_source));
                Ok(Self {
                    bytes,
                    source_label: compound.primary.original_path.clone(),
                    source_files,
                })
            }
        }
    }

    /// The `files` provenance array for the `source` block.
    pub(crate) fn source_files_json(&self) -> Value {
        Value::Array(
            self.source_files
                .iter()
                .map(|file| {
                    json!({
                        "role": &file.role,
                        "path": &file.path,
                        "artifact_id": file.artifact_id,
                        "system_file_id": file.system_file_id,
                        "fs_identifier": file.fs_identifier,
                    })
                })
                .collect(),
        )
    }

    /// Uniform provenance block for a record emitted from a file-backed artefact.
    pub(crate) fn source_json(&self, record: &str, index: i64, schema_variant: &str) -> Value {
        json!({
            "path": self.source_label,
            "record": record,
            "index": index,
            "schema_variant": schema_variant,
            "parser_confidence": "compatible_schema",
            "files": self.source_files_json(),
        })
    }
}

fn bounded_read(reader: &mut dyn Read, maximum: usize) -> Result<Vec<u8>> {
    let limit = u64::try_from(maximum)?
        .checked_add(1)
        .context("input limit overflow")?;
    let mut bytes = Vec::new();
    reader.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        anyhow::bail!("primary input exceeds {maximum} bytes");
    }
    Ok(bytes)
}

struct LimitedBytes {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Write for LimitedBytes {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(buffer.len())
            .is_none_or(|length| length > self.maximum)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "primary input exceeds parser byte limit",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

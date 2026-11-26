//! Shared asset recipes, verified publication and cache validation. Format-specific
//! cryptography remains with the parser that declares a recipe.
use crate::core::ReadSeek;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rendition {
    Original,
    Thumbnail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetErrorCode {
    MissingMetadata,
    InvalidKey,
    UnsupportedVersion,
    Malformed,
    AuthenticationFailed,
    SizeMismatch,
    HashMismatch,
    LimitExceeded,
    Cancelled,
    Io,
    UnsafeDestination,
}

#[derive(Debug)]
pub struct AssetError {
    pub code: AssetErrorCode,
}
impl fmt::Display for AssetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.code {
            AssetErrorCode::MissingMetadata => "Asset metadata is missing",
            AssetErrorCode::InvalidKey => "Asset key is malformed or missing",
            AssetErrorCode::UnsupportedVersion => "Unsupported asset version",
            AssetErrorCode::Malformed => "Asset framing or padding is malformed",
            AssetErrorCode::AuthenticationFailed => "Asset authentication failed",
            AssetErrorCode::SizeMismatch => "Asset size does not match its metadata",
            AssetErrorCode::HashMismatch => "Asset plaintext hash does not match",
            AssetErrorCode::LimitExceeded => "Asset recovery exceeds its byte limit",
            AssetErrorCode::Cancelled => "Asset recovery cancelled",
            AssetErrorCode::Io => "Asset input or output is unavailable",
            AssetErrorCode::UnsafeDestination => "asset destination overlaps evidence or is unsafe",
        })
    }
}
impl std::error::Error for AssetError {}
impl From<std::io::Error> for AssetError {
    fn from(_: std::io::Error) -> Self {
        failure(AssetErrorCode::Io)
    }
}
pub type Result<T> = std::result::Result<T, AssetError>;
pub(crate) fn failure(code: AssetErrorCode) -> AssetError {
    AssetError { code }
}
pub(crate) fn check(cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        Err(failure(AssetErrorCode::Cancelled))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetProof {
    pub source_sha256: String,
    pub plaintext_sha256: String,
    pub plaintext_size: u64,
    pub authentication: String,
    pub metadata_hash_checked: bool,
}

/// A parser-owned decoding recipe. It contains no host filesystem authority.
pub trait AssetRecipe: fmt::Debug + Send + Sync {
    fn local_path(&self) -> &str;
    fn mime(&self) -> Option<&str>;
    fn plaintext_size(&self) -> Option<u64>;
    fn fingerprint(&self) -> String;
    /// Optional directory beneath the parser's asset root. Local paths must
    /// remain inside this directory.
    fn base_directory(&self) -> Option<&str> {
        None
    }
    fn recover(
        &self,
        input: &mut dyn ReadSeek,
        output: &mut dyn Write,
        maximum: u64,
        cancel: Option<&AtomicBool>,
    ) -> Result<AssetProof>;
}

/// Already-plain acquired media. A content hash is observed, not represented as
/// cryptographic authentication when the application supplies no expected hash.
#[derive(Debug)]
pub struct PlaintextSpec {
    path: String,
    mime: Option<String>,
    size: Option<u64>,
}
impl PlaintextSpec {
    pub fn from_record(record: &Value, rendition: Rendition) -> Result<Self> {
        let attachment = &record["attachment"];
        let path = match rendition {
            Rendition::Original => attachment["local_path"]
                .as_str()
                .or_else(|| record["media"]["local_path"].as_str()),
            Rendition::Thumbnail => attachment["thumbnail_path"].as_str(),
        }
        .filter(|path| !path.is_empty() && path.len() <= 32768)
        .ok_or_else(|| failure(AssetErrorCode::MissingMetadata))?;
        let mime = attachment["mime"]
            .as_str()
            .filter(|mime| mime.len() <= 512)
            .map(str::to_owned);
        let size = if rendition == Rendition::Original {
            record["media"]["file_size"]
                .as_u64()
                .or_else(|| record["details"]["media"]["file_size"].as_u64())
        } else {
            None
        };
        Ok(Self {
            path: path.into(),
            mime,
            size,
        })
    }
}
impl AssetRecipe for PlaintextSpec {
    fn local_path(&self) -> &str {
        &self.path
    }
    fn mime(&self) -> Option<&str> {
        self.mime.as_deref()
    }
    fn plaintext_size(&self) -> Option<u64> {
        self.size
    }
    fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(
            serde_json::json!(["plaintext-v1", self.path, self.size, self.mime])
                .to_string()
                .as_bytes(),
        ))
    }
    fn recover(
        &self,
        input: &mut dyn ReadSeek,
        output: &mut dyn Write,
        maximum: u64,
        cancel: Option<&AtomicBool>,
    ) -> Result<AssetProof> {
        check(cancel)?;
        let length = input.seek(SeekFrom::End(0))?;
        if maximum == 0 || length > maximum {
            return Err(failure(AssetErrorCode::LimitExceeded));
        }
        if self.size.is_some_and(|size| size != length) {
            return Err(failure(AssetErrorCode::SizeMismatch));
        }
        input.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut written = 0u64;
        let mut buffer = Zeroizing::new(vec![0; 64 * 1024]);
        loop {
            check(cancel)?;
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            written = written
                .checked_add(n as u64)
                .ok_or_else(|| failure(AssetErrorCode::LimitExceeded))?;
            if written > maximum {
                return Err(failure(AssetErrorCode::LimitExceeded));
            }
            output.write_all(&buffer[..n])?;
            hash.update(&buffer[..n]);
        }
        if written != length {
            return Err(failure(AssetErrorCode::SizeMismatch));
        }
        check(cancel)?;
        let digest = hex::encode(hash.finalize());
        Ok(AssetProof {
            source_sha256: digest.clone(),
            plaintext_sha256: digest,
            plaintext_size: written,
            authentication: "plaintext".into(),
            metadata_hash_checked: false,
        })
    }
}

/// Resolve beneath the explicitly chosen source root, refusing traversal and
/// symlinks that escape it. Absolute acquired paths must also lie within it.
pub fn local_asset_path(source_root: &Path, recipe: &dyn AssetRecipe) -> Result<PathBuf> {
    let protected = source_root.canonicalize()?;
    let root = match recipe.base_directory() {
        Some(base) => protected.join(base).canonicalize()?,
        None => protected.clone(),
    };
    if !root.starts_with(&protected) {
        return Err(failure(AssetErrorCode::MissingMetadata));
    }
    let normalized = recipe.local_path().replace('\\', "/");
    let relative = Path::new(&normalized);
    if relative.components().any(|part| {
        matches!(
            part,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(failure(AssetErrorCode::MissingMetadata));
    }
    let file = if relative.is_absolute() {
        relative.to_path_buf()
    } else {
        root.join(relative)
    }
    .canonicalize()?;
    if !file.starts_with(root) || !file.is_file() {
        return Err(failure(AssetErrorCode::MissingMetadata));
    }
    Ok(file)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpedAsset {
    pub relative_path: String,
    pub proof: AssetProof,
}

/// Create a caller-selected output directory with private Unix permissions.
/// Existing directories retain their caller-configured permissions.
pub fn create_dump_directory(directory: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory)?;
    Ok(())
}

/// The caller owns/protects this output directory and must exclude acquired
/// evidence roots. File names never incorporate an evidence-supplied filename.
/// Failed/cancelled attempts remove their private temporary plaintext file.
pub fn dump_asset(
    input: &mut dyn ReadSeek,
    spec: &dyn AssetRecipe,
    directory: &Path,
    maximum: u64,
    cancel: Option<&AtomicBool>,
) -> Result<DumpedAsset> {
    check(cancel)?;
    create_dump_directory(directory)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".asset-")
        .tempfile_in(directory)?;
    let proof = spec.recover(input, temporary.as_file_mut(), maximum, cancel)?;
    temporary.as_file_mut().sync_all()?;
    check(cancel)?;
    let suffix = temporary
        .path()
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| failure(AssetErrorCode::UnsafeDestination))?
        .trim_start_matches('.');
    let relative_path = format!("{}-{suffix}", proof.plaintext_sha256);
    temporary
        .persist_noclobber(directory.join(&relative_path))
        .map_err(|_| failure(AssetErrorCode::Io))?;
    Ok(DumpedAsset {
        relative_path,
        proof,
    })
}

/// Reopen and verify a cached file before serving it. Restrict paths to one
/// generated filename and retain the verified handle, not a caller's host path.
pub fn open_dumped_asset(
    directory: &Path,
    asset: &DumpedAsset,
    cancel: Option<&AtomicBool>,
) -> Result<File> {
    let name = Path::new(&asset.relative_path);
    if name.components().count() != 1
        || !matches!(name.components().next(), Some(Component::Normal(_)))
    {
        return Err(failure(AssetErrorCode::UnsafeDestination));
    }
    let path = directory.join(name);
    if fs::symlink_metadata(&path)?.file_type().is_symlink() {
        return Err(failure(AssetErrorCode::UnsafeDestination));
    }
    let mut file = File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() != asset.proof.plaintext_size {
        return Err(failure(AssetErrorCode::HashMismatch));
    }
    let mut digest = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0; 64 * 1024]);
    loop {
        check(cancel)?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if hex::encode(digest.finalize()) != asset.proof.plaintext_sha256 {
        return Err(failure(AssetErrorCode::HashMismatch));
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// Validate before creating any directories: dumping below an acquired source
/// directory would mutate folder evidence even when no source is overwritten.
pub fn validate_dump_destination(source_root: &Path, destination: &Path) -> Result<()> {
    let protected = source_root.canonicalize()?;
    let absolute = if destination.is_absolute() {
        destination.to_path_buf()
    } else {
        std::env::current_dir()?.join(destination)
    };
    if absolute
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(failure(AssetErrorCode::UnsafeDestination));
    }
    let mut ancestor = absolute.as_path();
    let mut missing = Vec::new();
    while !ancestor.try_exists()? {
        missing.push(
            ancestor
                .file_name()
                .ok_or_else(|| failure(AssetErrorCode::UnsafeDestination))?
                .to_owned(),
        );
        ancestor = ancestor
            .parent()
            .ok_or_else(|| failure(AssetErrorCode::UnsafeDestination))?;
    }
    let mut resolved = ancestor.canonicalize()?;
    for part in missing.into_iter().rev() {
        resolved.push(part);
    }
    if resolved.starts_with(protected) {
        return Err(failure(AssetErrorCode::UnsafeDestination));
    }
    Ok(())
}

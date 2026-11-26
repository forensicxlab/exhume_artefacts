//! Signal local attachment metadata and authenticated decoding.
use crate::{
    ParserSecret,
    assets::{AssetError, AssetErrorCode, AssetProof, Rendition, Result, check, failure},
    core::ReadSeek,
};
use aes::cipher::{Block, BlockDecrypt, KeyInit};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    io::{SeekFrom, Write},
    sync::atomic::AtomicBool,
};
use zeroize::Zeroizing;
/// A normalized recipe from a standalone `mobile.communication.attachment`
/// record. Local keys are redacted and zeroized; transit `key`/`digest` fields
/// are deliberately not substituted for the local encryption metadata.
#[derive(Debug)]
pub struct AttachmentSpec {
    pub local_path: String,
    pub mime: Option<String>,
    size: Option<u64>,
    hash: Option<[u8; 32]>,
    key: Option<ParserSecret>,
}
impl AttachmentSpec {
    pub fn plaintext_size(&self) -> Option<u64> {
        self.size
    }
    pub fn from_record(record: &Value, rendition: Rendition) -> Result<Self> {
        let details = &record["details"];
        let inline = &details["inline_json"];
        let text = |value: &Value| value.as_str().filter(|s| !s.is_empty()).map(str::to_owned);
        let (path, key, size, hash, version, mime) = match rendition {
            Rendition::Original => (
                text(&record["attachment"]["local_path"])
                    .or_else(|| text(&record["media"]["local_path"])),
                text(&details["local_key"]),
                details
                    .get("size")
                    .or_else(|| record["media"].get("file_size")),
                text(&details["plaintext_hash"]),
                details.get("version").or_else(|| inline.get("version")),
                text(&record["attachment"]["mime"]),
            ),
            Rendition::Thumbnail => (
                text(&record["attachment"]["thumbnail_path"])
                    .or_else(|| text(&inline["thumbnail"]["path"])),
                text(&details["thumbnail_local_key"])
                    .or_else(|| text(&inline["thumbnail"]["localKey"])),
                details
                    .get("thumbnail_size")
                    .or_else(|| inline["thumbnail"].get("size")),
                text(&inline["thumbnail"]["plaintextHash"]),
                details
                    .get("thumbnail_version")
                    .or_else(|| inline["thumbnail"].get("version")),
                text(&details["thumbnail_content_type"])
                    .or_else(|| text(&inline["thumbnail"]["contentType"])),
            ),
        };
        let local_path = path.ok_or_else(|| failure(AssetErrorCode::MissingMetadata))?;
        if local_path.len() > 32768 || mime.as_ref().is_some_and(|value| value.len() > 512) {
            return Err(failure(AssetErrorCode::MissingMetadata));
        }
        let size = size
            .filter(|v| !v.is_null())
            .map(|v| {
                v.as_u64()
                    .ok_or_else(|| failure(AssetErrorCode::MissingMetadata))
            })
            .transpose()?;
        let version = version
            .filter(|v| !v.is_null())
            .map(|v| {
                v.as_u64()
                    .ok_or_else(|| failure(AssetErrorCode::UnsupportedVersion))
            })
            .transpose()?;
        if version.is_some_and(|v| !matches!(v, 1 | 2)) {
            return Err(failure(AssetErrorCode::UnsupportedVersion));
        }
        if version == Some(2) && key.is_none() {
            return Err(failure(AssetErrorCode::InvalidKey));
        }
        let key = key
            .map(|value| {
                if value.len() > 128 {
                    return Err(failure(AssetErrorCode::InvalidKey));
                }
                let decoded = Zeroizing::new(
                    STANDARD
                        .decode(value)
                        .map_err(|_| failure(AssetErrorCode::InvalidKey))?,
                );
                if decoded.len() != 64 {
                    return Err(failure(AssetErrorCode::InvalidKey));
                }
                Ok(ParserSecret::new(decoded.to_vec()))
            })
            .transpose()?;
        if key.is_some() && size.is_none() {
            return Err(failure(AssetErrorCode::MissingMetadata));
        }
        let hash = hash
            .map(|value| {
                let mut bytes = [0; 32];
                hex::decode_to_slice(value, &mut bytes)
                    .map_err(|_| failure(AssetErrorCode::MissingMetadata))?;
                Ok::<_, AssetError>(bytes)
            })
            .transpose()?;
        Ok(Self {
            local_path,
            mime,
            size,
            hash,
            key,
        })
    }
    /// Stable cache discriminator; never exposes the attachment key itself.
    pub fn fingerprint(&self) -> String {
        let recipe = serde_json::json!([
            "signal-local-attachment-v1",
            self.local_path,
            self.size,
            self.hash.map(hex::encode),
            self.key
                .as_ref()
                .map(|key| hex::encode(Sha256::digest(key.expose()))),
            self.mime
        ]);
        hex::encode(Sha256::digest(recipe.to_string().as_bytes()))
    }
}

/// Decode into an unpublished destination. A caller-supplied writer can contain
/// partial plaintext on failure; use `crate::assets::dump_asset` for atomic publication.
/// Encrypted input is authenticated in full before any plaintext is written,
/// and authenticated again while decoding to detect changes between passes.
pub fn recover_attachment(
    input: &mut dyn ReadSeek,
    output: &mut dyn Write,
    spec: &AttachmentSpec,
    maximum: u64,
    cancel: Option<&AtomicBool>,
) -> Result<AssetProof> {
    check(cancel)?;
    let length = input.seek(SeekFrom::End(0))?;
    if maximum == 0 || length > maximum || spec.size.is_some_and(|size| size > maximum) {
        return Err(failure(AssetErrorCode::LimitExceeded));
    }
    input.seek(SeekFrom::Start(0))?;
    let mut buffer = Zeroizing::new(vec![0; 64 * 1024]);
    let mut source_hash = Sha256::new();
    let mut plain_hash = Sha256::new();
    let mut written = 0u64;
    let authentication;
    if let Some(key) = &spec.key {
        if length < 64 || (length - 48) % 16 != 0 {
            return Err(failure(AssetErrorCode::Malformed));
        }
        let ciphertext_len = length - 48;
        let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&key.expose()[32..])
            .map_err(|_| failure(AssetErrorCode::InvalidKey))?;
        let mut remaining = length - 32;
        while remaining > 0 {
            check(cancel)?;
            let count = remaining.min(buffer.len() as u64) as usize;
            input.read_exact(&mut buffer[..count])?;
            hmac.update(&buffer[..count]);
            source_hash.update(&buffer[..count]);
            remaining -= count as u64;
        }
        let mut tag = [0; 32];
        input.read_exact(&mut tag)?;
        source_hash.update(tag);
        hmac.verify_slice(&tag)
            .map_err(|_| failure(AssetErrorCode::AuthenticationFailed))?;
        input.seek(SeekFrom::Start(0))?;
        let mut previous = Zeroizing::new([0u8; 16]);
        input.read_exact(&mut *previous)?;
        let mut decoded_mac = <Hmac<Sha256> as Mac>::new_from_slice(&key.expose()[32..])
            .map_err(|_| failure(AssetErrorCode::InvalidKey))?;
        decoded_mac.update(&*previous);
        let aes = aes::Aes256::new_from_slice(&key.expose()[..32])
            .map_err(|_| failure(AssetErrorCode::InvalidKey))?;
        let target = spec
            .size
            .ok_or_else(|| failure(AssetErrorCode::MissingMetadata))?;
        let mut remaining = ciphertext_len;
        let mut unpadded_len = ciphertext_len;
        while remaining > 0 {
            check(cancel)?;
            let count = remaining.min(buffer.len() as u64) as usize;
            input.read_exact(&mut buffer[..count])?;
            decoded_mac.update(&buffer[..count]);
            for chunk in buffer[..count].as_chunks_mut::<16>().0 {
                let ciphertext = *chunk;
                let mut block = Block::<aes::Aes256>::default();
                block.copy_from_slice(chunk);
                aes.decrypt_block(&mut block);
                for i in 0..16 {
                    chunk[i] = block[i] ^ previous[i];
                }
                previous.copy_from_slice(&ciphertext);
            }
            remaining -= count as u64;
            if remaining == 0 {
                let padding = usize::from(buffer[count - 1]);
                if padding == 0
                    || padding > 16
                    || buffer[count - padding..count]
                        .iter()
                        .any(|v| usize::from(*v) != padding)
                {
                    return Err(failure(AssetErrorCode::Malformed));
                }
                unpadded_len -= padding as u64;
            }
            let take = target.saturating_sub(written).min(count as u64) as usize;
            output.write_all(&buffer[..take])?;
            plain_hash.update(&buffer[..take]);
            written += take as u64;
        }
        let mut decoded_tag = [0; 32];
        input.read_exact(&mut decoded_tag)?;
        if tag != decoded_tag || input.seek(SeekFrom::End(0))? != length {
            return Err(failure(AssetErrorCode::AuthenticationFailed));
        }
        decoded_mac
            .verify_slice(&tag)
            .map_err(|_| failure(AssetErrorCode::AuthenticationFailed))?;
        if written != target || target > unpadded_len {
            return Err(failure(AssetErrorCode::SizeMismatch));
        }
        authentication = "hmac_sha256";
    } else {
        if spec.size.is_some_and(|size| size != length) {
            return Err(failure(AssetErrorCode::SizeMismatch));
        }
        loop {
            check(cancel)?;
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            written = written
                .checked_add(count as u64)
                .ok_or_else(|| failure(AssetErrorCode::LimitExceeded))?;
            if written > maximum {
                return Err(failure(AssetErrorCode::LimitExceeded));
            }
            output.write_all(&buffer[..count])?;
            source_hash.update(&buffer[..count]);
            plain_hash.update(&buffer[..count]);
        }
        if written != length {
            return Err(failure(AssetErrorCode::SizeMismatch));
        }
        authentication = "legacy_plaintext";
    }
    check(cancel)?;
    let observed: [u8; 32] = plain_hash.finalize().into();
    if spec.hash.is_some_and(|hash| hash != observed) {
        return Err(failure(AssetErrorCode::HashMismatch));
    }
    Ok(AssetProof {
        source_sha256: hex::encode(source_hash.finalize()),
        plaintext_sha256: hex::encode(observed),
        plaintext_size: written,
        authentication: authentication.into(),
        metadata_hash_checked: spec.hash.is_some(),
    })
}

impl crate::assets::AssetRecipe for AttachmentSpec {
    fn local_path(&self) -> &str {
        &self.local_path
    }
    fn mime(&self) -> Option<&str> {
        self.mime.as_deref()
    }
    fn plaintext_size(&self) -> Option<u64> {
        self.size
    }
    fn fingerprint(&self) -> String {
        AttachmentSpec::fingerprint(self)
    }
    fn base_directory(&self) -> Option<&str> {
        Some("attachments.noindex")
    }
    fn recover(
        &self,
        input: &mut dyn ReadSeek,
        output: &mut dyn Write,
        maximum: u64,
        cancel: Option<&AtomicBool>,
    ) -> Result<AssetProof> {
        recover_attachment(input, output, self, maximum, cancel)
    }
}

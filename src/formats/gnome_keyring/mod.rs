//! Offline GNOME Keyring binary collections, format 0.0.
//!
//! GNOME derives 32 bytes by iterating SHA-256 over the exact password and
//! eight-byte salt. The first and second halves are the AES-128-CBC key and IV.
//! The decrypted payload begins with an **unkeyed MD5 checksum**, including
//! zero padding. This detects wrong passwords and damaged payloads but provides
//! no cryptographic authenticity. The outer index is outside that checksum.
//! Validate recovered application secrets against the consuming application's
//! evidence. No native Secret Service or analyst credential store is accessed.
//!
//! Source: GNOME Keyring 48.0 `gkm-secret-binary.c` and `egg-symkey.c`.

mod reader;
#[cfg(test)]
mod tests;

use crate::ParserSecret;
use aes::Aes128;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use reader::Reader;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt,
    ops::Range,
    sync::atomic::{AtomicBool, Ordering},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PASSWORD_BYTES: usize = 1024 * 1024;
const MAX_ITERATIONS: u32 = 1_000_000;
const MAX_ITEMS: usize = 16_384;

/// Byte offsets refer to the file during parsing and to the decrypted buffer
/// during unlocking. Submitted and recovered secret values are never included.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyringError {
    UnsupportedFormat,
    UnsupportedProtection,
    Truncated {
        field: &'static str,
        offset: usize,
    },
    Malformed {
        field: &'static str,
        offset: usize,
    },
    LimitExceeded {
        field: &'static str,
    },
    /// Wrong passwords and damaged ciphertext cannot be distinguished.
    ChecksumFailed,
    InvalidSelector,
    ItemNotFound,
    AmbiguousItem,
    Cancelled,
}
impl fmt::Display for KeyringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat => {
                f.write_str("unsupported GNOME Keyring format; expected a binary collection")
            }
            Self::UnsupportedProtection => {
                f.write_str("unsupported GNOME Keyring version or protection")
            }
            Self::Truncated { field, offset } => {
                write!(f, "truncated GNOME Keyring {field} at byte {offset}")
            }
            Self::Malformed { field, offset } => {
                write!(f, "malformed GNOME Keyring {field} at byte {offset}")
            }
            Self::LimitExceeded { field } => {
                write!(f, "GNOME Keyring {field} exceeds the decoder limit")
            }
            Self::ChecksumFailed => f.write_str(
                "GNOME Keyring payload checksum failed; the password or evidence may be incorrect",
            ),
            Self::InvalidSelector => f.write_str(
                "GNOME Keyring selection requires distinct, nonempty text attribute names",
            ),
            Self::ItemNotFound => f.write_str("no GNOME Keyring item matches the exact attributes"),
            Self::AmbiguousItem => {
                f.write_str("multiple GNOME Keyring items match the exact attributes")
            }
            Self::Cancelled => f.write_str("GNOME Keyring recovery cancelled"),
        }
    }
}
impl std::error::Error for KeyringError {}
type Result<T> = std::result::Result<T, KeyringError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AttributeValue {
    Text(Option<String>),
    Integer(u32),
}
pub type Attributes = std::collections::BTreeMap<String, AttributeValue>;

#[derive(Debug, Clone, Serialize)]
pub struct KeyringMetadata {
    pub display_name: Option<String>,
    /// Exact Unix-second values in file order. GNOME's writer and reader swap
    /// their collection creation/modification interpretation, so retain both.
    pub collection_timestamps_raw: [u64; 2],
    pub flags: u32,
    pub lock_timeout_seconds: u32,
    pub iterations: u32,
    pub salt_hex: String,
    pub reserved: [u32; 4],
    pub encrypted_offset: usize,
    pub encrypted_length: usize,
}
#[derive(Debug, Clone, Serialize)]
pub struct IndexedItem {
    pub id: u32,
    pub item_type: u32,
    pub index_offset: usize,
    /// These are lookup hashes, not the decrypted attribute values. The outer
    /// index is unauthenticated and cannot establish secret ownership.
    pub hashed_attributes: Attributes,
}
#[derive(Debug, Clone, Serialize)]
pub struct ItemMetadata {
    pub id: u32,
    pub item_type: u32,
    pub index_offset: usize,
    /// Offset in the decrypted payload, including its initial 16-byte checksum.
    pub decrypted_offset: usize,
    pub display_name: Option<String>,
    pub created_at_unix_seconds: u64,
    pub modified_at_unix_seconds: u64,
    pub attributes: Attributes,
    pub acl_entries: u32,
}

/// Borrowed encrypted collection and its untrusted outer index.
#[derive(Debug)]
pub struct GnomeKeyring<'a> {
    metadata: KeyringMetadata,
    items: Vec<IndexedItem>,
    salt: [u8; 8],
    ciphertext: &'a [u8],
}
impl<'a> GnomeKeyring<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(KeyringError::LimitExceeded {
                field: "input bytes",
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.take(16, "magic")? != b"GnomeKeyring\n\r\0\n" {
            return Err(KeyringError::UnsupportedFormat);
        }
        if reader.take(4, "version and protection")? != [0, 0, 0, 0] {
            return Err(KeyringError::UnsupportedProtection);
        }
        let display_name = reader.text("collection name")?;
        let collection_timestamps_raw = [
            reader.u64("collection timestamp")?,
            reader.u64("collection timestamp")?,
        ];
        let flags = reader.u32("flags")?;
        let lock_timeout_seconds = reader.u32("lock timeout")?;
        let iterations = reader.u32("iterations")?;
        if iterations == 0 {
            return Err(KeyringError::Malformed {
                field: "zero KDF iterations",
                offset: reader.offset - 4,
            });
        }
        if iterations > MAX_ITERATIONS {
            return Err(KeyringError::LimitExceeded {
                field: "KDF iterations",
            });
        }
        let mut salt = [0; 8];
        salt.copy_from_slice(reader.take(8, "salt")?);
        let reserved = [
            reader.u32("reserved")?,
            reader.u32("reserved")?,
            reader.u32("reserved")?,
            reader.u32("reserved")?,
        ];
        let count = reader.count(MAX_ITEMS, "item count")?;
        let mut items = Vec::with_capacity(count);
        let mut identifiers = BTreeSet::new();
        for _ in 0..count {
            let index_offset = reader.offset;
            let id = reader.u32("item ID")?;
            if !identifiers.insert(id) {
                return Err(KeyringError::Malformed {
                    field: "duplicate item ID",
                    offset: index_offset,
                });
            }
            items.push(IndexedItem {
                id,
                index_offset,
                item_type: reader.u32("item type")?,
                hashed_attributes: reader.attributes()?,
            });
        }
        let length = usize::try_from(reader.u32("encrypted length")?).map_err(|_| {
            KeyringError::LimitExceeded {
                field: "encrypted bytes",
            }
        })?;
        let encrypted_offset = reader.offset;
        if length < 16 || !length.is_multiple_of(16) {
            return Err(KeyringError::Malformed {
                field: "encrypted length",
                offset: encrypted_offset,
            });
        }
        let ciphertext = reader.take(length, "encrypted payload")?;
        if reader.remaining() != 0 {
            return Err(KeyringError::Malformed {
                field: "trailing file data",
                offset: reader.offset,
            });
        }
        Ok(Self {
            metadata: KeyringMetadata {
                display_name,
                collection_timestamps_raw,
                flags,
                lock_timeout_seconds,
                iterations,
                salt_hex: hex::encode(salt),
                reserved,
                encrypted_offset,
                encrypted_length: length,
            },
            items,
            salt,
            ciphertext,
        })
    }
    pub fn metadata(&self) -> &KeyringMetadata {
        &self.metadata
    }
    pub fn indexed_items(&self) -> &[IndexedItem] {
        &self.items
    }

    /// Decode the complete payload and verify its unkeyed MD5 before exposing
    /// item metadata or returning selected secrets. Exact password bytes matter.
    pub fn unlock_password(
        &self,
        password: &[u8],
        cancel: Option<&AtomicBool>,
    ) -> Result<UnlockedKeyring> {
        check_cancel(cancel)?;
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(KeyringError::LimitExceeded {
                field: "password bytes",
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(self.salt);
        let mut digest = hasher.finalize_reset();
        let mut key_iv = Zeroizing::new([0u8; 32]);
        key_iv.copy_from_slice(&digest);
        digest.as_mut_slice().zeroize();
        for round in 1..self.metadata.iterations {
            if round % 1024 == 0 {
                check_cancel(cancel)?;
            }
            hasher.update(key_iv.as_slice());
            let mut digest = hasher.finalize_reset();
            key_iv.copy_from_slice(&digest);
            digest.as_mut_slice().zeroize();
        }
        check_cancel(cancel)?;
        let mut plaintext = Zeroizing::new(self.ciphertext.to_vec());
        cbc::Decryptor::<Aes128>::new_from_slices(&key_iv[..16], &key_iv[16..])
            .map_err(|_| KeyringError::ChecksumFailed)?
            .decrypt_padded_mut::<NoPadding>(&mut plaintext)
            .map_err(|_| KeyringError::ChecksumFailed)?;
        check_cancel(cancel)?;
        let mut checksum = md5::compute(&plaintext[16..]).0;
        let matched = bool::from(checksum.as_slice().ct_eq(&plaintext[..16]));
        checksum.zeroize();
        if !matched {
            return Err(KeyringError::ChecksumFailed);
        }
        let mut reader = Reader::new(&plaintext);
        reader.take(16, "payload checksum")?;
        let mut items = Vec::with_capacity(self.items.len());
        for indexed in &self.items {
            check_cancel(cancel)?;
            let decrypted_offset = reader.offset;
            let display_name = reader.text("item label")?;
            let secret = reader.byte_range("item secret")?;
            let created_at_unix_seconds = reader.u64("item creation time")?;
            let modified_at_unix_seconds = reader.u64("item modification time")?;
            reader.text("item reserved string")?;
            reader.take(16, "item reserved words")?;
            let attributes = reader.attributes()?;
            let acl_entries = reader.u32("ACL count")?;
            reader.skip_acl(acl_entries)?;
            items.push(Item {
                metadata: ItemMetadata {
                    id: indexed.id,
                    item_type: indexed.item_type,
                    index_offset: indexed.index_offset,
                    decrypted_offset,
                    display_name,
                    created_at_unix_seconds,
                    modified_at_unix_seconds,
                    attributes,
                    acl_entries,
                },
                secret,
            });
        }
        if reader.remaining() >= 16 || reader.rest().iter().any(|byte| *byte != 0) {
            return Err(KeyringError::Malformed {
                field: "decrypted padding or item count",
                offset: reader.offset,
            });
        }
        check_cancel(cancel)?;
        Ok(UnlockedKeyring { plaintext, items })
    }
}

struct Item {
    metadata: ItemMetadata,
    secret: Range<usize>,
}
pub struct UnlockedKeyring {
    plaintext: Zeroizing<Vec<u8>>,
    items: Vec<Item>,
}
impl fmt::Debug for UnlockedKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedKeyring")
            .field("item_count", &self.items.len())
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}
impl UnlockedKeyring {
    pub fn items(&self) -> impl Iterator<Item = &ItemMetadata> {
        self.items.iter().map(|item| &item.metadata)
    }

    /// Select one item by exact decrypted text attributes. Empty selection and
    /// duplicate names are rejected. Ambiguity never chooses the first secret.
    pub fn recover_secret(
        &self,
        attributes: &[(&str, &str)],
        cancel: Option<&AtomicBool>,
    ) -> Result<RecoveredSecret> {
        check_cancel(cancel)?;
        let mut names = BTreeSet::new();
        if attributes.is_empty()
            || attributes
                .iter()
                .any(|(name, _)| name.is_empty() || !names.insert(*name))
        {
            return Err(KeyringError::InvalidSelector);
        }
        let mut selected = None;
        for item in &self.items {
            check_cancel(cancel)?;
            if attributes.iter().all(|(key, expected)| matches!(item.metadata.attributes.get(*key), Some(AttributeValue::Text(Some(actual))) if actual == expected)) {
                if selected.is_some() { return Err(KeyringError::AmbiguousItem); }
                selected = Some(item);
            }
        }
        let item = selected.ok_or(KeyringError::ItemNotFound)?;
        Ok(RecoveredSecret {
            value: ParserSecret::new(self.plaintext[item.secret.clone()].to_vec()),
            item_id: item.metadata.id,
            index_offset: item.metadata.index_offset,
            decrypted_offset: item.metadata.decrypted_offset,
        })
    }
}
pub struct RecoveredSecret {
    value: ParserSecret,
    item_id: u32,
    index_offset: usize,
    decrypted_offset: usize,
}
impl fmt::Debug for RecoveredSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredSecret")
            .field("item_id", &self.item_id)
            .field("value", &"[REDACTED]")
            .finish()
    }
}
impl RecoveredSecret {
    pub fn expose(&self) -> &[u8] {
        self.value.expose()
    }
    pub fn item_id(&self) -> u32 {
        self.item_id
    }
    pub fn index_offset(&self) -> usize {
        self.index_offset
    }
    pub fn decrypted_offset(&self) -> usize {
        self.decrypted_offset
    }
}
fn check_cancel(cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        Err(KeyringError::Cancelled)
    } else {
        Ok(())
    }
}

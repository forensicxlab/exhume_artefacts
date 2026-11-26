//! Offline KDE KWallet 0.1: PBKDF2-HMAC-SHA512 and Blowfish-CBC.
//!
//! Supply the acquired `.kwl`, its same-stem 56-byte `.salt`, and exact wallet
//! password bytes. The fixed KDF uses 50,000 rounds and a 56-byte key. CBC uses
//! an all-zero eight-byte IV. KDE's encrypted, unkeyed SHA-1 variant covers the serialized
//! payload, excluding random framing/padding and the unencrypted MD5 index.
//! This detects wrong passwords and damage, but is not a MAC. Validate recovered
//! application secrets against the consuming application's evidence.
//! On little-endian systems KDE's historical SHA1 class interprets message and
//! digest words in little-endian order. Ordinary SHA-1 is not compatible. This
//! decoder explicitly reproduces that behavior independently of the host.
//! Wallets written by big-endian hosts have not been validated.
//!
//! Secrets remain in zeroizing, redacted handles. Password entries contain a
//! nested QDataStream QString; return its exact UTF-8 value without trimming or
//! Base64 decoding. No native wallet or analyst credential store is accessed.
//! Legacy SHA-1 KDF/ECB wallets and GPG protection are explicitly unsupported.
//!
//! Sources: KDE/kwallet v6.13.0, `src/runtime/kwalletd/backend/`:
//! `kwalletbackend.cc`, `backendpersisthandler.cpp`, `kwalletentry.cc`, `cbc.cc`.

mod checksum;
mod reader;
#[cfg(test)]
mod tests;

use crate::ParserSecret;
use blowfish::Blowfish;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use reader::Reader;
use serde::Serialize;
use sha2::Sha512;
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
pub const SALT_BYTES: usize = 56;
const MAX_FOLDERS: usize = 16_384;
const MAX_ENTRIES: usize = 100_000;
// Folder names are repeated in emitted entry metadata. Bound that expansion
// separately from the encoded payload, which stores each folder name once.
const MAX_ENTRY_METADATA_BYTES: usize = 16 * 1024 * 1024;
const ITERATIONS: u32 = 50_000;

/// Offsets refer to the file during parsing and the decrypted QDataStream
/// payload during unlocking/password recovery. They are not ciphertext offsets.
/// Submitted passwords and recovered values never appear in errors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WalletError {
    UnsupportedFormat,
    UnsupportedProtection,
    InvalidSalt,
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
    /// A wrong password and damaged ciphertext cannot be distinguished.
    ChecksumFailed,
    IndexMismatch,
    EntryNotFound,
    UnsupportedEntryType,
    Cancelled,
}
impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat => f.write_str("unsupported KWallet file magic"),
            Self::UnsupportedProtection => f.write_str(
                "unsupported KWallet protection; expected 0.1 Blowfish-CBC/PBKDF2-SHA512",
            ),
            Self::InvalidSalt => f.write_str("KWallet recovery requires the matching 56-byte salt"),
            Self::Truncated { field, offset } => {
                write!(f, "truncated KWallet {field} at byte {offset}")
            }
            Self::Malformed { field, offset } => {
                write!(f, "malformed KWallet {field} at byte {offset}")
            }
            Self::LimitExceeded { field } => write!(f, "KWallet {field} exceeds the decoder limit"),
            Self::ChecksumFailed => f.write_str(
                "KWallet payload checksum failed; the password, salt or evidence may be incorrect",
            ),
            Self::IndexMismatch => {
                f.write_str("KWallet outer index disagrees with the decrypted payload")
            }
            Self::EntryNotFound => {
                f.write_str("no KWallet entry matches the exact folder and name")
            }
            Self::UnsupportedEntryType => f.write_str("selected KWallet entry is not a password"),
            Self::Cancelled => f.write_str("KWallet recovery cancelled"),
        }
    }
}
impl std::error::Error for WalletError {}
type Result<T> = std::result::Result<T, WalletError>;

#[derive(Debug, Clone, Serialize)]
pub struct WalletMetadata {
    pub major_version: u8,
    pub minor_version: u8,
    pub cipher_id: u8,
    pub hash_id: u8,
    pub iterations: u32,
    pub encrypted_offset: usize,
    pub encrypted_length: usize,
}
#[derive(Debug, Clone, Serialize)]
pub struct IndexedFolder {
    pub index_offset: usize,
    pub name_md5: String,
    pub entry_name_md5: Vec<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct EntryMetadata {
    pub folder: String,
    pub name: String,
    /// Native KWallet EntryType: 1 = Password, 2 = Stream, 3 = Map.
    pub entry_type: i32,
    /// Byte offset within the original file's outer index.
    pub index_offset: usize,
    /// Byte offset within the decrypted QDataStream payload, after framing.
    pub decrypted_offset: usize,
}
#[derive(Debug)]
pub struct KWallet<'a> {
    metadata: WalletMetadata,
    folders: Vec<IndexedFolder>,
    ciphertext: &'a [u8],
}
impl<'a> KWallet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(WalletError::LimitExceeded {
                field: "input bytes",
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.take(12, "magic")? != b"KWALLET\n\r\0\r\n" {
            return Err(WalletError::UnsupportedFormat);
        }
        let version = reader.take(4, "version and protection")?;
        if version != [0, 1, 3, 2] {
            return Err(WalletError::UnsupportedProtection);
        }
        let count = reader.count(MAX_FOLDERS, "folder count")?;
        let mut folders = Vec::with_capacity(count);
        let mut total_entries = 0usize;
        for _ in 0..count {
            let index_offset = reader.offset;
            let name_md5 = hex::encode(reader.take(16, "folder hash")?);
            let entries = reader.count(MAX_ENTRIES, "entry count")?;
            total_entries =
                total_entries
                    .checked_add(entries)
                    .ok_or(WalletError::LimitExceeded {
                        field: "total entries",
                    })?;
            if total_entries > MAX_ENTRIES {
                return Err(WalletError::LimitExceeded {
                    field: "total entries",
                });
            }
            let mut entry_name_md5 = Vec::with_capacity(entries);
            for _ in 0..entries {
                entry_name_md5.push(hex::encode(reader.take(16, "entry hash")?));
            }
            folders.push(IndexedFolder {
                index_offset,
                name_md5,
                entry_name_md5,
            });
        }
        let ciphertext = reader.rest();
        if ciphertext.len() < 40 || !ciphertext.len().is_multiple_of(8) {
            return Err(WalletError::Malformed {
                field: "ciphertext length",
                offset: reader.offset,
            });
        }
        Ok(Self {
            metadata: WalletMetadata {
                major_version: version[0],
                minor_version: version[1],
                cipher_id: version[2],
                hash_id: version[3],
                iterations: ITERATIONS,
                encrypted_offset: reader.offset,
                encrypted_length: ciphertext.len(),
            },
            folders,
            ciphertext,
        })
    }
    pub fn metadata(&self) -> &WalletMetadata {
        &self.metadata
    }
    pub fn indexed_folders(&self) -> &[IndexedFolder] {
        &self.folders
    }

    /// Decode the complete payload and verify its encrypted, unkeyed SHA-1.
    /// Cancellation is checked before/after the fixed bounded KDF/decryption,
    /// and between entries. Structural errors never expose partial secrets.
    pub fn unlock_password(
        &self,
        password: &[u8],
        salt: &[u8],
        cancel: Option<&AtomicBool>,
    ) -> Result<UnlockedWallet> {
        check_cancel(cancel)?;
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(WalletError::LimitExceeded {
                field: "password bytes",
            });
        }
        if salt.len() != SALT_BYTES {
            return Err(WalletError::InvalidSalt);
        }
        let mut key = Zeroizing::new([0u8; 56]);
        pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, ITERATIONS, key.as_mut());
        check_cancel(cancel)?;
        let mut plaintext = Zeroizing::new(self.ciphertext.to_vec());
        cbc::Decryptor::<Blowfish>::new_from_slices(key.as_slice(), &[0; 8])
            .map_err(|_| WalletError::ChecksumFailed)?
            .decrypt_padded_mut::<NoPadding>(&mut plaintext)
            .map_err(|_| WalletError::ChecksumFailed)?;
        check_cancel(cancel)?;
        let size = u32::from_be_bytes([plaintext[8], plaintext[9], plaintext[10], plaintext[11]]);
        let size = usize::try_from(size).map_err(|_| WalletError::ChecksumFailed)?;
        let end = 12usize
            .checked_add(size)
            .ok_or(WalletError::ChecksumFailed)?;
        let checksum_start = plaintext.len() - 20;
        if end >= checksum_start || checksum_start - end > 8 {
            return Err(WalletError::ChecksumFailed);
        }
        let mut checksum = checksum::little_endian(&plaintext[12..end], cancel)?;
        let matched = bool::from(checksum.as_slice().ct_eq(&plaintext[checksum_start..]));
        checksum.zeroize();
        if !matched {
            return Err(WalletError::ChecksumFailed);
        }
        let mut reader = Reader::new(&plaintext[12..end]);
        let mut items = Vec::new();
        let mut folders = BTreeSet::new();
        let mut metadata_bytes_left = MAX_ENTRY_METADATA_BYTES;
        for indexed in &self.folders {
            check_cancel(cancel)?;
            let offset = reader.offset;
            let folder = reader.text("folder name")?;
            if !folders.insert(folder.clone()) {
                return Err(WalletError::Malformed {
                    field: "duplicate folder name",
                    offset,
                });
            }
            let count = reader.count(MAX_ENTRIES, "decrypted entry count")?;
            if hex::encode(md5::compute(folder.as_bytes()).0) != indexed.name_md5
                || count != indexed.entry_name_md5.len()
            {
                return Err(WalletError::IndexMismatch);
            }
            let mut names = BTreeSet::new();
            for (index, hashed) in indexed.entry_name_md5.iter().enumerate() {
                check_cancel(cancel)?;
                let decrypted_offset = reader.offset;
                let name = reader.text("entry name")?;
                metadata_bytes_left = folder
                    .len()
                    .checked_add(name.len())
                    .and_then(|length| metadata_bytes_left.checked_sub(length))
                    .ok_or(WalletError::LimitExceeded {
                        field: "entry metadata bytes",
                    })?;
                if !names.insert(name.clone()) {
                    return Err(WalletError::Malformed {
                        field: "duplicate entry name",
                        offset: decrypted_offset,
                    });
                }
                if hex::encode(md5::compute(name.as_bytes()).0) != *hashed {
                    return Err(WalletError::IndexMismatch);
                }
                let entry_type = reader.i32("entry type")?;
                let value = reader.bytes("entry value")?;
                items.push(Entry {
                    metadata: EntryMetadata {
                        folder: folder.clone(),
                        name,
                        entry_type,
                        index_offset: indexed.index_offset + 20 + index * 16,
                        decrypted_offset,
                    },
                    value: (value.start + 12)..(value.end + 12),
                });
            }
        }
        if !reader.rest().is_empty() {
            return Err(WalletError::Malformed {
                field: "trailing payload data",
                offset: reader.offset,
            });
        }
        check_cancel(cancel)?;
        Ok(UnlockedWallet { plaintext, items })
    }
}

struct Entry {
    metadata: EntryMetadata,
    value: Range<usize>,
}
pub struct UnlockedWallet {
    plaintext: Zeroizing<Vec<u8>>,
    items: Vec<Entry>,
}
impl fmt::Debug for UnlockedWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedWallet")
            .field("entry_count", &self.items.len())
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}
impl UnlockedWallet {
    pub fn entries(&self) -> impl Iterator<Item = &EntryMetadata> {
        self.items.iter().map(|entry| &entry.metadata)
    }
    /// Select exactly one password by its decrypted folder and entry name.
    /// This decodes the nested QDataStream QString, not the raw QByteArray.
    pub fn recover_password(
        &self,
        folder: &str,
        name: &str,
        cancel: Option<&AtomicBool>,
    ) -> Result<RecoveredPassword> {
        check_cancel(cancel)?;
        let entry = self
            .items
            .iter()
            .find(|entry| entry.metadata.folder == folder && entry.metadata.name == name)
            .ok_or(WalletError::EntryNotFound)?;
        if entry.metadata.entry_type != 1 {
            return Err(WalletError::UnsupportedEntryType);
        }
        let mut reader = Reader::new(&self.plaintext[entry.value.clone()]);
        let mut password = reader.secret_text("password QString").map_err(|error| {
            // Nested QDataStream offsets become offsets in the decrypted
            // wallet payload, consistent with entry metadata and unlock errors.
            let base = entry.value.start - 12;
            match error {
                WalletError::Truncated { field, offset } => WalletError::Truncated {
                    field,
                    offset: base + offset,
                },
                WalletError::Malformed { field, offset } => WalletError::Malformed {
                    field,
                    offset: base + offset,
                },
                other => other,
            }
        })?;
        if !reader.rest().is_empty() {
            return Err(WalletError::Malformed {
                field: "trailing password data",
                offset: entry.value.start + reader.offset - 12,
            });
        }
        check_cancel(cancel)?;
        Ok(RecoveredPassword {
            value: ParserSecret::new(std::mem::take(&mut *password).into_bytes()),
            metadata: entry.metadata.clone(),
        })
    }
}
pub struct RecoveredPassword {
    value: ParserSecret,
    metadata: EntryMetadata,
}
impl fmt::Debug for RecoveredPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredPassword")
            .field("metadata", &self.metadata)
            .field("value", &"[REDACTED]")
            .finish()
    }
}
impl RecoveredPassword {
    pub fn expose(&self) -> &[u8] {
        self.value.expose()
    }
    pub fn metadata(&self) -> &EntryMetadata {
        &self.metadata
    }
}
fn check_cancel(cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        Err(WalletError::Cancelled)
    } else {
        Ok(())
    }
}

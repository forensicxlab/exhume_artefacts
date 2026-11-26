//! Portable, offline recovery from file-based macOS Keychains (`kych`).
//!
//! A password unlocks the database encryption/signing keys only after the full
//! database-blob MAC verifies. Generic-password recovery selects one exact
//! service/account pair and verifies its wrapping-key MAC before unwrapping it.
//! Versions 0x100 (Apple's historical staged HMAC), 0x101 and 0x200 are supported.
//! Login Keychains may use an indirect password: HMAC-SHA256 with a 32-byte
//! protected-entropy value from `/private/var/db/SystemKeys/<database salt hex>`
//! and the user's exact password. See [`LegacyKeychain::unlock_login_password`].
//! A blob version does not identify this protection route: both direct and
//! indirect password protection can use version 0x200.
//!
//! The record's `ssgp` payload uses unauthenticated 3DES-CBC. Its metadata and
//! ciphertext are **not** authenticated by the wrapping-key MAC. Consumers must
//! validate recovered application keys against that application's encrypted
//! evidence; valid padding alone does not establish record integrity.
//!
//! SQLite data-protection Keychains, Secure Enclave/keybag recovery, System
//! Keychain unlock files, password guessing and native Keychain APIs are outside
//! this module. No analyst-machine credential store is accessed.
//!
//! ```no_run
//! use exhume_artefacts::formats::keychain::LegacyKeychain;
//!
//! # fn recover(keychain_bytes: &[u8], password: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
//! let unlocked = LegacyKeychain::parse(keychain_bytes)?.unlock_password(password, None)?;
//! let candidate = unlocked.recover_generic_password(
//!     b"Signal Safe Storage", b"Signal Key", None,
//! )?;
//! // Consume candidate.expose() in an application-specific key resolver.
//! // Do not serialize it; validate the derived key against Signal's database.
//! # let _ = candidate;
//! # Ok(()) }
//! ```

mod crypto;
pub(crate) mod database;

pub use database::{
    GenericPassword, KeychainMetadata, LegacyKeychain, RecoveredPassword, UnlockedKeychain,
};

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

/// Maximum complete file size accepted by the decoder, in bytes.
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
/// Maximum size of a single record, encrypted blob or recovered value, in bytes.
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
/// Maximum exact password size, in bytes. Whitespace is significant.
pub const MAX_PASSWORD_BYTES: usize = 1024 * 1024;
const MAX_TABLES: usize = 64;
const MAX_RECORD_SLOTS: usize = 1_000_000;

/// Expected failures. No variant contains a password or recovered secret.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeychainError {
    Truncated {
        field: &'static str,
        offset: usize,
    },
    Malformed {
        field: &'static str,
        offset: usize,
    },
    UnsupportedFormat,
    UnsupportedVersion {
        format: &'static str,
        version: u32,
    },
    UnsupportedProtection,
    UnsupportedAttribute {
        offset: usize,
    },
    LimitExceeded {
        field: &'static str,
    },
    MissingDatabaseBlob,
    ItemNotFound,
    AmbiguousItem,
    MissingWrappingKey,
    AmbiguousWrappingKey,
    /// Wrong credentials and damaged evidence cannot always be distinguished.
    AuthenticationFailed,
    /// An authenticated key could not decode the unauthenticated item payload.
    InvalidPayload,
    Cancelled,
}

impl fmt::Display for KeychainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { field, offset } => write!(f, "truncated Keychain {field} at byte {offset}"),
            Self::Malformed { field, offset } => write!(f, "malformed Keychain {field} at byte {offset}"),
            Self::UnsupportedFormat => f.write_str("unsupported Keychain format; offline recovery requires a file-based 'kych' Keychain"),
            Self::UnsupportedVersion { format, version } => write!(f, "unsupported Keychain {format} version {version:#x}"),
            Self::UnsupportedProtection => f.write_str("unsupported Keychain key protection"),
            Self::UnsupportedAttribute { offset } => write!(f, "unsupported multivalued Keychain attribute at byte {offset}"),
            Self::LimitExceeded { field } => write!(f, "Keychain {field} exceeds the decoder limit"),
            Self::MissingDatabaseBlob => f.write_str("Keychain contains no database protection blob"),
            Self::ItemNotFound => f.write_str("no generic-password item matches the exact service and account"),
            Self::AmbiguousItem => f.write_str("multiple generic-password items match the exact service and account"),
            Self::MissingWrappingKey => f.write_str("Keychain item references a missing wrapping key"),
            Self::AmbiguousWrappingKey => f.write_str("multiple Keychain wrapping keys match the item label"),
            Self::AuthenticationFailed => f.write_str("Keychain authentication failed; protection inputs or evidence may be incorrect (login Keychains may require protected entropy)"),
            Self::InvalidPayload => f.write_str("Keychain item payload could not be decoded; it is not authenticated by the key-blob MAC"),
            Self::Cancelled => f.write_str("Keychain recovery cancelled"),
        }
    }
}
impl std::error::Error for KeychainError {}

type Result<T> = std::result::Result<T, KeychainError>;

fn check_cancel(cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        Err(KeychainError::Cancelled)
    } else {
        Ok(())
    }
}

fn malformed(field: &'static str, offset: usize) -> KeychainError {
    KeychainError::Malformed { field, offset }
}

/// A bounded, borrowed section. All offsets are file-relative in errors.
#[derive(Clone, Copy)]
pub(crate) struct Section<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) offset: usize,
}
impl<'a> Section<'a> {
    pub(crate) fn part(self, offset: usize, length: usize, field: &'static str) -> Result<Self> {
        let absolute = self
            .offset
            .checked_add(offset)
            .ok_or_else(|| malformed(field, self.offset))?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| malformed(field, absolute))?;
        let bytes = self
            .bytes
            .get(offset..end)
            .ok_or(KeychainError::Truncated {
                field,
                offset: absolute,
            })?;
        Ok(Self {
            bytes,
            offset: absolute,
        })
    }
    pub(crate) fn u32(self, offset: usize, field: &'static str) -> Result<u32> {
        let b = self.part(offset, 4, field)?.bytes;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn usize(self, offset: usize, field: &'static str) -> Result<usize> {
        usize::try_from(self.u32(offset, field)?)
            .map_err(|_| KeychainError::LimitExceeded { field })
    }
}

#[cfg(test)]
pub(crate) mod fixtures;
#[cfg(test)]
mod tests;

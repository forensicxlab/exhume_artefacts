//! Offline Windows DPAPI decoding and authenticated recovery.
//!
//! Metadata decoding is separate from unlocking. Recovery currently supports
//! AES-256-CBC/SHA-512 master keys protected by a local account password and
//! matching DPAPI blobs. Domain backup keys, credential history, machine keys,
//! DPAPI-NG and older cipher suites are not recovered by this module.
//! No native Windows API or analyst-machine credential store is used.

mod blob;
mod master_key;

pub use blob::{Blob, BlobMetadata};
pub use master_key::{MasterKey, MasterKeyBlockMetadata, MasterKeyFile, MasterKeyFileMetadata};

use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::{Zeroize, Zeroizing};

/// Maximum encoded master-key file or DPAPI blob size, in bytes.
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
/// Upper bound on password-derivation rounds. Larger counts remain inspectable.
pub const MAX_KDF_ROUNDS: u32 = 1_000_000;
pub(crate) const AES_256: u32 = 0x6610;
pub(crate) const SHA_512: u32 = 0x800e;

/// Expected failures. Errors never contain a submitted password or recovered key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DpapiError {
    Truncated {
        field: &'static str,
        offset: usize,
    },
    Malformed {
        field: &'static str,
    },
    UnsupportedVersion {
        format: &'static str,
        version: u32,
    },
    UnsupportedAlgorithms {
        cipher: u32,
        hash: u32,
    },
    LimitExceeded {
        field: &'static str,
    },
    InvalidSid,
    MissingMasterKey,
    WrongMasterKey,
    /// Authentication did not validate: credentials, entropy or evidence may
    /// be responsible. This does not prove that a password was incorrect.
    AuthenticationFailed,
    Cancelled,
}

impl fmt::Display for DpapiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { field, offset } => write!(f, "truncated DPAPI {field} at byte {offset}"),
            Self::Malformed { field } => write!(f, "malformed DPAPI {field}"),
            Self::UnsupportedVersion { format, version } => write!(f, "unsupported DPAPI {format} version {version}"),
            Self::UnsupportedAlgorithms { cipher, hash } => write!(f, "unsupported DPAPI recovery algorithms: cipher {cipher:#x}, hash {hash:#x}"),
            Self::LimitExceeded { field } => write!(f, "DPAPI {field} exceeds the recovery limit"),
            Self::InvalidSid => f.write_str("invalid Windows account SID"),
            Self::MissingMasterKey => f.write_str("DPAPI file contains no primary master-key block"),
            Self::WrongMasterKey => f.write_str("DPAPI blob references a different master-key GUID"),
            Self::AuthenticationFailed => f.write_str("DPAPI authentication failed: credentials, optional entropy or evidence may be incorrect"),
            Self::Cancelled => f.write_str("DPAPI recovery cancelled"),
        }
    }
}
impl std::error::Error for DpapiError {}

pub(crate) type Result<T> = std::result::Result<T, DpapiError>;

pub(crate) fn check_cancel(cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        Err(DpapiError::Cancelled)
    } else {
        Ok(())
    }
}

pub(crate) fn hmac512(key: &[u8], data: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key)
        .map_err(|_| DpapiError::Malformed { field: "HMAC key" })?;
    mac.update(data);
    let mut bytes = mac.finalize().into_bytes();
    let mut result = Zeroizing::new([0; 64]);
    result.copy_from_slice(&bytes);
    bytes.as_mut_slice().zeroize();
    Ok(result)
}

pub(crate) fn utf16(bytes: &[u8], field: &'static str) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(DpapiError::Malformed { field });
    }
    let units: Vec<_> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16(&units).map_err(|_| DpapiError::Malformed { field })
}

pub(crate) fn canonical_guid(value: &str) -> Result<String> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(i, byte)| {
            if [8, 13, 18, 23].contains(&i) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(DpapiError::Malformed {
            field: "master-key GUID",
        });
    }
    Ok(value.to_ascii_lowercase())
}

pub(crate) fn guid(bytes: &[u8]) -> Result<String> {
    let mut reader = Reader::new(bytes)?;
    let a = reader.u32("GUID")?;
    let b = reader.take(2, "GUID")?;
    let c = reader.take(2, "GUID")?;
    let d = reader.take(8, "GUID")?;
    Ok(format!(
        "{a:08x}-{:04x}-{:04x}-{}-{}",
        u16::from_le_bytes([b[0], b[1]]),
        u16::from_le_bytes([c[0], c[1]]),
        hex::encode(&d[..2]),
        hex::encode(&d[2..])
    ))
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pub(crate) position: usize,
}
impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(DpapiError::LimitExceeded {
                field: "input bytes",
            });
        }
        Ok(Self { bytes, position: 0 })
    }
    pub(crate) fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(DpapiError::Malformed { field })?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(DpapiError::Truncated {
                field,
                offset: self.position,
            })?;
        self.position = end;
        Ok(value)
    }
    pub(crate) fn u32(&mut self, field: &'static str) -> Result<u32> {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(self.take(4, field)?);
        Ok(u32::from_le_bytes(bytes))
    }
    pub(crate) fn u64(&mut self, field: &'static str) -> Result<u64> {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(self.take(8, field)?);
        Ok(u64::from_le_bytes(bytes))
    }
    pub(crate) fn sized(&mut self, field: &'static str) -> Result<&'a [u8]> {
        let size =
            usize::try_from(self.u32(field)?).map_err(|_| DpapiError::LimitExceeded { field })?;
        self.take(size, field)
    }
    pub(crate) fn finish(&self) -> Result<()> {
        if self.position != self.bytes.len() {
            return Err(DpapiError::Malformed {
                field: "trailing bytes",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod fixtures;
#[cfg(test)]
mod tests;

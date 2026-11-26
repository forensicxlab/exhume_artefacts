use super::{
    AES_256, DpapiError, MAX_KDF_ROUNDS, Reader, Result, SHA_512, canonical_guid, check_cancel,
    hmac512, utf16,
};
use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::{Digest, Sha1};
use sha2::Sha512;
use std::fmt;
use std::sync::atomic::AtomicBool;
use zeroize::{Zeroize, Zeroizing};

/// Non-secret information from a master-key protection block.
#[derive(Debug, Clone, Serialize)]
pub struct MasterKeyBlockMetadata {
    pub version: u32,
    pub rounds: u32,
    pub hash_algorithm: u32,
    pub cipher_algorithm: u32,
    pub ciphertext_bytes: usize,
}

/// Master-key file header and protection algorithms; contains no recovered keys.
#[derive(Debug, Clone, Serialize)]
pub struct MasterKeyFileMetadata {
    pub version: u32,
    pub guid: String,
    pub policy: u32,
    pub flags: u32,
    pub primary: Option<MasterKeyBlockMetadata>,
    pub backup_bytes: u64,
    pub credential_history_bytes: u64,
    pub domain_key_bytes: u64,
}

/// A borrowed, structurally validated DPAPI master-key file.
///
/// File parsing does not authenticate its ciphertext or recover backup/domain
/// blocks. Unsupported protection algorithms remain visible in the metadata.
pub struct MasterKeyFile<'a> {
    metadata: MasterKeyFileMetadata,
    primary: Option<Protection<'a>>,
}

struct Protection<'a> {
    salt: &'a [u8],
    ciphertext: &'a [u8],
}

impl fmt::Debug for MasterKeyFile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.metadata.fmt(f)
    }
}

/// An in-memory 64-byte master key associated with its file GUID.
/// Password recovery authenticates it; importing bytes does not.
/// Key bytes are zeroized on drop, redacted in Debug, and never serialized.
pub struct MasterKey {
    pub(crate) guid: String,
    pub(crate) bytes: Zeroizing<[u8; 64]>,
}

impl MasterKey {
    /// Import an already recovered key. The caller is responsible for erasing
    /// any other copies it retains. Importing does not authenticate the key.
    pub fn from_bytes(guid: &str, bytes: [u8; 64]) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        Ok(Self {
            guid: canonical_guid(guid)?,
            bytes,
        })
    }

    pub fn guid(&self) -> &str {
        &self.guid
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterKey")
            .field("guid", &self.guid)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl<'a> MasterKeyFile<'a> {
    /// Parse lengths and file metadata. Input is limited by `MAX_INPUT_BYTES`.
    /// Truncated sections, invalid GUIDs and trailing bytes are rejected.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes)?;
        let version = reader.u32("master-key file version")?;
        if ![1, 2].contains(&version) {
            return Err(DpapiError::UnsupportedVersion {
                format: "master-key file",
                version,
            });
        }
        reader.take(8, "reserved file header")?;
        let guid = canonical_guid(&utf16(
            reader.take(72, "master-key GUID")?,
            "master-key GUID",
        )?)?;
        reader.take(4, "reserved file header")?;
        let policy = reader.u32("policy")?;
        let flags = reader.u32("flags")?;
        let primary_bytes = reader.u64("primary block length")?;
        let backup_bytes = reader.u64("backup block length")?;
        let credential_history_bytes = reader.u64("credential history length")?;
        let domain_key_bytes = reader.u64("domain key length")?;
        let primary_data = reader.take(length(primary_bytes)?, "primary block")?;
        reader.take(length(backup_bytes)?, "backup block")?;
        reader.take(length(credential_history_bytes)?, "credential history")?;
        reader.take(length(domain_key_bytes)?, "domain key")?;
        reader.finish()?;

        let (primary_metadata, primary) = if primary_data.is_empty() {
            (None, None)
        } else {
            let mut block = Reader::new(primary_data)?;
            let version = block.u32("protection version")?;
            let salt = block.take(16, "protection salt")?;
            let rounds = block.u32("protection rounds")?;
            let hash_algorithm = block.u32("protection hash")?;
            let cipher_algorithm = block.u32("protection cipher")?;
            let ciphertext =
                block.take(primary_data.len() - block.position, "protection ciphertext")?;
            if ciphertext.is_empty() {
                return Err(DpapiError::Malformed {
                    field: "empty protection ciphertext",
                });
            }
            (
                Some(MasterKeyBlockMetadata {
                    version,
                    rounds,
                    hash_algorithm,
                    cipher_algorithm,
                    ciphertext_bytes: ciphertext.len(),
                }),
                Some(Protection { salt, ciphertext }),
            )
        };
        Ok(Self {
            metadata: MasterKeyFileMetadata {
                version,
                guid,
                policy,
                flags,
                primary: primary_metadata,
                backup_bytes,
                credential_history_bytes,
                domain_key_bytes,
            },
            primary,
        })
    }

    pub fn metadata(&self) -> &MasterKeyFileMetadata {
        &self.metadata
    }

    /// Validate the supported local-password protection and SID without running
    /// a KDF or authenticating any key material.
    pub fn check_local_password_protection(&self, sid: &str) -> Result<()> {
        validate_sid(sid)?;
        let metadata = self
            .metadata
            .primary
            .as_ref()
            .ok_or(DpapiError::MissingMasterKey)?;
        let protection = self.primary.as_ref().ok_or(DpapiError::MissingMasterKey)?;
        if metadata.version != 2 {
            return Err(DpapiError::UnsupportedVersion {
                format: "protection block",
                version: metadata.version,
            });
        }
        if metadata.cipher_algorithm != AES_256 || metadata.hash_algorithm != SHA_512 {
            return Err(DpapiError::UnsupportedAlgorithms {
                cipher: metadata.cipher_algorithm,
                hash: metadata.hash_algorithm,
            });
        }
        if metadata.rounds == 0 {
            return Err(DpapiError::Malformed {
                field: "zero protection rounds",
            });
        }
        if metadata.rounds > MAX_KDF_ROUNDS {
            return Err(DpapiError::LimitExceeded {
                field: "derivation rounds",
            });
        }
        if protection.ciphertext.len() < 144 || !protection.ciphertext.len().is_multiple_of(16) {
            return Err(DpapiError::Malformed {
                field: "AES protection ciphertext length",
            });
        }
        Ok(())
    }

    /// Authenticate and recover an AES-256/SHA-512 primary block using the
    /// local-account SHA-1 password/SID derivation. Password is exact UTF-8;
    /// it is encoded as UTF-16LE without trimming or normalization.
    ///
    /// This does not try NT-hash/domain/Protected Users derivations, password
    /// history, or backup keys. Authentication failure preserves that uncertainty.
    /// The caller can pass its existing cancellation flag; it is checked before
    /// work and at most every 256 derivation rounds. Inputs and rounds are bounded.
    pub fn unlock_local_password(
        &self,
        sid: &str,
        password: &str,
        cancel: Option<&AtomicBool>,
    ) -> Result<MasterKey> {
        check_cancel(cancel)?;
        validate_sid(sid)?;
        if password.len() > 16 * 1024 {
            return Err(DpapiError::LimitExceeded {
                field: "password bytes",
            });
        }
        self.check_local_password_protection(sid)?;
        let metadata = self
            .metadata
            .primary
            .as_ref()
            .ok_or(DpapiError::MissingMasterKey)?;
        let protection = self.primary.as_ref().ok_or(DpapiError::MissingMasterKey)?;
        let utf16_password = Zeroizing::new(
            password
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        );
        let mut password_hash = Sha1::digest(&*utf16_password);
        let encoded_sid = Zeroizing::new(
            sid.encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        );
        let mut mac =
            Hmac::<Sha1>::new_from_slice(&password_hash).map_err(|_| DpapiError::Malformed {
                field: "password derivation",
            })?;
        password_hash.as_mut_slice().zeroize();
        mac.update(&encoded_sid);
        let mut prekey = mac.finalize().into_bytes();
        let result = self.unlock_prekey(&prekey, protection, metadata.rounds, cancel);
        prekey.as_mut_slice().zeroize();
        result
    }

    fn unlock_prekey(
        &self,
        prekey: &[u8],
        protection: &Protection<'_>,
        rounds: u32,
        cancel: Option<&AtomicBool>,
    ) -> Result<MasterKey> {
        let mut input = [0; 20];
        input[..16].copy_from_slice(protection.salt);
        input[16..].copy_from_slice(&1_u32.to_be_bytes());
        let mut material = hmac512(prekey, &input)?;
        // DPAPI feeds the accumulated XOR back into each PRF round. This is
        // deliberately not the standard PBKDF2 feedback rule.
        for round in 1..rounds {
            if round.is_multiple_of(256) {
                check_cancel(cancel)?;
            }
            let next = hmac512(prekey, &*material)?;
            for (byte, extra) in material.iter_mut().zip(next.iter()) {
                *byte ^= extra;
            }
        }
        let mut plaintext = Zeroizing::new(protection.ciphertext.to_vec());
        cbc::Decryptor::<Aes256>::new_from_slices(&material[..32], &material[32..48])
            .map_err(|_| DpapiError::Malformed {
                field: "AES key/IV length",
            })?
            .decrypt_padded_mut::<NoPadding>(&mut plaintext)
            .map_err(|_| DpapiError::AuthenticationFailed)?;
        let key_start = plaintext.len() - 64;
        let mac_key = hmac512(prekey, &plaintext[..16])?;
        let mut verifier =
            Hmac::<Sha512>::new_from_slice(&*mac_key).map_err(|_| DpapiError::Malformed {
                field: "authentication key",
            })?;
        verifier.update(&plaintext[key_start..]);
        verifier
            .verify_slice(&plaintext[16..80])
            .map_err(|_| DpapiError::AuthenticationFailed)?;
        check_cancel(cancel)?;
        let mut bytes = Zeroizing::new([0; 64]);
        bytes.copy_from_slice(&plaintext[key_start..]);
        Ok(MasterKey {
            guid: self.metadata.guid.clone(),
            bytes,
        })
    }
}

fn length(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| DpapiError::LimitExceeded {
        field: "section bytes",
    })
}

fn validate_sid(sid: &str) -> Result<()> {
    if sid.len() > 184 {
        return Err(DpapiError::InvalidSid);
    }
    let parts: Vec<_> = sid.split('-').collect();
    if !(4..=18).contains(&parts.len()) || parts[0] != "S" || parts[1] != "1" {
        return Err(DpapiError::InvalidSid);
    }
    let authority = parts[2]
        .parse::<u64>()
        .map_err(|_| DpapiError::InvalidSid)?;
    if authority > 0x0000_ffff_ffff_ffff
        || parts[2..]
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(DpapiError::InvalidSid);
    }
    for part in &parts[3..] {
        part.parse::<u32>().map_err(|_| DpapiError::InvalidSid)?;
    }
    Ok(())
}

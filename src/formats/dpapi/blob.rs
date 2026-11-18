use super::{
    AES_256, DpapiError, MasterKey, Reader, Result, SHA_512, check_cancel, guid, hmac512, utf16,
};
use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::{Digest, Sha1};
use sha2::Sha512;
use std::fmt;
use std::sync::atomic::AtomicBool;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const PROVIDER: &[u8; 16] = b"\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8c\x7a\x00\xc0\x4f\xc2\x97\xeb";

/// Blob metadata suitable for discovery and dependency association.
#[derive(Debug, Clone, Serialize)]
pub struct BlobMetadata {
    pub version: u32,
    pub master_key_version: u32,
    pub master_key_guid: String,
    pub flags: u32,
    pub description: String,
    pub cipher_algorithm: u32,
    pub cipher_key_bits: u32,
    pub hash_algorithm: u32,
    pub hash_bits: u32,
    pub ciphertext_bytes: usize,
    pub signature_bytes: usize,
}

/// Borrowed DPAPI ciphertext. Parsing validates structure, not authenticity.
pub struct Blob<'a> {
    metadata: BlobMetadata,
    salt: &'a [u8],
    mac_salt: &'a [u8],
    ciphertext: &'a [u8],
    signed: &'a [u8],
    signature: &'a [u8],
}

impl fmt::Debug for Blob<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.metadata.fmt(f)
    }
}

impl<'a> Blob<'a> {
    /// Parse a standard DPAPI provider blob. Lengths are checked against the
    /// complete bounded input; unsupported ciphers remain inspectable.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes)?;
        let version = reader.u32("blob version")?;
        if version != 1 {
            return Err(DpapiError::UnsupportedVersion {
                format: "blob",
                version,
            });
        }
        if reader.take(16, "provider GUID")? != PROVIDER {
            return Err(DpapiError::Malformed {
                field: "provider GUID",
            });
        }
        let master_key_version = reader.u32("blob master-key version")?;
        let master_key_guid = guid(reader.take(16, "blob master-key GUID")?)?;
        let flags = reader.u32("blob flags")?;
        let description = utf16(reader.sized("description")?, "description")?
            .trim_end_matches('\0')
            .to_owned();
        let cipher_algorithm = reader.u32("blob cipher")?;
        let cipher_key_bits = reader.u32("blob cipher key bits")?;
        let salt = reader.sized("blob salt")?;
        reader.sized("blob HMAC key")?;
        let hash_algorithm = reader.u32("blob hash")?;
        let hash_bits = reader.u32("blob hash bits")?;
        let mac_salt = reader.sized("blob MAC salt")?;
        let ciphertext = reader.sized("blob ciphertext")?;
        let signed = &bytes[20..reader.position];
        let signature = reader.sized("blob signature")?;
        reader.finish()?;
        Ok(Self {
            metadata: BlobMetadata {
                version,
                master_key_version,
                master_key_guid,
                flags,
                description,
                cipher_algorithm,
                cipher_key_bits,
                hash_algorithm,
                hash_bits,
                ciphertext_bytes: ciphertext.len(),
                signature_bytes: signature.len(),
            },
            salt,
            mac_salt,
            ciphertext,
            signed,
            signature,
        })
    }

    pub fn metadata(&self) -> &BlobMetadata {
        &self.metadata
    }

    /// Authenticate and decrypt using the blob's matching master key and exact
    /// optional entropy bytes. Plaintext is returned only after authentication.
    /// Supports AES-256/SHA-512; other suites produce `UnsupportedAlgorithms`.
    pub fn decrypt(
        &self,
        key: &MasterKey,
        entropy: Option<&[u8]>,
        cancel: Option<&AtomicBool>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        check_cancel(cancel)?;
        if self.metadata.master_key_guid != key.guid {
            return Err(DpapiError::WrongMasterKey);
        }
        if self.metadata.master_key_version != 1 {
            return Err(DpapiError::UnsupportedVersion {
                format: "blob master key",
                version: self.metadata.master_key_version,
            });
        }
        if self.metadata.cipher_algorithm != AES_256 || self.metadata.hash_algorithm != SHA_512 {
            return Err(DpapiError::UnsupportedAlgorithms {
                cipher: self.metadata.cipher_algorithm,
                hash: self.metadata.hash_algorithm,
            });
        }
        if self.metadata.cipher_key_bits != 256
            || self.metadata.hash_bits != 512
            || self.signature.len() != 64
            || self.salt.is_empty()
            || self.mac_salt.is_empty()
            || self.ciphertext.is_empty()
            || !self.ciphertext.len().is_multiple_of(16)
        {
            return Err(DpapiError::Malformed {
                field: "AES/SHA-512 blob lengths",
            });
        }
        let entropy = entropy.unwrap_or_default();
        if entropy.len() > super::MAX_INPUT_BYTES {
            return Err(DpapiError::LimitExceeded {
                field: "entropy bytes",
            });
        }
        let mut key_hash = Sha1::digest(key.bytes.as_slice());
        let result = self.decrypt_hashed_key(&key_hash, entropy, cancel);
        key_hash.as_mut_slice().zeroize();
        result
    }

    fn decrypt_hashed_key(
        &self,
        key_hash: &[u8],
        entropy: &[u8],
        cancel: Option<&AtomicBool>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut standard =
            Hmac::<Sha512>::new_from_slice(key_hash).map_err(|_| DpapiError::Malformed {
                field: "blob authentication key",
            })?;
        standard.update(self.mac_salt);
        standard.update(entropy);
        standard.update(self.signed);
        let standard_valid = standard.verify_slice(self.signature).is_ok();

        // DPAPI also has a signature variant that appends the signed data
        // after the inner/outer hash of the MAC salt rather than inside HMAC.
        let mut pads = Zeroizing::new([0; 128]);
        pads[..key_hash.len()].copy_from_slice(key_hash);
        for byte in pads.iter_mut() {
            *byte ^= 0x36;
        }
        let mut inner = Sha512::new();
        inner.update(pads.as_slice());
        inner.update(self.mac_salt);
        let mut inner_digest = inner.finalize();
        for byte in pads.iter_mut() {
            *byte ^= 0x36 ^ 0x5c;
        }
        let mut outer = Sha512::new();
        outer.update(pads.as_slice());
        outer.update(inner_digest.as_slice());
        outer.update(entropy);
        outer.update(self.signed);
        inner_digest.as_mut_slice().zeroize();
        let mut legacy_digest = outer.finalize();
        let legacy_valid = bool::from(legacy_digest.as_slice().ct_eq(self.signature));
        legacy_digest.as_mut_slice().zeroize();
        if !standard_valid && !legacy_valid {
            return Err(DpapiError::AuthenticationFailed);
        }
        check_cancel(cancel)?;
        let mut derivation_input =
            Zeroizing::new(Vec::with_capacity(self.salt.len() + entropy.len()));
        derivation_input.extend_from_slice(self.salt);
        derivation_input.extend_from_slice(entropy);
        let session = hmac512(key_hash, &derivation_input)?;
        let mut plaintext = Zeroizing::new(self.ciphertext.to_vec());
        let length = cbc::Decryptor::<Aes256>::new_from_slices(&session[..32], &[0; 16])
            .map_err(|_| DpapiError::Malformed {
                field: "blob AES key",
            })?
            .decrypt_padded_mut::<Pkcs7>(&mut plaintext)
            .map_err(|_| DpapiError::AuthenticationFailed)?
            .len();
        // Erase the tail before shortening the allocation.
        plaintext[length..].zeroize();
        plaintext.truncate(length);
        check_cancel(cancel)?;
        Ok(plaintext)
    }
}

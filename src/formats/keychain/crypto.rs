use super::{KeychainError, MAX_RECORD_BYTES, Result, Section, malformed};
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use des::TdesEde3;
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub(super) const DB_HEADER_BYTES: usize = 92;
pub(super) const KEY_HEADER_BYTES: usize = 136;
const BLOB_MAGIC: u32 = 0xfade_0711;
const CMS_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

pub(super) struct Blob<'a> {
    pub(super) section: Section<'a>,
    pub(super) version: u32,
    pub(super) crypto_offset: usize,
    pub(super) header_size: usize,
}
impl<'a> Blob<'a> {
    pub(super) fn parse(section: Section<'a>, header_size: usize) -> Result<Self> {
        section.part(0, header_size, "blob header")?;
        if section.u32(0, "blob magic")? != BLOB_MAGIC {
            return Err(malformed("blob magic", section.offset));
        }
        let crypto_offset = section.usize(8, "encrypted section offset")?;
        let total = section.usize(12, "blob size")?;
        if total > MAX_RECORD_BYTES {
            return Err(KeychainError::LimitExceeded {
                field: "blob bytes",
            });
        }
        if crypto_offset < header_size || crypto_offset > total || total != section.bytes.len() {
            return Err(malformed("blob bounds", section.offset));
        }
        let ciphertext_length = total - crypto_offset;
        if ciphertext_length == 0 || !ciphertext_length.is_multiple_of(8) {
            return Err(malformed(
                "blob ciphertext length",
                section.offset + crypto_offset,
            ));
        }
        Ok(Self {
            section,
            version: section.u32(4, "blob version")?,
            crypto_offset,
            header_size,
        })
    }
    pub(super) fn check_version(&self) -> Result<()> {
        if ![0x100, 0x101, 0x200].contains(&self.version) {
            return Err(KeychainError::UnsupportedVersion {
                format: "blob",
                version: self.version,
            });
        }
        Ok(())
    }
    pub(super) fn verify(&self, signing_key: &[u8; 20]) -> Result<()> {
        self.check_version()?;
        let signature_offset = self.header_size - 20;
        let chunks = [
            &self.section.bytes[..signature_offset],
            &self.section.bytes[self.header_size..],
        ];
        let signature = if self.version == 0x100 {
            legacy_mac(signing_key, &chunks)
        } else {
            let mut mac = Hmac::<Sha1>::new_from_slice(signing_key)
                .map_err(|_| KeychainError::AuthenticationFailed)?;
            for chunk in chunks {
                mac.update(chunk);
            }
            let mut digest = mac.finalize().into_bytes();
            let mut result = Zeroizing::new([0; 20]);
            result.copy_from_slice(&digest);
            digest.as_mut_slice().zeroize();
            result
        };
        if bool::from(
            signature
                .as_slice()
                .ct_eq(&self.section.bytes[signature_offset..self.header_size]),
        ) {
            Ok(())
        } else {
            Err(KeychainError::AuthenticationFailed)
        }
    }
    pub(super) fn ciphertext(&self) -> &[u8] {
        &self.section.bytes[self.crypto_offset..]
    }
}

// Apple HmacSha1Legacy.c reproduces the BSAFE 4.0 multi-update bug: every
// update completes an inner digest and starts the outer digest. The next
// update appends another ipad and chunk to that outer state. The two chunk
// boundaries in dbcrypto.cpp are therefore part of the file format.
fn legacy_mac(key: &[u8; 20], chunks: &[&[u8]]) -> Zeroizing<[u8; 20]> {
    let mut ipad = Zeroizing::new([0x36; 64]);
    let mut opad = Zeroizing::new([0x5c; 64]);
    for (i, byte) in key.iter().enumerate() {
        ipad[i] ^= byte;
        opad[i] ^= byte;
    }
    let mut state = Sha1::new();
    for chunk in chunks {
        state.update(ipad.as_slice());
        state.update(chunk);
        let mut inner = state.finalize_reset();
        state.update(opad.as_slice());
        state.update(inner.as_slice());
        inner.as_mut_slice().zeroize();
    }
    let mut digest = state.finalize();
    let mut result = Zeroizing::new([0; 20]);
    result.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    result
}

pub(super) fn decrypt(key: &[u8; 24], iv: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext.len() > MAX_RECORD_BYTES {
        return Err(KeychainError::LimitExceeded {
            field: "ciphertext bytes",
        });
    }
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(8) {
        return Err(KeychainError::InvalidPayload);
    }
    let mut plain = Zeroizing::new(ciphertext.to_vec());
    let length = cbc::Decryptor::<TdesEde3>::new_from_slices(key, iv)
        .map_err(|_| KeychainError::InvalidPayload)?
        .decrypt_padded_mut::<Pkcs7>(&mut plain)
        .map_err(|_| KeychainError::InvalidPayload)?
        .len();
    // Erase the discarded tail before Vec::truncate changes its logical length.
    plain[length..].zeroize();
    plain.truncate(length);
    Ok(plain)
}

pub(super) fn unwrap_key(
    blob: &Blob<'_>,
    encryption_key: &[u8; 24],
) -> Result<Zeroizing<[u8; 24]>> {
    // Apple custom wrapping: decrypt using the CMS IV, reverse *all* bytes,
    // extract the embedded IV, then decrypt again. Descriptive data is variable.
    let mut outer = decrypt(encryption_key, &CMS_IV, blob.ciphertext())?;
    outer.reverse();
    if outer.len() <= 8 {
        return Err(KeychainError::InvalidPayload);
    }
    let inner = decrypt(encryption_key, &outer[..8], &outer[8..])?;
    let section = Section {
        bytes: &inner,
        offset: 0,
    };
    let description_size = section
        .usize(0, "wrapped key descriptive data size")
        .map_err(|_| KeychainError::InvalidPayload)?;
    let key_offset = 4usize
        .checked_add(description_size)
        .ok_or(KeychainError::InvalidPayload)?;
    let key = inner
        .get(key_offset..)
        .ok_or(KeychainError::InvalidPayload)?;
    if key.len() != 24 {
        return Err(KeychainError::UnsupportedProtection);
    }
    let mut result = Zeroizing::new([0; 24]);
    result.copy_from_slice(key);
    Ok(result)
}

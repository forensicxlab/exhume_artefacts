//! Offline Chromium/Electron OS Crypt envelopes.
//!
//! Supports **macOS** synchronous `v10`: PBKDF2-HMAC-SHA1 with the
//! exact Safe Storage password bytes, `saltysalt`, 1003 rounds, AES-128-CBC and
//! an IV of sixteen spaces. This is distinct from Windows `v10` GCM and Linux
//! password/backend handling; the version prefix alone does not identify an OS.
//! Linux `v11` uses the exact Secret Service/KWallet Safe Storage value with
//! one PBKDF2 iteration. Legacy Linux `v10` uses the fixed password `peanuts`.
//! Neither CBC envelope has an authentication tag. No fallback is attempted
//! between envelopes or credential values.
//!
//! CBC has no authentication tag. Successful decoding returns a candidate,
//! never proof that the password, ciphertext or plaintext is authentic. For
//! Signal Desktop, validate the returned 64-character hexadecimal database key
//! with SQLCipher before parsing messages. Keychain blob authentication does
//! not authenticate this envelope or the Keychain item's password payload.
//!
//! No Keychain access, key discovery, JSON configuration parsing, plaintext
//! fallback, password guessing or application-specific validation occurs here.
//! Source references: Electron `v45.2.1`'s `electron_api_safe_storage.cc` calls
//! synchronous `OSCrypt`; Chromium `143.0.7497.1`'s `os_crypt_mac.mm` defines
//! the supported envelope. See module tests for an independent Python vector.

use crate::core::ParserSecret;
use aes::Aes128;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use sha1::Sha1;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::{Zeroize, Zeroizing};

/// Maximum encoded envelope size, including the three-byte prefix, in bytes.
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
/// Maximum exact Safe Storage password size, in bytes.
pub const MAX_PASSWORD_BYTES: usize = 1024 * 1024;

/// Decoding failures never contain submitted or recovered secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OsCryptError {
    Truncated,
    UnsupportedEnvelope,
    InvalidLength,
    EmptyPassword,
    MissingPassword,
    InvalidKeyLength,
    AuthenticationFailed,
    LimitExceeded,
    /// Padding failed; this does not distinguish wrong keys from damaged data.
    DecryptionFailed,
    Cancelled,
}

impl fmt::Display for OsCryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated OS Crypt envelope",
            Self::UnsupportedEnvelope => "unsupported OS Crypt envelope for this platform",
            Self::InvalidLength => "invalid OS Crypt ciphertext length",
            Self::EmptyPassword => "Safe Storage password is empty",
            Self::MissingPassword => "Linux v11 recovery requires the exact Safe Storage password",
            Self::InvalidKeyLength => "Windows OS Crypt storage key must contain 32 bytes",
            Self::AuthenticationFailed => "Windows OS Crypt envelope authentication failed",
            Self::LimitExceeded => "OS Crypt input exceeds the decoder byte limit",
            Self::DecryptionFailed => {
                "OS Crypt decryption failed; the password or evidence may be incorrect"
            }
            Self::Cancelled => "OS Crypt decryption cancelled",
        })
    }
}
impl std::error::Error for OsCryptError {}

fn check_cancel(cancel: Option<&AtomicBool>) -> Result<(), OsCryptError> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        Err(OsCryptError::Cancelled)
    } else {
        Ok(())
    }
}

/// Decode a macOS `v10` envelope using the exact recovered Safe Storage value.
///
/// The password is used as stored: no whitespace trimming, Base64 decoding or
/// login-password substitution. Bytes before the ciphertext must be `v10`.
/// The returned [`ParserSecret`] is erased on drop and redacted in Debug; the
/// caller must erase any additional copies. Validate it in the consuming app.
///
/// Cancellation is checked before/after the fixed, bounded derivation and after
/// decryption. No native OS API, global cache or source write is performed.
pub fn decrypt_macos_v10(
    envelope: &[u8],
    safe_storage_password: &[u8],
    cancel: Option<&AtomicBool>,
) -> Result<ParserSecret, OsCryptError> {
    decrypt_cbc(envelope, b"v10", safe_storage_password, 1003, cancel)
}

/// Decode a Linux synchronous OS Crypt envelope. `v11` requires the exact
/// recovered Safe Storage bytes, without Base64 decoding or trimming. `v10`
/// explicitly selects Chromium's legacy fixed-password format. A supplied
/// password is unused for `v10`; a failed `v11` never selects a legacy key.
/// Validate the unauthenticated plaintext with the consuming application.
pub fn decrypt_linux(
    envelope: &[u8],
    safe_storage_password: Option<&[u8]>,
    cancel: Option<&AtomicBool>,
) -> Result<ParserSecret, OsCryptError> {
    check_cancel(cancel)?;
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(OsCryptError::LimitExceeded);
    }
    let prefix = envelope.get(..3).ok_or(OsCryptError::Truncated)?;
    match prefix {
        b"v10" => decrypt_cbc(envelope, b"v10", b"peanuts", 1, cancel),
        b"v11" => decrypt_cbc(
            envelope,
            b"v11",
            safe_storage_password.ok_or(OsCryptError::MissingPassword)?,
            1,
            cancel,
        ),
        _ => Err(OsCryptError::UnsupportedEnvelope),
    }
}

fn decrypt_cbc(
    envelope: &[u8],
    expected_prefix: &[u8; 3],
    safe_storage_password: &[u8],
    iterations: u32,
    cancel: Option<&AtomicBool>,
) -> Result<ParserSecret, OsCryptError> {
    check_cancel(cancel)?;
    if envelope.len() > MAX_ENVELOPE_BYTES || safe_storage_password.len() > MAX_PASSWORD_BYTES {
        return Err(OsCryptError::LimitExceeded);
    }
    let prefix = envelope.get(..3).ok_or(OsCryptError::Truncated)?;
    if prefix != expected_prefix {
        return Err(OsCryptError::UnsupportedEnvelope);
    }
    let ciphertext = &envelope[3..];
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(OsCryptError::InvalidLength);
    }
    if safe_storage_password.is_empty() {
        return Err(OsCryptError::EmptyPassword);
    }
    let mut key = Zeroizing::new([0u8; 16]);
    pbkdf2::pbkdf2_hmac::<Sha1>(
        safe_storage_password,
        b"saltysalt",
        iterations,
        key.as_mut(),
    );
    check_cancel(cancel)?;
    let mut plain = Zeroizing::new(ciphertext.to_vec());
    let length = cbc::Decryptor::<Aes128>::new_from_slices(key.as_slice(), &[b' '; 16])
        .map_err(|_| OsCryptError::DecryptionFailed)?
        .decrypt_padded_mut::<Pkcs7>(&mut plain)
        .map_err(|_| OsCryptError::DecryptionFailed)?
        .len();
    plain[length..].zeroize();
    plain.truncate(length);
    check_cancel(cancel)?;
    Ok(ParserSecret::new(std::mem::take(&mut *plain)))
}

/// Authenticate a Windows `v10 | nonce[12] | ciphertext | tag[16]` envelope.
/// The storage key is the exact 32-byte DPAPI plaintext; associated data is empty.
pub fn decrypt_windows_v10(
    envelope: &[u8],
    storage_key: &[u8],
    cancel: Option<&AtomicBool>,
) -> Result<ParserSecret, OsCryptError> {
    use aes_gcm::{
        Aes256Gcm, Nonce, Tag,
        aead::{AeadInPlace, KeyInit},
    };
    check_cancel(cancel)?;
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(OsCryptError::LimitExceeded);
    }
    if storage_key.len() != 32 {
        return Err(OsCryptError::InvalidKeyLength);
    }
    if envelope.get(..3) != Some(b"v10") {
        return Err(OsCryptError::UnsupportedEnvelope);
    }
    if envelope.len() < 31 {
        return Err(OsCryptError::Truncated);
    }
    let tag_start = envelope.len() - 16;
    let mut plaintext = Zeroizing::new(envelope[15..tag_start].to_vec());
    let cipher =
        Aes256Gcm::new_from_slice(storage_key).map_err(|_| OsCryptError::InvalidKeyLength)?;
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&envelope[3..15]),
            b"",
            plaintext.as_mut_slice(),
            Tag::from_slice(&envelope[tag_start..]),
        )
        .map_err(|_| OsCryptError::AuthenticationFailed)?;
    check_cancel(cancel)?;
    Ok(ParserSecret::new(std::mem::take(&mut *plaintext)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::sqlite::sqlcipher::SqlCipherKey;

    #[test]
    fn linux_envelopes_use_exact_storage_bytes_and_never_try_other_keys() {
        let values: serde_json::Value =
            serde_json::from_str(include_str!("../recovery/fixtures/signal-linux.json")).unwrap();
        let password = values["safe_storage"].as_str().unwrap().as_bytes();
        let expected = values["database_key"].as_str().unwrap().as_bytes();
        for field in ["v10_config", "v11_config"] {
            let envelope = hex::decode(values[field]["encryptedKey"].as_str().unwrap()).unwrap();
            assert_eq!(
                decrypt_linux(&envelope, Some(password), None)
                    .unwrap()
                    .expose(),
                expected
            );
        }
        let envelope = hex::decode(values["v11_config"]["encryptedKey"].as_str().unwrap()).unwrap();
        assert_eq!(
            decrypt_linux(&envelope, None, None).unwrap_err(),
            OsCryptError::MissingPassword
        );
        assert_eq!(
            decrypt_linux(&envelope, Some(b""), None).unwrap_err(),
            OsCryptError::EmptyPassword
        );
        assert!(
            decrypt_linux(
                &envelope,
                Some(values["safe_storage"].as_str().unwrap().trim().as_bytes()),
                None
            )
            .is_err()
        );
        assert!(decrypt_macos_v10(&envelope, password, None).is_err());
        assert_eq!(
            decrypt_linux(&envelope, Some(password), Some(&AtomicBool::new(true))).unwrap_err(),
            OsCryptError::Cancelled
        );
    }

    #[test]
    fn linux_envelope_inputs_are_bounded_and_framed() {
        for envelope in [b"v11".as_slice(), b"v10z"] {
            assert_eq!(
                decrypt_linux(envelope, Some(b"test"), None).unwrap_err(),
                OsCryptError::InvalidLength
            );
        }
        assert_eq!(
            decrypt_linux(b"v", None, None).unwrap_err(),
            OsCryptError::Truncated
        );
        assert_eq!(
            decrypt_linux(b"v99", None, None).unwrap_err(),
            OsCryptError::UnsupportedEnvelope
        );
        let mut envelope = vec![0; MAX_ENVELOPE_BYTES + 1];
        envelope[..3].copy_from_slice(b"v11");
        assert_eq!(
            decrypt_linux(&envelope, None, None).unwrap_err(),
            OsCryptError::LimitExceeded
        );
    }

    // Generated independently with hashlib.pbkdf2_hmac('sha1', ..., 1003, 16)
    // and PyCryptodome AES.MODE_CBC / pad(..., 16). All inputs are invented.
    const PASSWORD: &[u8] = b"SYNTHETIC-PASSWORD+with/base64==\n";
    const EXPECTED: &[u8] = b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const VECTOR: &str = "763130e73e44a5d2125774bc82e233b5f416b948da4f7cc2cdb1cb68c56f2ba4fa2359d7eb1ee6832e022ada48e18fce6260f2992d60ff0d662ce26ecc4cfea82ac8ed378927041b854568f6691e43b6396f24";

    #[test]
    fn decodes_the_independent_vector_and_returns_a_redacted_secret() {
        let envelope = hex::decode(VECTOR).unwrap();
        let candidate = decrypt_macos_v10(&envelope, PASSWORD, None).unwrap();
        assert_eq!(candidate.expose(), EXPECTED);
        assert_eq!(format!("{candidate:?}"), "[REDACTED]");
        assert!(SqlCipherKey::from_hex(candidate.expose()).is_ok());
    }

    #[test]
    fn preserves_exact_password_bytes_and_reports_decoding_failures_safely() {
        let envelope = hex::decode(VECTOR).unwrap();
        for password in [b"wrong".as_slice(), &PASSWORD[..PASSWORD.len() - 1]] {
            let error = decrypt_macos_v10(&envelope, password, None).unwrap_err();
            assert_eq!(error, OsCryptError::DecryptionFailed);
            assert!(!error.to_string().contains("SYNTHETIC"));
        }
        assert_eq!(
            decrypt_macos_v10(&envelope, b"", None).unwrap_err(),
            OsCryptError::EmptyPassword
        );
    }

    #[test]
    fn does_not_misrepresent_valid_padding_as_authentication() {
        let mut envelope = hex::decode(VECTOR).unwrap();
        // Damage early blocks while leaving the final padding block intact.
        envelope[3] ^= 1;
        let candidate = decrypt_macos_v10(&envelope, PASSWORD, None).unwrap();
        assert_ne!(candidate.expose(), EXPECTED);
        assert!(SqlCipherKey::from_hex(candidate.expose()).is_err());
    }

    #[test]
    fn rejects_bad_prefixes_lengths_limits_and_cancellation() {
        let envelope = hex::decode(VECTOR).unwrap();
        for bytes in [b"".as_slice(), b"v", b"v1"] {
            assert_eq!(
                decrypt_macos_v10(bytes, PASSWORD, None).unwrap_err(),
                OsCryptError::Truncated
            );
        }
        for bytes in [b"v11".as_slice(), b"v20", b"abc"] {
            assert_eq!(
                decrypt_macos_v10(bytes, PASSWORD, None).unwrap_err(),
                OsCryptError::UnsupportedEnvelope
            );
        }
        for size in [3, 4, 18, 20, envelope.len() - 1] {
            assert_eq!(
                decrypt_macos_v10(&envelope[..size], PASSWORD, None).unwrap_err(),
                OsCryptError::InvalidLength
            );
        }
        assert_eq!(
            decrypt_macos_v10(&vec![0; MAX_ENVELOPE_BYTES + 1], PASSWORD, None).unwrap_err(),
            OsCryptError::LimitExceeded
        );
        assert_eq!(
            decrypt_macos_v10(&envelope, &vec![0; MAX_PASSWORD_BYTES + 1], None).unwrap_err(),
            OsCryptError::LimitExceeded
        );
        assert_eq!(
            decrypt_macos_v10(&envelope, PASSWORD, Some(&AtomicBool::new(true))).unwrap_err(),
            OsCryptError::Cancelled
        );
    }
    #[test]
    fn gcm_tampering_cancellation_and_bounds_never_release_plaintext() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../recovery/fixtures/signal-keys.json")).unwrap();
        let envelope =
            hex::decode(fixture["windows_config"]["encryptedKey"].as_str().unwrap()).unwrap();
        let key: Vec<u8> = (0..32).collect();
        for offset in [3, 15, envelope.len() - 1] {
            let mut damaged = envelope.clone();
            damaged[offset] ^= 1;
            assert_eq!(
                decrypt_windows_v10(&damaged, &key, None).unwrap_err(),
                OsCryptError::AuthenticationFailed
            );
        }
        assert_eq!(
            decrypt_windows_v10(&envelope, &key[..31], None).unwrap_err(),
            OsCryptError::InvalidKeyLength
        );
        assert_eq!(
            decrypt_windows_v10(
                &envelope,
                &key,
                Some(&std::sync::atomic::AtomicBool::new(true))
            )
            .unwrap_err(),
            OsCryptError::Cancelled
        );
        for length in 3..31 {
            assert!(decrypt_windows_v10(&envelope[..length], &key, None).is_err());
        }
    }
}

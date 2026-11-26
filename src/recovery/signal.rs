//! Signal key envelopes. Callers locate acquired files and authenticate stores;
//! validate returned candidates with the existing `desktop_signal` parser.

pub mod attachment;

use crate::{
    ParserSecret,
    formats::{
        dpapi::{Blob, DpapiError, MasterKey},
        os_crypt::{self, OsCryptError},
        sqlite::sqlcipher::SqlCipherKey,
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer};
use std::{fmt, sync::atomic::AtomicBool};
use zeroize::Zeroizing;

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// Framing only: `V10` does not identify the operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeKind {
    Plaintext,
    V10,
    V11,
    Dpapi,
    Unsupported,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum SignalRecoveryError {
    InvalidConfiguration,
    LimitExceeded,
    MissingLocalState,
    UnsupportedEnvelope,
    InvalidDatabaseKey,
    Dpapi(DpapiError),
    OsCrypt(OsCryptError),
}
impl fmt::Display for SignalRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => f.write_str("malformed Signal key configuration"),
            Self::LimitExceeded => f.write_str("Signal configuration exceeds the byte limit"),
            Self::MissingLocalState => {
                f.write_str("Windows v10 recovery requires Signal Local State")
            }
            Self::UnsupportedEnvelope => f.write_str("unsupported Signal key envelope"),
            Self::InvalidDatabaseKey => {
                f.write_str("recovered Signal key is not exactly 64 ASCII hexadecimal characters")
            }
            Self::Dpapi(e) => e.fmt(f),
            Self::OsCrypt(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for SignalRecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Dpapi(e) => Some(e),
            Self::OsCrypt(e) => Some(e),
            _ => None,
        }
    }
}
impl From<DpapiError> for SignalRecoveryError {
    fn from(e: DpapiError) -> Self {
        Self::Dpapi(e)
    }
}
impl From<OsCryptError> for SignalRecoveryError {
    fn from(e: OsCryptError) -> Self {
        Self::OsCrypt(e)
    }
}

// A present null is invalid. Damaged encryptedKey must not select plaintext key.
#[derive(Default)]
struct ConfigString(Option<Zeroizing<String>>);
impl<'de> Deserialize<'de> for ConfigString {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|value| Self(Some(Zeroizing::new(value))))
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigFields {
    #[serde(default)]
    encrypted_key: ConfigString,
    #[serde(default)]
    key: ConfigString,
}

/// Owned, redacted envelope. Plaintext configuration keys are erased on drop.
pub struct SignalKeyEnvelope {
    kind: EnvelopeKind,
    bytes: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for SignalKeyEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignalKeyEnvelope")
            .field("kind", &self.kind)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}
impl SignalKeyEnvelope {
    pub fn parse(config: &[u8]) -> Result<Self, SignalRecoveryError> {
        if config.len() > MAX_CONFIG_BYTES {
            return Err(SignalRecoveryError::LimitExceeded);
        }
        let mut fields: ConfigFields = serde_json::from_slice(config)
            .map_err(|_| SignalRecoveryError::InvalidConfiguration)?;
        if let Some(encoded) = fields.encrypted_key.0.take() {
            let bytes = Zeroizing::new(
                hex::decode(encoded.as_bytes())
                    .map_err(|_| SignalRecoveryError::InvalidConfiguration)?,
            );
            let kind = if bytes.starts_with(b"v10") {
                EnvelopeKind::V10
            } else if bytes.starts_with(b"v11") {
                EnvelopeKind::V11
            } else if bytes.starts_with(&[1, 0, 0, 0]) {
                Blob::parse(&bytes)?;
                EnvelopeKind::Dpapi
            } else {
                EnvelopeKind::Unsupported
            };
            Ok(Self { kind, bytes })
        } else if let Some(mut key) = fields.key.0.take() {
            let bytes = Zeroizing::new(std::mem::take(&mut *key).into_bytes());
            check_key(&bytes)?;
            Ok(Self {
                kind: EnvelopeKind::Plaintext,
                bytes,
            })
        } else {
            Err(SignalRecoveryError::InvalidConfiguration)
        }
    }
    pub fn kind(&self) -> EnvelopeKind {
        self.kind
    }
    pub fn plaintext_key(&self) -> Option<ParserSecret> {
        (self.kind == EnvelopeKind::Plaintext).then(|| ParserSecret::new(self.bytes.to_vec()))
    }
    /// Discover the required GUID without recovering a secret.
    pub fn windows_master_key_guid(
        &self,
        local_state: Option<&[u8]>,
    ) -> Result<String, SignalRecoveryError> {
        let blob = self.windows_blob(local_state)?;
        Ok(Blob::parse(&blob)?.metadata().master_key_guid.clone())
    }
    pub fn recover_windows(
        &self,
        local_state: Option<&[u8]>,
        master: &MasterKey,
        cancel: Option<&AtomicBool>,
    ) -> Result<ParserSecret, SignalRecoveryError> {
        let blob = self.windows_blob(local_state)?;
        let recovered = Blob::parse(&blob)?.decrypt(master, None, cancel)?;
        let candidate = match self.kind {
            EnvelopeKind::Dpapi => ParserSecret::new(recovered.to_vec()),
            EnvelopeKind::V10 => os_crypt::decrypt_windows_v10(&self.bytes, &recovered, cancel)?,
            _ => return Err(SignalRecoveryError::UnsupportedEnvelope),
        };
        check_key(candidate.expose())?;
        Ok(candidate)
    }
    /// CBC plaintext is a candidate; validate it against the acquired database.
    pub fn recover_macos(
        &self,
        safe_storage: &[u8],
        cancel: Option<&AtomicBool>,
    ) -> Result<ParserSecret, SignalRecoveryError> {
        if self.kind != EnvelopeKind::V10 {
            return Err(SignalRecoveryError::UnsupportedEnvelope);
        }
        let candidate = os_crypt::decrypt_macos_v10(&self.bytes, safe_storage, cancel)?;
        check_key(candidate.expose())?;
        Ok(candidate)
    }
    /// Decode a Linux `v10`/`v11` key envelope. Supply the exact recovered
    /// Safe Storage value for `v11`. Legacy `v10` needs no secret-store input.
    /// CBC and the GNOME Keyring MD5 do not authenticate a database key;
    /// validate the returned candidate through the SQLCipher parser.
    pub fn recover_linux(
        &self,
        safe_storage: Option<&[u8]>,
        cancel: Option<&AtomicBool>,
    ) -> Result<ParserSecret, SignalRecoveryError> {
        if !matches!(self.kind, EnvelopeKind::V10 | EnvelopeKind::V11) {
            return Err(SignalRecoveryError::UnsupportedEnvelope);
        }
        let candidate = os_crypt::decrypt_linux(&self.bytes, safe_storage, cancel)?;
        check_key(candidate.expose())?;
        Ok(candidate)
    }
    fn windows_blob(
        &self,
        local_state: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, SignalRecoveryError> {
        match self.kind {
            EnvelopeKind::Dpapi => Ok(Zeroizing::new(self.bytes.to_vec())),
            EnvelopeKind::V10 => {
                let input = local_state.ok_or(SignalRecoveryError::MissingLocalState)?;
                if input.len() > MAX_CONFIG_BYTES {
                    return Err(SignalRecoveryError::LimitExceeded);
                }
                #[derive(Deserialize)]
                struct State {
                    os_crypt: Crypt,
                }
                #[derive(Deserialize)]
                struct Crypt {
                    encrypted_key: String,
                }
                let state: State = serde_json::from_slice(input)
                    .map_err(|_| SignalRecoveryError::InvalidConfiguration)?;
                let wrapped = STANDARD
                    .decode(state.os_crypt.encrypted_key)
                    .map_err(|_| SignalRecoveryError::InvalidConfiguration)?;
                if wrapped.get(..5) != Some(b"DPAPI") {
                    return Err(SignalRecoveryError::UnsupportedEnvelope);
                }
                let blob = Zeroizing::new(wrapped[5..].to_vec());
                Blob::parse(&blob)?;
                Ok(blob)
            }
            _ => Err(SignalRecoveryError::UnsupportedEnvelope),
        }
    }
}
fn check_key(bytes: &[u8]) -> Result<(), SignalRecoveryError> {
    SqlCipherKey::from_hex(bytes)
        .map(|_| ())
        .map_err(|_| SignalRecoveryError::InvalidDatabaseKey)
}

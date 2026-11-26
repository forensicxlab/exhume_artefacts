//! Synthetic, deterministic vectors generated with PyCryptodome and checked
//! with Impacket 0.13.1. Contains no acquired user data.
pub(crate) const PASSWORD: &str = "fixture password ☃";
pub(crate) const SID: &str = "S-1-5-21-123-456-789-1001";
pub(crate) const GUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
pub(crate) const MASTER_FILE: &str = include_str!("fixtures/master_file.hex");
pub(crate) const BLOB: &str = include_str!("fixtures/blob.hex");
pub(crate) const BLOB_ENTROPY: &str = include_str!("fixtures/blob_entropy.hex");
pub(crate) const BLOB_LEGACY_SIGNATURE: &str = include_str!("fixtures/blob_legacy_signature.hex");

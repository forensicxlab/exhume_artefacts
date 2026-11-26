use super::crypto::{self, Blob, DB_HEADER_BYTES, KEY_HEADER_BYTES};
use super::{
    KeychainError, MAX_INPUT_BYTES, MAX_PASSWORD_BYTES, MAX_RECORD_BYTES, MAX_RECORD_SLOTS,
    MAX_TABLES, Result, Section, check_cancel, malformed,
};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;
use sha2::Sha256;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::AtomicBool;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const GENERIC_PASSWORD: u32 = 0x8000_0000;
pub(crate) const SYMMETRIC_KEY: u32 = 0x11;
const METADATA: u32 = 0x8000_8000;
pub(crate) const GENERIC_HEADER_BYTES: usize = 88;
const KEY_RECORD_HEADER_BYTES: usize = 132;

/// Structural information only; parsing alone does not authenticate it.
#[derive(Debug, Clone, Serialize)]
pub struct KeychainMetadata {
    pub file_version: u32,
    pub blob_version: Option<u32>,
    pub database_blob_offset: Option<usize>,
    pub table_count: usize,
    pub generic_password_count: usize,
    pub symmetric_key_count: usize,
}

/// A bounded, borrowed file-based Keychain. It never opens files or calls macOS.
/// Metadata/table validation does not establish item integrity or decrypt data.
pub struct LegacyKeychain<'a> {
    pub(crate) tables: Vec<Table<'a>>,
    database_blob: Option<Blob<'a>>,
    metadata: KeychainMetadata,
}

impl fmt::Debug for LegacyKeychain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.metadata.fmt(f)
    }
}

pub(crate) struct Table<'a> {
    pub(crate) id: u32,
    pub(crate) offset: usize,
    pub(crate) records: Vec<Record<'a>>,
}

#[derive(Clone, Copy)]
pub(crate) struct Record<'a> {
    pub(crate) section: Section<'a>,
    pub(crate) number: u32,
}

impl<'a> Record<'a> {
    pub(crate) fn data(&self, header_size: usize) -> Result<Section<'a>> {
        self.section.part(0, header_size, "record header")?;
        self.section.part(
            header_size,
            self.section.usize(16, "record data size")?,
            "record data",
        )
    }

    // The low bit means one value; otherwise an explicit value count precedes
    // the value. Never read an attribute from a neighbouring record.
    pub(crate) fn value(&self, index: usize, header_size: usize) -> Result<Option<Section<'a>>> {
        let slot = index
            .checked_mul(4)
            .and_then(|n| n.checked_add(24))
            .ok_or_else(|| malformed("attribute index", self.section.offset))?;
        if slot.checked_add(4).is_none_or(|end| end > header_size) {
            return Err(malformed("attribute slot", self.section.offset));
        }
        let raw = self.section.usize(slot, "attribute offset")?;
        if raw == 0 {
            return Ok(None);
        }
        let mut offset = raw & !1;
        let data = self.data(header_size)?;
        let data_end = header_size
            .checked_add(data.bytes.len())
            .ok_or_else(|| malformed("record data size", self.section.offset))?;
        if !offset.is_multiple_of(4) || offset < data_end || offset >= self.section.bytes.len() {
            return Err(malformed("attribute offset", self.section.offset + slot));
        }
        if raw & 1 == 0 {
            match self.section.u32(offset, "attribute value count")? {
                0 => return Ok(None),
                1 => offset += 4,
                _ => {
                    return Err(KeychainError::UnsupportedAttribute {
                        offset: self.section.offset + slot,
                    });
                }
            }
        }
        Ok(Some(self.section.part(
            offset,
            self.section.bytes.len() - offset,
            "attribute value",
        )?))
    }

    pub(crate) fn blob_attribute(
        &self,
        index: usize,
        header_size: usize,
    ) -> Result<Option<Section<'a>>> {
        self.value(index, header_size)?
            .map(|value| value.part(4, value.usize(0, "attribute length")?, "attribute bytes"))
            .transpose()
    }
}

/// Metadata and encrypted data for one generic-password record.
/// Service/account comparisons are byte-exact; no UTF-8 replacement or trimming.
#[derive(Clone, Copy)]
pub struct GenericPassword<'a> {
    record: Record<'a>,
    service: Option<Section<'a>>,
    account: Option<Section<'a>>,
}
impl<'a> GenericPassword<'a> {
    pub fn service(&self) -> Option<&'a [u8]> {
        self.service.map(|s| s.bytes)
    }
    pub fn account(&self) -> Option<&'a [u8]> {
        self.account.map(|s| s.bytes)
    }
    pub fn record_offset(&self) -> usize {
        self.record.section.offset
    }
    pub fn record_number(&self) -> u32 {
        self.record.number
    }
}

/// Authenticated database keys and their source Keychain; secrets are erased on
/// drop, redacted in Debug and never serialized. This does not authenticate the
/// file's searchable attributes or individual password payloads.
pub struct UnlockedKeychain<'a> {
    file: LegacyKeychain<'a>,
    encryption_key: Zeroizing<[u8; 24]>,
    signing_key: Zeroizing<[u8; 20]>,
}
impl fmt::Debug for UnlockedKeychain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedKeychain")
            .field("metadata", self.file.metadata())
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

/// A decoded generic-password payload. Its wrapping keys were authenticated;
/// its CBC ciphertext and service/account metadata have no authentication tag.
/// Treat the value as a candidate until the consuming application validates it.
/// The caller must erase any additional copies it retains.
pub struct RecoveredPassword {
    bytes: Zeroizing<Vec<u8>>,
    record_offset: usize,
    wrapping_key_record_offset: usize,
}
impl RecoveredPassword {
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }
    pub fn record_offset(&self) -> usize {
        self.record_offset
    }
    pub fn wrapping_key_record_offset(&self) -> usize {
        self.wrapping_key_record_offset
    }
}
impl fmt::Debug for RecoveredPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredPassword")
            .field("bytes", &"[REDACTED]")
            .field("record_offset", &self.record_offset)
            .field(
                "wrapping_key_record_offset",
                &self.wrapping_key_record_offset,
            )
            .finish()
    }
}

impl<'a> LegacyKeychain<'a> {
    /// Validate declared sections, live record slots, sizes and overlaps.
    /// Missing database protection remains inspectable but cannot be unlocked.
    /// File versions other than 0x10000 are explicitly unsupported.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(KeychainError::LimitExceeded {
                field: "input bytes",
            });
        }
        let file = Section { bytes, offset: 0 };
        if file.part(0, 4, "file magic")?.bytes != b"kych" {
            return Err(KeychainError::UnsupportedFormat);
        }
        let version = file.u32(4, "file version")?;
        if version != 0x1_0000 {
            return Err(KeychainError::UnsupportedVersion {
                format: "file",
                version,
            });
        }
        let schema_offset = file.usize(12, "schema offset")?;
        if schema_offset < 16 || !schema_offset.is_multiple_of(4) {
            return Err(malformed("schema offset", 12));
        }
        let schema_size = file.usize(schema_offset, "schema size")?;
        let schema = file.part(schema_offset, schema_size, "schema")?;
        let footer_offset = schema_offset
            .checked_add(schema_size)
            .ok_or_else(|| malformed("schema size", schema_offset))?;
        file.part(footer_offset, 4, "database version footer")?;
        let table_count = schema.usize(4, "table count")?;
        if table_count > MAX_TABLES {
            return Err(KeychainError::LimitExceeded { field: "tables" });
        }
        let directory_end = 8 + 4 * table_count;
        schema.part(0, directory_end, "table directory")?;
        let mut tables = Vec::with_capacity(table_count);
        let mut table_ranges = Vec::with_capacity(table_count);
        let mut ids = BTreeSet::new();
        let mut total_slots = 0usize;
        for i in 0..table_count {
            let offset = schema.usize(8 + 4 * i, "table offset")?;
            if offset < directory_end || !offset.is_multiple_of(4) {
                return Err(malformed("table offset", schema.offset + 8 + 4 * i));
            }
            let length = schema.usize(offset, "table size")?;
            let table = schema.part(offset, length, "table")?;
            table.part(0, 28, "table header")?;
            let id = table.u32(4, "table id")?;
            if !ids.insert(id) {
                return Err(malformed("duplicate table id", table.offset + 4));
            }
            let count = table.usize(8, "record count")?;
            let slots = table.usize(24, "record slot count")?;
            total_slots = total_slots
                .checked_add(slots)
                .ok_or(KeychainError::LimitExceeded {
                    field: "record slots",
                })?;
            if total_slots > MAX_RECORD_SLOTS {
                return Err(KeychainError::LimitExceeded {
                    field: "record slots",
                });
            }
            if count > slots {
                return Err(malformed("record count", table.offset + 8));
            }
            let slots_end = 28 + 4 * slots;
            table.part(0, slots_end, "record directory")?;
            let records_start = table.usize(12, "records offset")?;
            let indexes_start = table.usize(16, "indexes offset")?;
            if records_start < slots_end || records_start > indexes_start || indexes_start > length
            {
                return Err(malformed("table sections", table.offset));
            }
            let mut records = Vec::with_capacity(count);
            let mut ranges = Vec::with_capacity(count);
            for slot in 0..slots {
                let relative = table.usize(28 + slot * 4, "record offset")?;
                // Zero and odd links belong to the free list, not live rows.
                if relative == 0 || relative & 1 != 0 {
                    continue;
                }
                if !relative.is_multiple_of(4)
                    || relative < records_start
                    || relative >= indexes_start
                {
                    return Err(malformed("record offset", table.offset + 28 + slot * 4));
                }
                let size = table.usize(relative, "record size")?;
                if size > MAX_RECORD_BYTES {
                    return Err(KeychainError::LimitExceeded {
                        field: "record bytes",
                    });
                }
                if size < 24 || !size.is_multiple_of(4) || size > indexes_start - relative {
                    return Err(malformed("record size", table.offset + relative));
                }
                let section = table.part(relative, size, "record")?;
                let number = section.u32(4, "record number")?;
                if usize::try_from(number).ok() != Some(slot) {
                    return Err(malformed("record number", section.offset + 4));
                }
                records.push(Record { section, number });
                ranges.push((relative, relative + size));
            }
            if records.len() != count {
                return Err(malformed("live record count", table.offset + 8));
            }
            reject_overlaps(&mut ranges, table.offset, "overlapping records")?;
            tables.push(Table {
                id,
                offset: table.offset,
                records,
            });
            table_ranges.push((offset, offset + length));
        }
        reject_overlaps(&mut table_ranges, schema.offset, "overlapping tables")?;
        let mut database_blob = None;
        if let Some(table) = tables.iter().find(|table| table.id == METADATA) {
            if table.records.len() > 1 {
                return Err(malformed("database protection record count", table.offset));
            }
            if let Some(record) = table.records.first() {
                database_blob = Some(Blob::parse(record.data(24)?, DB_HEADER_BYTES)?);
            }
        }
        let metadata = KeychainMetadata {
            file_version: version,
            blob_version: database_blob.as_ref().map(|blob| blob.version),
            database_blob_offset: database_blob.as_ref().map(|blob| blob.section.offset),
            table_count,
            generic_password_count: tables
                .iter()
                .find(|t| t.id == GENERIC_PASSWORD)
                .map_or(0, |t| t.records.len()),
            symmetric_key_count: tables
                .iter()
                .find(|t| t.id == SYMMETRIC_KEY)
                .map_or(0, |t| t.records.len()),
        };
        Ok(Self {
            tables,
            database_blob,
            metadata,
        })
    }

    pub fn metadata(&self) -> &KeychainMetadata {
        &self.metadata
    }

    /// Check whether the database protection format is supported without a
    /// credential or KDF. This validates capabilities, not authentication.
    pub fn check_password_protection(&self) -> Result<()> {
        self.database_blob
            .as_ref()
            .ok_or(KeychainError::MissingDatabaseBlob)?
            .check_version()
    }

    /// Lowercase hexadecimal filename used by macOS to find this database's
    /// protected entropy under `/private/var/db/SystemKeys/`. The salt is public,
    /// untrusted metadata until authentication succeeds; no path is opened.
    /// A filename does not prove that the indirect protection route is in use.
    pub fn protected_entropy_identifier(&self) -> Option<String> {
        self.database_blob
            .as_ref()
            .map(|blob| hex::encode(&blob.section.bytes[44..64]))
    }

    /// Authenticate a login Keychain protected with a SystemKeys companion.
    ///
    /// `protected_entropy` is the exact 32-byte CFData value from the salt-matched
    /// SystemKeys plist, not its Base64/XML encoding. The caller owns evidence
    /// lookup and provenance for that companion. Derives the indirect password
    /// as HMAC-SHA256(entropy, password), then uses the ordinary blob KDF/MAC.
    /// No native Keychain/keybag API, device secret or analyst credential store
    /// is accessed. The caller must erase any retained entropy/password copies.
    pub fn unlock_login_password(
        self,
        password: &[u8],
        protected_entropy: &[u8; 32],
        cancel: Option<&AtomicBool>,
    ) -> Result<UnlockedKeychain<'a>> {
        check_cancel(cancel)?;
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(KeychainError::LimitExceeded {
                field: "password bytes",
            });
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(protected_entropy)
            .map_err(|_| KeychainError::AuthenticationFailed)?;
        mac.update(password);
        let mut digest = mac.finalize().into_bytes();
        let mut indirect = Zeroizing::new([0; 32]);
        indirect.copy_from_slice(&digest);
        digest.as_mut_slice().zeroize();
        self.unlock_password(indirect.as_slice(), cancel)
    }

    /// Return byte-exact selectors and source offsets. Malformed selectors are
    /// errors, never silently treated as missing or replaced with lossy UTF-8.
    pub fn generic_passwords(&self) -> Result<Vec<GenericPassword<'a>>> {
        let Some(table) = self
            .tables
            .iter()
            .find(|table| table.id == GENERIC_PASSWORD)
        else {
            return Ok(Vec::new());
        };
        table
            .records
            .iter()
            .map(|record| {
                record.data(GENERIC_HEADER_BYTES)?;
                Ok(GenericPassword {
                    record: *record,
                    service: record.blob_attribute(14, GENERIC_HEADER_BYTES)?,
                    account: record.blob_attribute(13, GENERIC_HEADER_BYTES)?,
                })
            })
            .collect()
    }

    /// Consume the parsed file and authenticate its database keys using exact
    /// password bytes, PBKDF2-HMAC-SHA1 (1000 rounds), 3DES-CBC and the full MAC.
    /// No password normalization or newline removal is performed. Cancellation
    /// is checked on either side of the fixed, bounded derivation.
    pub fn unlock_password(
        self,
        password: &[u8],
        cancel: Option<&AtomicBool>,
    ) -> Result<UnlockedKeychain<'a>> {
        check_cancel(cancel)?;
        self.check_password_protection()?;
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(KeychainError::LimitExceeded {
                field: "password bytes",
            });
        }
        let blob = self
            .database_blob
            .as_ref()
            .ok_or(KeychainError::MissingDatabaseBlob)?;
        blob.check_version()?;
        let mut master = Zeroizing::new([0; 24]);
        pbkdf2::pbkdf2_hmac::<Sha1>(password, &blob.section.bytes[44..64], 1000, master.as_mut());
        check_cancel(cancel)?;
        let plain = crypto::decrypt(&master, &blob.section.bytes[64..72], blob.ciphertext())
            .map_err(|_| KeychainError::AuthenticationFailed)?;
        if plain.len() < 44 {
            return Err(KeychainError::AuthenticationFailed);
        }
        let mut encryption_key = Zeroizing::new([0; 24]);
        let mut signing_key = Zeroizing::new([0; 20]);
        encryption_key.copy_from_slice(&plain[..24]);
        signing_key.copy_from_slice(&plain[24..44]);
        blob.verify(&signing_key)?;
        check_cancel(cancel)?;
        Ok(UnlockedKeychain {
            file: self,
            encryption_key,
            signing_key,
        })
    }
}

impl<'a> UnlockedKeychain<'a> {
    pub(crate) fn keychain(&self) -> &LegacyKeychain<'a> {
        &self.file
    }
    pub fn metadata(&self) -> &KeychainMetadata {
        self.file.metadata()
    }
    pub fn generic_passwords(&self) -> Result<Vec<GenericPassword<'a>>> {
        self.file.generic_passwords()
    }

    /// Decode one exact service/account match. Duplicate selectors or group-key
    /// labels are explicit errors. A missing item is distinct from a missing key.
    /// The returned payload is a candidate (see [`RecoveredPassword`]).
    pub fn recover_generic_password(
        &self,
        service: &[u8],
        account: &[u8],
        cancel: Option<&AtomicBool>,
    ) -> Result<RecoveredPassword> {
        check_cancel(cancel)?;
        let mut selected = None;
        for item in self.file.generic_passwords()? {
            check_cancel(cancel)?;
            if item.service() == Some(service)
                && item.account() == Some(account)
                && selected.replace(item).is_some()
            {
                return Err(KeychainError::AmbiguousItem);
            }
        }
        let item = selected.ok_or(KeychainError::ItemNotFound)?;
        let payload = item.record.data(GENERIC_HEADER_BYTES)?;
        if payload.bytes.len() < 36 || &payload.bytes[..4] != b"ssgp" {
            return Err(KeychainError::UnsupportedProtection);
        }
        let label = &payload.bytes[..20];
        let mut wrapping_record = None;
        if let Some(table) = self.file.tables.iter().find(|t| t.id == SYMMETRIC_KEY) {
            for record in &table.records {
                check_cancel(cancel)?;
                if record
                    .blob_attribute(6, KEY_RECORD_HEADER_BYTES)?
                    .is_some_and(|value| value.bytes == label)
                    && wrapping_record.replace(record).is_some()
                {
                    return Err(KeychainError::AmbiguousWrappingKey);
                }
            }
        }
        let record = wrapping_record.ok_or(KeychainError::MissingWrappingKey)?;
        let blob = Blob::parse(record.data(KEY_RECORD_HEADER_BYTES)?, KEY_HEADER_BYTES)?;
        blob.verify(&self.signing_key)?;
        let s = blob.section;
        // CSSM session key, 3DES/192 bits, Apple custom wrapped format.
        for (offset, expected) in [
            (24, 2),
            (52, 17),
            (56, 2),
            (60, 192),
            (100, 3),
            (104, 100),
            (108, 17),
            (112, 6),
        ] {
            if s.u32(offset, "wrapped key header")? != expected {
                return Err(KeychainError::UnsupportedProtection);
            }
        }
        let key = crypto::unwrap_key(&blob, &self.encryption_key)?;
        check_cancel(cancel)?;
        let bytes = crypto::decrypt(&key, &payload.bytes[20..28], &payload.bytes[28..])?;
        check_cancel(cancel)?;
        Ok(RecoveredPassword {
            bytes,
            record_offset: item.record_offset(),
            wrapping_key_record_offset: record.section.offset,
        })
    }
}

fn reject_overlaps(ranges: &mut [(usize, usize)], base: usize, field: &'static str) -> Result<()> {
    ranges.sort_unstable();
    if let Some(pair) = ranges.windows(2).find(|pair| pair[0].1 > pair[1].0) {
        return Err(malformed(field, base + pair[1].0));
    }
    Ok(())
}

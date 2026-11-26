use super::{AttributeValue, Attributes, KeyringError, Result};
use std::ops::Range;

const MAX_FIELD_BYTES: usize = 1024 * 1024;
const MAX_FIELDS: usize = 100_000;

/// Cursor offsets are relative to this buffer. For decrypted records that means
/// plaintext offsets, never physical ciphertext offsets.
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    pub(super) offset: usize,
    fields_left: usize,
}
impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            fields_left: MAX_FIELDS,
        }
    }
    pub(super) fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
    pub(super) fn rest(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }
    pub(super) fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(KeyringError::LimitExceeded { field })?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(KeyringError::Truncated {
                field,
                offset: self.offset,
            })?;
        self.offset = end;
        Ok(bytes)
    }
    pub(super) fn u32(&mut self, field: &'static str) -> Result<u32> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    pub(super) fn u64(&mut self, field: &'static str) -> Result<u64> {
        Ok((u64::from(self.u32(field)?) << 32) | u64::from(self.u32(field)?))
    }
    pub(super) fn count(&mut self, maximum: usize, field: &'static str) -> Result<usize> {
        let count =
            usize::try_from(self.u32(field)?).map_err(|_| KeyringError::LimitExceeded { field })?;
        if count > maximum {
            return Err(KeyringError::LimitExceeded { field });
        }
        Ok(count)
    }
    pub(super) fn text(&mut self, field: &'static str) -> Result<Option<String>> {
        let length = self.u32(field)?;
        if length == u32::MAX {
            return Ok(None);
        }
        let length = usize::try_from(length).map_err(|_| KeyringError::LimitExceeded { field })?;
        if length > MAX_FIELD_BYTES {
            return Err(KeyringError::LimitExceeded { field });
        }
        let offset = self.offset;
        let bytes = self.take(length, field)?;
        let value =
            std::str::from_utf8(bytes).map_err(|_| KeyringError::Malformed { field, offset })?;
        if value.contains('\0') {
            return Err(KeyringError::Malformed { field, offset });
        }
        Ok(Some(value.to_owned()))
    }
    pub(super) fn byte_range(&mut self, field: &'static str) -> Result<Range<usize>> {
        let count = self.u32(field)?;
        // GNOME's byte-array NULL sentinel represents an empty secret.
        let length = if count == u32::MAX {
            0
        } else {
            usize::try_from(count).map_err(|_| KeyringError::LimitExceeded { field })?
        };
        if length > MAX_FIELD_BYTES {
            return Err(KeyringError::LimitExceeded { field });
        }
        let start = self.offset;
        self.take(length, field)?;
        Ok(start..self.offset)
    }
    fn consume_fields(&mut self, count: usize, field: &'static str) -> Result<()> {
        self.fields_left = self
            .fields_left
            .checked_sub(count)
            .ok_or(KeyringError::LimitExceeded { field })?;
        Ok(())
    }
    pub(super) fn attributes(&mut self) -> Result<Attributes> {
        let count = self.count(1024, "attribute count")?;
        self.consume_fields(count, "total attributes and ACLs")?;
        let mut attributes = Attributes::new();
        for _ in 0..count {
            let offset = self.offset;
            let name = self
                .text("attribute name")?
                .ok_or(KeyringError::Malformed {
                    field: "null attribute name",
                    offset,
                })?;
            let value = match self.u32("attribute type")? {
                0 => AttributeValue::Text(self.text("attribute value")?),
                1 => AttributeValue::Integer(self.u32("attribute value")?),
                _ => {
                    return Err(KeyringError::Malformed {
                        field: "attribute type",
                        offset,
                    });
                }
            };
            if attributes.insert(name, value).is_some() {
                return Err(KeyringError::Malformed {
                    field: "duplicate attribute name",
                    offset,
                });
            }
        }
        Ok(attributes)
    }
    pub(super) fn skip_acl(&mut self, count: u32) -> Result<()> {
        let count = usize::try_from(count)
            .map_err(|_| KeyringError::LimitExceeded { field: "ACL count" })?;
        if count > 1024 {
            return Err(KeyringError::LimitExceeded { field: "ACL count" });
        }
        self.consume_fields(count, "total attributes and ACLs")?;
        for _ in 0..count {
            self.u32("ACL allowed types")?;
            self.text("ACL label")?;
            self.text("ACL path")?;
            self.text("ACL reserved string")?;
            self.u32("ACL reserved word")?;
        }
        Ok(())
    }
}

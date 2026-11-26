use super::{Result, WalletError};
use std::ops::Range;
use zeroize::Zeroizing;

const MAX_FIELD_BYTES: usize = 1024 * 1024;

/// Offsets refer to the supplied buffer: the file's outer index or the
/// decrypted QDataStream payload, never a guessed ciphertext location.
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    pub(super) offset: usize,
}
impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    pub(super) fn rest(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }
    pub(super) fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WalletError::LimitExceeded { field })?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(WalletError::Truncated {
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
    pub(super) fn i32(&mut self, field: &'static str) -> Result<i32> {
        let bytes = self.take(4, field)?;
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    pub(super) fn count(&mut self, maximum: usize, field: &'static str) -> Result<usize> {
        let count =
            usize::try_from(self.u32(field)?).map_err(|_| WalletError::LimitExceeded { field })?;
        if count > maximum {
            return Err(WalletError::LimitExceeded { field });
        }
        Ok(count)
    }
    pub(super) fn bytes(&mut self, field: &'static str) -> Result<Range<usize>> {
        let length = match self.u32(field)? {
            u32::MAX => 0, // QDataStream's null QByteArray/QString marker.
            value => usize::try_from(value).map_err(|_| WalletError::LimitExceeded { field })?,
        };
        if length > MAX_FIELD_BYTES {
            return Err(WalletError::LimitExceeded { field });
        }
        let start = self.offset;
        self.take(length, field)?;
        Ok(start..self.offset)
    }
    pub(super) fn text(&mut self, field: &'static str) -> Result<String> {
        let text = self.secret_text(field)?;
        Ok(text.to_string())
    }
    pub(super) fn secret_text(&mut self, field: &'static str) -> Result<Zeroizing<String>> {
        let range = self.bytes(field)?;
        if !range.len().is_multiple_of(2) {
            return Err(WalletError::Malformed {
                field,
                offset: range.start,
            });
        }
        let units = self.bytes[range.clone()]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|bytes| u16::from_be_bytes(*bytes));
        let mut value = Zeroizing::new(String::new());
        for character in char::decode_utf16(units) {
            value.push(character.map_err(|_| WalletError::Malformed {
                field,
                offset: range.start,
            })?);
        }
        Ok(value)
    }
}

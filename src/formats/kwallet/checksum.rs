//! KDE's historical SHA1 class on little-endian hosts reads message words and
//! writes digest words in native order, despite its fixed Q_BIG_ENDIAN macro.
//! Padding, including the bit count, is still written in big-endian order.
//! A 55-byte remainder uses two final blocks because KDE tests the byte count
//! strictly below 56 after adding 0x80, another difference from standard SHA-1.
//! Reuse RustCrypto's compression function with explicit word conversion; using
//! ordinary SHA-1 rejects a correctly decrypted native KWallet payload.

use super::{Result, WalletError, check_cancel};
use sha1::digest::generic_array::GenericArray;
use std::sync::atomic::AtomicBool;
use zeroize::Zeroizing;

pub(super) fn little_endian(bytes: &[u8], cancel: Option<&AtomicBool>) -> Result<[u8; 20]> {
    let mut state = Zeroizing::new([
        0x67452301u32,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0,
    ]);
    let mut block = Zeroizing::new([0u8; 64]);
    let (chunks, remainder) = bytes.as_chunks::<64>();
    for (index, chunk) in chunks.iter().enumerate() {
        if index % 1024 == 0 {
            check_cancel(cancel)?;
        }
        block.copy_from_slice(chunk);
        compress(&mut state, &mut block);
    }
    let mut ending = Zeroizing::new([0u8; 128]);
    ending[..remainder.len()].copy_from_slice(remainder);
    ending[remainder.len()] = 0x80;
    let end = if remainder.len() < 55 { 64 } else { 128 };
    let bits = u64::try_from(bytes.len())
        .ok()
        .and_then(|n| n.checked_mul(8))
        .ok_or(WalletError::LimitExceeded {
            field: "checksum bytes",
        })?;
    ending[end - 8..end].copy_from_slice(&bits.to_be_bytes());
    for chunk in ending[..end].as_chunks::<64>().0 {
        block.copy_from_slice(chunk);
        compress(&mut state, &mut block);
    }
    let mut digest = [0u8; 20];
    for (word, output) in state.iter().zip(digest.as_chunks_mut::<4>().0) {
        output.copy_from_slice(&word.to_le_bytes());
    }
    check_cancel(cancel)?;
    Ok(digest)
}

fn compress(state: &mut [u32; 5], block: &mut [u8; 64]) {
    for word in block.as_chunks_mut::<4>().0 {
        word.reverse();
    }
    sha1::compress(state, std::slice::from_ref(GenericArray::from_slice(block)));
}

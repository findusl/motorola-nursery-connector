// SPDX-License-Identifier: GPL-3.0-or-later
//! Body padding from AddPadding 0x167e50 and RemovePadding 0x16a960.

use crate::CodecError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSize {
    Bytes16,
    Bytes32,
}

impl BlockSize {
    pub fn bytes(self) -> usize {
        match self {
            Self::Bytes16 => 16,
            Self::Bytes32 => 32,
        }
    }
}

/// Append a complete padding block when input is aligned, including empty input.
/// The limit applies to the padded result, before allocating it.
pub fn pad(input: &[u8], block: BlockSize, maximum: usize) -> Result<Vec<u8>, CodecError> {
    let count = block.bytes() - input.len() % block.bytes();
    let length = input
        .len()
        .checked_add(count)
        .ok_or(CodecError::InvalidLimit)?;
    if length > maximum {
        return Err(CodecError::PayloadTooLarge { length, maximum });
    }
    let mut output = Vec::with_capacity(length);
    output.extend_from_slice(input);
    output.resize(length, count as u8);
    Ok(output)
}

/// Match the native shared validator's 1..32 padding range, with an additional
/// safety check that the padding fits inside the body. Cipher-specific block
/// alignment must be checked by the cipher layer. Returns borrowed plaintext.
pub fn unpad(input: &[u8]) -> Result<&[u8], CodecError> {
    let count = usize::from(*input.last().ok_or(CodecError::InvalidPadding)?);
    if !(1..=32).contains(&count) || count > input.len() {
        return Err(CodecError::InvalidPadding);
    }
    let end = input.len() - count;
    if !input[end..].iter().all(|byte| usize::from(*byte) == count) {
        return Err(CodecError::InvalidPadding);
    }
    Ok(&input[..end])
}

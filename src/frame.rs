// SPDX-License-Identifier: GPL-3.0-or-later
//! CBasePacket framing. Artifact references: constructor 0x14dbe0,
//! GetDataThruMask 0x14dbb4, receive accumulation 0x14e2ac.

use crate::CodecError;

pub const HEADER_LENGTH: usize = 8;
/// Protocol obfuscation constant, not a credential or encryption key.
const PAYLOAD_MASK: [u8; 4] = 0x350bu32.to_le_bytes();

/// XOR complete words while more than four bytes remain. Deliberately leaves
/// the final one to four bytes unchanged, matching the original strict `> 4`.
pub fn apply_mask(payload: &mut [u8]) {
    let words = payload.len().saturating_sub(1) / 4;
    for word in payload[..words * 4].chunks_exact_mut(4) {
        for (byte, mask) in word.iter_mut().zip(PAYLOAD_MASK) {
            *byte ^= mask;
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    pub command: i32,
    /// Unmasked payload. May contain credentials; Debug omits its contents.
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("command", &self.command)
            .field("payload_length", &self.payload.len())
            .finish()
    }
}

impl Frame {
    pub fn encode(&self, maximum: usize) -> Result<Vec<u8>, CodecError> {
        validate_limit(maximum)?;
        validate_size(self.payload.len(), maximum)?;
        let mut wire = Vec::with_capacity(HEADER_LENGTH + self.payload.len());
        wire.extend_from_slice(&self.command.to_le_bytes());
        wire.extend_from_slice(&(self.payload.len() as i32).to_le_bytes());
        wire.extend_from_slice(&self.payload);
        apply_mask(&mut wire[HEADER_LENGTH..]);
        Ok(wire)
    }
}

fn validate_limit(maximum: usize) -> Result<(), CodecError> {
    if maximum > i32::MAX as usize {
        Err(CodecError::InvalidLimit)
    } else {
        Ok(())
    }
}

fn validate_size(length: usize, maximum: usize) -> Result<(), CodecError> {
    if length > maximum {
        Err(CodecError::PayloadTooLarge { length, maximum })
    } else {
        Ok(())
    }
}

/// Incremental decoder, bounded by the configured maximum payload per frame.
///
/// Malformed lengths poison the decoder: a caller must discard the connection
/// or explicitly reset it. Bytes following a bad header cannot be trusted as a
/// new frame. Successful frames preceding an error in the same push are dropped
/// with that push's error. Callers must not use this as a resynchronizing parser.
/// A push returning many frames retains their total size in its output vector;
/// network callers should feed bounded read chunks.
pub struct FrameDecoder {
    maximum: usize,
    header: [u8; HEADER_LENGTH],
    header_used: usize,
    expected: Option<usize>,
    payload: Vec<u8>,
    poisoned: bool,
}

impl FrameDecoder {
    pub fn new(maximum: usize) -> Result<Self, CodecError> {
        validate_limit(maximum)?;
        Ok(Self {
            maximum,
            header: [0; HEADER_LENGTH],
            header_used: 0,
            expected: None,
            payload: Vec::new(),
            poisoned: false,
        })
    }

    /// Forget buffered bytes. Use only at a known new transport boundary.
    pub fn reset(&mut self) {
        self.header_used = 0;
        self.expected = None;
        self.payload.clear();
        self.poisoned = false;
    }

    pub fn buffered_len(&self) -> usize {
        self.header_used + self.payload.len()
    }

    pub fn is_idle(&self) -> bool {
        !self.poisoned && self.buffered_len() == 0
    }

    pub fn push(&mut self, mut input: &[u8]) -> Result<Vec<Frame>, CodecError> {
        if self.poisoned {
            return Err(CodecError::DecoderPoisoned);
        }
        let mut frames = Vec::new();
        while !input.is_empty() {
            if self.header_used < HEADER_LENGTH {
                let count = (HEADER_LENGTH - self.header_used).min(input.len());
                self.header[self.header_used..self.header_used + count]
                    .copy_from_slice(&input[..count]);
                self.header_used += count;
                input = &input[count..];
                if self.header_used < HEADER_LENGTH {
                    break;
                }
                let length = i32::from_le_bytes(self.header[4..8].try_into().unwrap());
                let checked = if length < 0 {
                    Err(CodecError::InvalidLength)
                } else {
                    validate_size(length as usize, self.maximum)
                };
                if let Err(error) = checked {
                    self.poisoned = true;
                    return Err(error);
                }
                self.expected = Some(length as usize);
            }
            let expected = self.expected.expect("complete header has checked length");
            let count = (expected - self.payload.len()).min(input.len());
            self.payload.extend_from_slice(&input[..count]);
            input = &input[count..];
            if self.payload.len() == expected {
                let mut payload = std::mem::take(&mut self.payload);
                apply_mask(&mut payload);
                frames.push(Frame {
                    command: i32::from_le_bytes(self.header[..4].try_into().unwrap()),
                    payload,
                });
                self.header_used = 0;
                self.expected = None;
            }
        }
        Ok(frames)
    }
}

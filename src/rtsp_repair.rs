// SPDX-License-Identifier: GPL-3.0-or-later
//! Optional, narrowly scoped workaround for one observed camera framing defect.
//! A complete RTSP/1.0 response inserted between a `$` header and its RTP body
//! is moved before that header. Neither the response nor RTP bytes are edited.
//! This is not general resynchronization: any ambiguous candidate poisons the
//! instance. Callers must discard the connection after errors, not resume it.
use rtsp_types::{Message, ParseError};
use std::fmt;
use zeroize::Zeroize;

const PREFIX: &[u8] = b"RTSP/1.0 ";
const MAXIMUM_LIMIT: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairError {
    InvalidLimit,
    BufferLimit,
    InvalidFraming,
    InvalidCandidate,
    Truncated,
    Disabled,
}
impl fmt::Display for RepairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimit => "rtsp_repair_invalid_limit",
            Self::BufferLimit => "rtsp_repair_buffer_limit",
            Self::InvalidFraming => "rtsp_repair_invalid_framing",
            Self::InvalidCandidate => "rtsp_repair_invalid_candidate",
            Self::Truncated => "rtsp_repair_truncated",
            Self::Disabled => "rtsp_repair_disabled",
        })
    }
}
impl std::error::Error for RepairError {}

/// One instance per camera-to-client RTSP TCP connection. Output can be delayed
/// until a whole interleaved frame is available. Feed bounded chunks; this type
/// limits retained input, while returned output is proportional to the input.
/// No Debug implementation: the retained buffer can contain private media.
pub struct RtspRepair {
    buffer: Vec<u8>,
    maximum: usize,
    disabled: bool,
    repairs: u64,
}
impl Drop for RtspRepair {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}
enum Parsed {
    Wait,
    Plain(usize),
    Repair { response_end: usize, total: usize },
}
impl RtspRepair {
    pub fn new(maximum_buffer: usize) -> Result<Self, RepairError> {
        if !(64..=MAXIMUM_LIMIT).contains(&maximum_buffer) {
            return Err(RepairError::InvalidLimit);
        }
        Ok(Self {
            buffer: Vec::new(),
            maximum: maximum_buffer,
            disabled: false,
            repairs: 0,
        })
    }
    pub fn enabled(&self) -> bool {
        !self.disabled
    }
    pub fn repairs(&self) -> u64 {
        self.repairs
    }
    fn fail<T>(&mut self, error: RepairError) -> Result<T, RepairError> {
        self.disabled = true;
        self.buffer.zeroize();
        self.buffer.clear();
        Err(error)
    }
    pub fn feed(&mut self, mut input: &[u8]) -> Result<Vec<u8>, RepairError> {
        if self.disabled {
            return Err(RepairError::Disabled);
        }
        let mut output = Vec::new();
        while !input.is_empty() {
            let available = self.maximum - self.buffer.len();
            if available == 0 {
                return self.fail(RepairError::BufferLimit);
            }
            let n = input.len().min(available).min(4096);
            self.buffer.extend_from_slice(&input[..n]);
            input = &input[n..];
            loop {
                let parsed = match self.parse_front() {
                    Ok(parsed) => parsed,
                    Err(error) => return self.fail(error),
                };
                let consumed = match parsed {
                    Parsed::Wait => break,
                    Parsed::Plain(n) => {
                        output.extend_from_slice(&self.buffer[..n]);
                        n
                    }
                    Parsed::Repair {
                        response_end,
                        total,
                    } => {
                        output.extend_from_slice(&self.buffer[4..response_end]);
                        output.extend_from_slice(&self.buffer[..4]);
                        output.extend_from_slice(&self.buffer[response_end..total]);
                        self.repairs = self.repairs.saturating_add(1);
                        total
                    }
                };
                self.buffer[..consumed].zeroize();
                self.buffer.drain(..consumed);
            }
            if self.buffer.len() == self.maximum {
                return self.fail(RepairError::BufferLimit);
            }
        }
        Ok(output)
    }
    /// Call on EOF. Successful feeds already returned all complete units.
    pub fn finish(&mut self) -> Result<Vec<u8>, RepairError> {
        if self.disabled {
            return Err(RepairError::Disabled);
        }
        if !self.buffer.is_empty() {
            return self.fail(RepairError::Truncated);
        }
        Ok(Vec::new())
    }
    fn parse_front(&self) -> Result<Parsed, RepairError> {
        let bytes = self.buffer.as_slice();
        if bytes.is_empty() {
            return Ok(Parsed::Wait);
        }
        if bytes[0] == b'$' {
            if bytes.len() < 4 {
                return Ok(Parsed::Wait);
            }
            let size = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
            let frame_end = 4 + size;
            if frame_end > self.maximum {
                return Err(RepairError::BufferLimit);
            }
            if bytes.len() == 4 {
                return if size == 0 {
                    Ok(Parsed::Plain(4))
                } else {
                    Ok(Parsed::Wait)
                };
            }
            let body = &bytes[4..];
            // No searching within RTP. Only inspect the immediate payload prefix.
            // Prefix R has invalid RTP version; normal RTP version2 bypasses this.
            if size >= 12 && body[0] >> 6 != 2 && matches_prefix(body, PREFIX) {
                if body.len() < PREFIX.len() {
                    return Ok(Parsed::Wait);
                }
                let response_len = match response_size(body)? {
                    Some(n) => n,
                    None => return Ok(Parsed::Wait),
                };
                let response_end = 4 + response_len;
                let total = response_end
                    .checked_add(size)
                    .ok_or(RepairError::BufferLimit)?;
                if total > self.maximum {
                    return Err(RepairError::BufferLimit);
                }
                if bytes.len() < total {
                    return Ok(Parsed::Wait);
                }
                if !valid_rtp(&bytes[response_end..total]) {
                    return Err(RepairError::InvalidCandidate);
                }
                return Ok(Parsed::Repair {
                    response_end,
                    total,
                });
            }
            return if bytes.len() < frame_end {
                Ok(Parsed::Wait)
            } else {
                Ok(Parsed::Plain(frame_end))
            };
        }
        // Preserve normal RTSP responses and blank CRLF boundaries unchanged.
        if bytes[0] == b'\r' {
            if bytes.len() == 1 {
                return Ok(Parsed::Wait);
            }
            return if bytes[1] == b'\n' {
                Ok(Parsed::Plain(2))
            } else {
                Err(RepairError::InvalidFraming)
            };
        }
        if !matches_prefix(bytes, PREFIX) {
            return Err(RepairError::InvalidFraming);
        }
        if bytes.len() < PREFIX.len() {
            return Ok(Parsed::Wait);
        }
        Ok(match response_size(bytes)? {
            Some(n) => Parsed::Plain(n),
            None => Parsed::Wait,
        })
    }
}

fn matches_prefix(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes[..bytes.len().min(prefix.len())] == prefix[..bytes.len().min(prefix.len())]
}
fn response_size(bytes: &[u8]) -> Result<Option<usize>, RepairError> {
    match Message::<&[u8]>::parse(bytes) {
        Ok((Message::Response(_), n)) if n > 0 => Ok(Some(n)),
        Err(ParseError::Incomplete(_)) => Ok(None),
        _ => Err(RepairError::InvalidFraming),
    }
}
// Structural validation only, not a claim that the media codec payload decodes.
fn valid_rtp(packet: &[u8]) -> bool {
    if packet.len() < 12 || packet[0] >> 6 != 2 {
        return false;
    }
    let mut header = 12 + 4 * (packet[0] & 15) as usize;
    if packet.len() < header {
        return false;
    }
    if packet[0] & 0x10 != 0 {
        if packet.len() < header + 4 {
            return false;
        }
        let words = u16::from_be_bytes([packet[header + 2], packet[header + 3]]) as usize;
        header += 4 + words * 4;
        if packet.len() < header {
            return false;
        }
    }
    if packet[0] & 0x20 != 0 {
        let pad = *packet.last().unwrap() as usize;
        if pad == 0 || pad > packet.len() - header {
            return false;
        }
    }
    true
}

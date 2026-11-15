// SPDX-License-Identifier: GPL-3.0-or-later
//! Multiplexed channel headers and close semantics. No encryption here.
//! References: SendReqInfo 0x170368, SendTunnelOnAccess 0x164358,
//! DealWithDataInfoImpl 0x170448, SendAccessPortReject 0x16414c.

use crate::{frame::Frame, CodecError};

pub const CHANNEL_HEADER_LENGTH: usize = 16;
pub const COMMAND_CHANNEL: i32 = 0;
pub const COMMAND_KEEPALIVE: i32 = 1;
pub const COMMAND_OPEN: i32 = 7;
pub const CLOSE_REQUEST: i32 = -4;
pub const CLOSE_ACK: i32 = -2;
pub const CLOSE_FINAL: i32 = -3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ChannelDirection {
    Initiator = 1,
    Target = 2,
    Rejected = 3,
}

impl TryFrom<u16> for ChannelDirection {
    type Error = CodecError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Initiator),
            2 => Ok(Self::Target),
            3 => Ok(Self::Rejected),
            other => Err(CodecError::InvalidDirection(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelHeader {
    pub request_id: i32,
    pub sequence: i32,
    pub direction: ChannelDirection,
    pub local_port: u16,
    pub peer_port: u16,
    /// Native sender sets zero; preserved on decode without inferring semantics.
    pub reserved: u16,
}

impl ChannelHeader {
    pub fn encode(self) -> [u8; CHANNEL_HEADER_LENGTH] {
        let mut bytes = [0; CHANNEL_HEADER_LENGTH];
        bytes[0..4].copy_from_slice(&self.request_id.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[8..10].copy_from_slice(&(self.direction as u16).to_le_bytes());
        bytes[10..12].copy_from_slice(&self.local_port.to_le_bytes());
        bytes[12..14].copy_from_slice(&self.peer_port.to_le_bytes());
        bytes[14..16].copy_from_slice(&self.reserved.to_le_bytes());
        bytes
    }

    /// Decode an unmasked command-0 payload header. Returned bytes are still
    /// ciphertext; decrypt/unpad them before treating them as service traffic.
    pub fn split(payload: &[u8]) -> Result<(Self, &[u8]), CodecError> {
        if payload.len() < CHANNEL_HEADER_LENGTH {
            return Err(CodecError::TruncatedHeader {
                expected: CHANNEL_HEADER_LENGTH,
                actual: payload.len(),
            });
        }
        Ok((
            Self {
                request_id: i32::from_le_bytes(payload[0..4].try_into().unwrap()),
                sequence: i32::from_le_bytes(payload[4..8].try_into().unwrap()),
                direction: u16::from_le_bytes(payload[8..10].try_into().unwrap()).try_into()?,
                local_port: u16::from_le_bytes(payload[10..12].try_into().unwrap()),
                peer_port: u16::from_le_bytes(payload[12..14].try_into().unwrap()),
                reserved: u16::from_le_bytes(payload[14..16].try_into().unwrap()),
            },
            &payload[CHANNEL_HEADER_LENGTH..],
        ))
    }

    pub fn action(self) -> ChannelAction {
        if self.direction == ChannelDirection::Rejected {
            ChannelAction::Remove
        } else {
            match self.sequence {
                CLOSE_REQUEST => ChannelAction::ReplyAndClose {
                    sequence: CLOSE_ACK,
                },
                CLOSE_ACK => ChannelAction::ReplyAndRemove {
                    sequence: CLOSE_FINAL,
                },
                CLOSE_FINAL => ChannelAction::Remove,
                _ => ChannelAction::Forward,
            }
        }
    }
}

/// Describes receive-side protocol decisions, not actual socket operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelAction {
    Forward,
    /// Send reply, enter closing state, retain channel until final acknowledgement.
    ReplyAndClose {
        sequence: i32,
    },
    /// Send reply then remove the channel.
    ReplyAndRemove {
        sequence: i32,
    },
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenChannel {
    pub local_port: u16,
    pub remote_port: u16,
    pub request_id: i32,
}

impl OpenChannel {
    pub fn encode(self) -> [u8; 8] {
        let mut payload = [0; 8];
        payload[0..2].copy_from_slice(&self.local_port.to_le_bytes());
        payload[2..4].copy_from_slice(&self.remote_port.to_le_bytes());
        payload[4..8].copy_from_slice(&self.request_id.to_le_bytes());
        payload
    }

    pub fn decode(payload: &[u8]) -> Result<Self, CodecError> {
        if payload.len() != 8 {
            return Err(CodecError::TruncatedHeader {
                expected: 8,
                actual: payload.len(),
            });
        }
        Ok(Self {
            local_port: u16::from_le_bytes(payload[0..2].try_into().unwrap()),
            remote_port: u16::from_le_bytes(payload[2..4].try_into().unwrap()),
            request_id: i32::from_le_bytes(payload[4..8].try_into().unwrap()),
        })
    }

    pub fn frame(self) -> Frame {
        Frame {
            command: COMMAND_OPEN,
            payload: self.encode().to_vec(),
        }
    }
}

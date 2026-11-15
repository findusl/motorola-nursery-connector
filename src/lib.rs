// SPDX-License-Identifier: GPL-3.0-or-later
//! Independent protocol implementation reconstructed from artifact analysis.
//! Synthetic native-oracle tests verify wire framing and legacy cryptography;
//! they do not prove successful connection to a physical camera.

pub mod channel;
pub mod crypto;
pub mod frame;
pub mod padding;
pub mod settings;
pub mod signaling;
pub mod wire_io;

use std::fmt;

/// Errors exclude packet contents so credentials cannot leak through logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    InvalidLimit,
    InvalidLength,
    PayloadTooLarge { length: usize, maximum: usize },
    TruncatedHeader { expected: usize, actual: usize },
    InvalidDirection(u16),
    InvalidPadding,
    DecoderPoisoned,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => write!(f, "frame size limit exceeds signed protocol length"),
            Self::InvalidLength => write!(f, "negative protocol payload length"),
            Self::PayloadTooLarge { length, maximum } => {
                write!(
                    f,
                    "payload length {length} exceeds configured maximum {maximum}"
                )
            }
            Self::TruncatedHeader { expected, actual } => {
                write!(
                    f,
                    "truncated header: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidDirection(value) => write!(f, "unsupported channel direction {value}"),
            Self::InvalidPadding => write!(f, "invalid padding"),
            Self::DecoderPoisoned => write!(f, "decoder requires reset after framing error"),
        }
    }
}

impl std::error::Error for CodecError {}

pub mod session;

pub mod supervisor;

pub mod media_observer;

mod diagnostic_capture;

pub mod request_observer;

pub mod rtsp_repair;

pub mod telemetry;

pub mod account_transport;

pub mod account;

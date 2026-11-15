// SPDX-License-Identifier: GPL-3.0-or-later
//! App-side Orbweb 4.5.3 bootstrap and direct rendezvous payloads.
//!
//! Independently reconstructed from the inspected ARM64 artifact. References:
//! GenP2PServerID 0x159f18; ReqHostNIC 0x1505ac; SendConnHostReq 0x14f0d4;
//! ParseP2PServerUtil 0x14f1bc; ParseHostNic 0x150334; XListen send 0x177390;
//! HandleDirConn 0x177ea4. These are payload codecs, not a network client.

use crate::frame::Frame;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

pub const SDK_VERSION: &str = "4.5.3";
pub const DIRECT_MODE: u32 = 1;
pub const SERVER_PORT: u16 = 443;
pub const MAX_CANDIDATES: usize = 64;
pub const MAX_DIRECT_PAYLOAD: usize = 8192;

/// Deliberately contains no packet text, identities, or credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalingError {
    InvalidLength,
    InvalidText,
    FieldTooLong,
    MissingTerminator,
    InvalidVersion,
    InvalidAddress,
    InvalidCounter,
    TooManyCandidates,
}

impl fmt::Display for SignalingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "invalid signaling payload length",
            Self::InvalidText => "invalid signaling text",
            Self::FieldTooLong => "signaling field exceeds its slot",
            Self::MissingTerminator => "signaling string lacks terminator",
            Self::InvalidVersion => "invalid signaling version",
            Self::InvalidAddress => "invalid signaling address",
            Self::InvalidCounter => "generated identity counter exceeds 999",
            Self::TooManyCandidates => "too many direct candidates",
        })
    }
}
impl std::error::Error for SignalingError {}

fn identity(text: &str, maximum: usize) -> Result<(), SignalingError> {
    if text.is_empty()
        || !text.is_ascii()
        || text.bytes().any(|b| b.is_ascii_control() || b == b';')
    {
        return Err(SignalingError::InvalidText);
    }
    if text.len() > maximum {
        return Err(SignalingError::FieldTooLong);
    }
    Ok(())
}

fn put_string(slot: &mut [u8], text: &str) -> Result<(), SignalingError> {
    identity(text, slot.len().saturating_sub(1))?;
    slot.fill(0);
    slot[..text.len()].copy_from_slice(text.as_bytes());
    Ok(())
}

fn c_string(slot: &[u8]) -> Result<String, SignalingError> {
    let end = slot
        .iter()
        .position(|b| *b == 0)
        .ok_or(SignalingError::MissingTerminator)?;
    let text = std::str::from_utf8(&slot[..end]).map_err(|_| SignalingError::InvalidText)?;
    if !text.is_ascii() || text.bytes().any(|b| b.is_ascii_control()) {
        return Err(SignalingError::InvalidText);
    }
    Ok(text.to_owned())
}

/// The caller increments its per-process counter modulo 1000 before calling.
/// The native fallback client token is a locally generated 8-4-4-4-12 identity,
/// not the Motorola account token or the camera's session password.
pub fn generated_id(
    device: &str,
    client_token: &str,
    counter: u16,
) -> Result<String, SignalingError> {
    identity(device, 127)?;
    identity(client_token, 254)?;
    if counter > 999 {
        return Err(SignalingError::InvalidCounter);
    }
    let id = format!("{device}_ctok_{client_token}#{counter:03}");
    identity(&id, 254)?;
    Ok(id)
}

/// Native discovery accepts a hostname or IP, not an arbitrary URL.
/// POST JSON `{ "role": "client", "id": device, "token": "" }` to this URL.
pub fn discovery_url(rendezvous: &str) -> Result<String, SignalingError> {
    if let Ok(ip) = rendezvous.parse::<IpAddr>() {
        return Ok(match ip {
            IpAddr::V4(_) => format!("https://{ip}/api/device/connection"),
            IpAddr::V6(_) => format!("https://[{ip}]/api/device/connection"),
        });
    }
    if rendezvous.is_empty()
        || rendezvous.len() > 253
        || !rendezvous.is_ascii()
        || rendezvous.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(SignalingError::InvalidAddress);
    }
    Ok(format!("https://{rendezvous}/api/device/connection"))
}

fn raw_id(command: i32, id: &str) -> Result<Frame, SignalingError> {
    identity(id, 254)?;
    Ok(Frame {
        command,
        payload: id.as_bytes().to_vec(),
    })
}

pub fn register103(id: &str) -> Result<Frame, SignalingError> {
    raw_id(103, id)
}
pub fn success115(id: &str) -> Result<Frame, SignalingError> {
    raw_id(115, id)
}

pub fn host_nic119(
    device: &str,
    id: &str,
    local_ipv4_count: u32,
    requested_mode: u32,
    timeout_ms: u32,
) -> Result<Frame, SignalingError> {
    let mut payload = vec![0; 0x20c];
    put_string(&mut payload[..0x80], device)?;
    put_string(&mut payload[0x80..0xff], SDK_VERSION)?;
    // The shared generated ID must also fit command106's narrower 255-byte slot.
    identity(id, 254)?;
    put_string(&mut payload[0xff..0x200], id)?;
    payload[0x200..0x204].copy_from_slice(&local_ipv4_count.to_le_bytes());
    payload[0x204..0x208].copy_from_slice(&requested_mode.to_le_bytes());
    payload[0x208..0x20c].copy_from_slice(&timeout_ms.to_le_bytes());
    Ok(Frame {
        command: 119,
        payload,
    })
}

pub fn connect106(
    device: &str,
    id: &str,
    client_token: &str,
    relay_ip: &str,
) -> Result<Frame, SignalingError> {
    let mut payload = vec![0; 0x322];
    // Keep the same device constraint as command119 to prevent partial startup.
    identity(device, 127)?;
    put_string(&mut payload[..0x100], device)?;
    // 0x100..0x102 is the native zero-valued u16.
    put_string(&mut payload[0x102..0x201], id)?;
    put_string(&mut payload[0x201..0x300], client_token)?;
    relay_ip
        .parse::<IpAddr>()
        .map_err(|_| SignalingError::InvalidAddress)?;
    put_string(&mut payload[0x300..0x320], relay_ip)?;
    payload[0x320..].copy_from_slice(&SERVER_PORT.to_le_bytes());
    Ok(Frame {
        command: 106,
        payload,
    })
}

/// Protocol endpoints are unbracketed `IP:port`, even for IPv6. Scoped IPv6
/// addresses cannot be represented by this implementation.
pub fn listen200(id: &str, candidates: &[SocketAddr]) -> Result<Frame, SignalingError> {
    identity(id, 254)?;
    if candidates.len() > MAX_CANDIDATES {
        return Err(SignalingError::TooManyCandidates);
    }
    let mut text = id.to_owned();
    for endpoint in candidates {
        if endpoint.port() == 0
            || matches!(endpoint, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0)
        {
            return Err(SignalingError::InvalidAddress);
        }
        text.push(';');
        text.push_str(&format!("{}:{}", endpoint.ip(), endpoint.port()));
    }
    let mut payload = text.into_bytes();
    payload.push(0);
    if payload.len() > MAX_DIRECT_PAYLOAD {
        return Err(SignalingError::InvalidLength);
    }
    Ok(Frame {
        command: 200,
        payload,
    })
}

#[derive(Clone, PartialEq, Eq)]
pub struct BootstrapServers {
    pub stun_tcp_primary: String,
    pub stun_tcp_secondary: String,
    pub shunt: String,
    pub stun_primary: String,
    pub stun_secondary: String,
}
impl fmt::Debug for BootstrapServers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BootstrapServers { addresses: <redacted> }")
    }
}

/// Strict current-version schema; reject extensions until independently known.
/// Empty unused server slots are allowed. These are STUN/shunt addresses, not keys.
pub fn parse104(payload: &[u8]) -> Result<BootstrapServers, SignalingError> {
    if payload.len() != 160 {
        return Err(SignalingError::InvalidLength);
    }
    Ok(BootstrapServers {
        stun_tcp_primary: c_string(&payload[0..32])?,
        stun_tcp_secondary: c_string(&payload[32..64])?,
        shunt: c_string(&payload[64..96])?,
        stun_primary: c_string(&payload[96..128])?,
        stun_secondary: c_string(&payload[128..160])?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilities {
    pub version: [u32; 3],
    /// Native value1 selects 32-byte-block Rijndael; other values select AES.
    pub cipher_flag: u8,
    pub host_nic_count: u32,
    pub host_mode: u32,
}

pub fn parse120(payload: &[u8]) -> Result<HostCapabilities, SignalingError> {
    if payload.len() != 0x20c {
        return Err(SignalingError::InvalidLength);
    }
    let text = c_string(&payload[0x80..0xff])?;
    let mut version = [0; 3];
    let mut parts = text.split('.');
    for component in &mut version {
        let part = parts.next().ok_or(SignalingError::InvalidVersion)?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(SignalingError::InvalidVersion);
        }
        *component = part.parse().map_err(|_| SignalingError::InvalidVersion)?;
    }
    if parts.next().is_some() {
        return Err(SignalingError::InvalidVersion);
    }
    Ok(HostCapabilities {
        version,
        cipher_flag: payload[0x1fd],
        host_nic_count: u32::from_le_bytes(payload[0x200..0x204].try_into().unwrap()),
        host_mode: u32::from_le_bytes(payload[0x204..0x208].try_into().unwrap()),
    })
}

#[derive(Clone, PartialEq, Eq)]
pub struct DirectCandidates {
    /// Keep the wire order; peer handshake determines which identity it expects.
    pub identity_a: String,
    pub identity_b: String,
    pub candidates: Vec<SocketAddr>,
}
impl fmt::Debug for DirectCandidates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectCandidates")
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

pub fn parse204(payload: &[u8]) -> Result<DirectCandidates, SignalingError> {
    if payload.is_empty() || payload.len() > MAX_DIRECT_PAYLOAD {
        return Err(SignalingError::InvalidLength);
    }
    // Native HandleDirConnPacket calls strlen at ELF 0x178784. Treat the
    // bounded prefix before the first NUL as text; trailing packet storage is
    // not part of the candidate string (and is never interpreted separately).
    let end = payload
        .iter()
        .position(|b| *b == 0)
        .ok_or(SignalingError::MissingTerminator)?;
    let text = std::str::from_utf8(&payload[..end]).map_err(|_| SignalingError::InvalidText)?;
    if !text.is_ascii() || text.bytes().any(|b| b.is_ascii_control()) {
        return Err(SignalingError::InvalidText);
    }
    let mut parts = text.split(';');
    let identity_a = parts.next().ok_or(SignalingError::InvalidText)?;
    let identity_b = parts.next().ok_or(SignalingError::InvalidText)?;
    identity(identity_a, 254)?;
    identity(identity_b, 254)?;
    let mut candidates = Vec::new();
    for part in parts {
        if candidates.len() == MAX_CANDIDATES {
            return Err(SignalingError::TooManyCandidates);
        }
        let (ip, port) = part
            .rsplit_once(':')
            .ok_or(SignalingError::InvalidAddress)?;
        let ip: IpAddr = ip.parse().map_err(|_| SignalingError::InvalidAddress)?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(SignalingError::InvalidAddress);
        }
        let port: u16 = port.parse().map_err(|_| SignalingError::InvalidAddress)?;
        if port == 0 {
            return Err(SignalingError::InvalidAddress);
        }
        candidates.push(SocketAddr::new(ip, port));
    }
    if candidates.is_empty() {
        return Err(SignalingError::InvalidAddress);
    }
    Ok(DirectCandidates {
        identity_a: identity_a.to_owned(),
        identity_b: identity_b.to_owned(),
        candidates,
    })
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! Passive camera-to-receiver RTSP/RTP diagnostics. Never modifies forwarded bytes.
//!
//! Sequence gaps count *observed forward discontinuities*, not proven packet
//! loss: late packets, source restarts and observer resets affect interpretation.
//! Duplicate detection covers the last 128 sequence numbers. Sequence/timestamp
//! arithmetic uses wrapping serial numbers. No payload/header text or identifiers
//! other than interleaved channel numbers appear in snapshots or errors.
use rtsp_types::{headers, Message, ParseError};
use serde::Serialize;
use std::{collections::BTreeMap, fmt};
use zeroize::Zeroize;

const DEFAULT_MAXIMUM: usize = 256 * 1024;
const MAXIMUM_LIMIT: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationError {
    InvalidLimit,
    BufferLimit,
    InvalidFraming,
    Disabled,
}
impl fmt::Display for ObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimit => "observer_invalid_limit",
            Self::BufferLimit => "observer_buffer_limit",
            Self::InvalidFraming => "observer_invalid_framing",
            Self::Disabled => "observer_disabled",
        })
    }
}
impl std::error::Error for ObservationError {}

#[derive(Debug, Default, Clone, Serialize)]
pub struct StreamCounters {
    pub rtp_packets: u64,
    pub rtp_bytes: u64,
    pub ssrc_changes: u64,
    pub gap_events: u64,
    pub missing_sequence_numbers: u64,
    pub duplicates: u64,
    pub out_of_order: u64,
    pub older_than_duplicate_window: u64,
    pub timestamp_changes: u64,
    pub timestamp_regressions: u64,
}
#[derive(Debug, Default, Clone, Serialize)]
pub struct ObservationSnapshot {
    pub enabled: bool,
    pub buffered_bytes: usize,
    pub input_bytes: u64,
    pub rtsp_responses: u64,
    pub rtsp_error_responses: u64,
    pub interleaved_frames: u64,
    pub rtcp_frames: u64,
    pub rtcp_packets: u64,
    pub malformed_rtp: u64,
    pub malformed_rtcp: u64,
    pub invalid_rtp_version: u64,
    pub unnegotiated_frames: u64,
    pub framing_errors: u64,
    pub resets: u64,
    pub streams: BTreeMap<u8, StreamCounters>,
}
#[derive(Default)]
struct SequenceState {
    ssrc: Option<u32>,
    highest: u16,
    seen: u128,
    timestamp: u32,
}
#[derive(Default)]
struct State {
    totals: ObservationSnapshot,
    channels: BTreeMap<u8, bool>, // true RTP, false RTCP; at most 256 entries
    sequences: BTreeMap<u8, SequenceState>,
}
/// Feed only camera-to-receiver bytes from one RTSP TCP connection. On framing
/// error this observer disables itself. The caller MUST continue forwarding;
/// reset only at a known new RTSP connection boundary, never scan video for '$'.
pub struct MediaObserver {
    buffer: Vec<u8>,
    maximum: usize,
    disabled: bool,
    state: State,
}
impl Default for MediaObserver {
    fn default() -> Self {
        Self::new(DEFAULT_MAXIMUM).unwrap()
    }
}
impl Drop for MediaObserver {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}
impl MediaObserver {
    pub fn new(maximum: usize) -> Result<Self, ObservationError> {
        if !(64..=MAXIMUM_LIMIT).contains(&maximum) {
            return Err(ObservationError::InvalidLimit);
        }
        Ok(Self {
            buffer: Vec::new(),
            maximum,
            disabled: false,
            state: State::default(),
        })
    }
    pub fn snapshot(&self) -> ObservationSnapshot {
        let mut result = self.state.totals.clone();
        result.enabled = !self.disabled;
        result.buffered_bytes = self.buffer.len();
        result
    }
    pub fn reset(&mut self) {
        self.buffer.zeroize();
        self.buffer.clear();
        self.disabled = false;
        self.state.channels.clear();
        self.state.sequences.clear();
        self.state.totals.resets += 1;
    }
    fn fail(&mut self, error: ObservationError) -> Result<(), ObservationError> {
        self.disabled = true;
        self.state.totals.framing_errors += 1;
        self.buffer.zeroize();
        self.buffer.clear();
        Err(error)
    }
    pub fn feed(&mut self, mut input: &[u8]) -> Result<(), ObservationError> {
        self.state.totals.input_bytes = self
            .state
            .totals
            .input_bytes
            .saturating_add(input.len() as u64);
        if self.disabled {
            return Err(ObservationError::Disabled);
        }
        while !input.is_empty() {
            let available = self.maximum - self.buffer.len();
            if available == 0 {
                return self.fail(ObservationError::BufferLimit);
            }
            // Large coalesced input is drained incrementally, not treated as one
            // giant partial frame. Only the unparsed suffix survives each pass.
            let n = input.len().min(available).min(4096);
            self.buffer.extend_from_slice(&input[..n]);
            input = &input[n..];
            let mut consumed = 0;
            while consumed < self.buffer.len() {
                match Message::<&[u8]>::parse(&self.buffer[consumed..]) {
                    Ok((message, n)) if n != 0 => {
                        observe_message(&mut self.state, message);
                        consumed += n;
                    }
                    Err(ParseError::Incomplete(_)) => break,
                    _ => return self.fail(ObservationError::InvalidFraming),
                }
            }
            self.buffer[..consumed].zeroize();
            self.buffer.drain(..consumed);
            if self.buffer.len() == self.maximum {
                return self.fail(ObservationError::BufferLimit);
            }
        }
        Ok(())
    }
}
fn observe_message(state: &mut State, message: Message<&[u8]>) {
    match message {
        Message::Response(r) => {
            state.totals.rtsp_responses += 1;
            if !r.status().is_success() {
                state.totals.rtsp_error_responses += 1;
                return;
            }
            // SETUP replies carry Transport. No CSeq/auth/header values retained.
            if let Some(transport) = r.header(&headers::TRANSPORT) {
                for part in transport.as_str().split([',', ';']) {
                    let Some((name, value)) = part.trim().split_once('=') else {
                        continue;
                    };
                    if !name.trim().eq_ignore_ascii_case("interleaved") {
                        continue;
                    }
                    let value = value.trim().trim_matches('"');
                    let Some((rtp, rtcp)) = value.split_once('-') else {
                        continue;
                    };
                    if let (Ok(rtp), Ok(rtcp)) =
                        (rtp.trim().parse::<u8>(), rtcp.trim().parse::<u8>())
                    {
                        if rtp != rtcp {
                            state.channels.insert(rtp, true);
                            state.channels.insert(rtcp, false);
                        }
                    }
                }
            }
        }
        Message::Data(data) => observe_interleaved(state, data.channel_id(), data.as_slice()),
        Message::Request(_) => {}
    }
}
fn observe_interleaved(state: &mut State, channel: u8, body: &[u8]) {
    state.totals.interleaved_frames += 1;
    let is_rtp = match state.channels.get(&channel) {
        Some(value) => *value,
        None => {
            state.totals.unnegotiated_frames += 1;
            // This fallback is inherently ambiguous with RTP marker+PT72..76;
            // negotiated channel mapping always wins over payload heuristics.
            !(body.len() >= 4 && (200..=204).contains(&body[1]) && rtcp_count(body).is_some())
        }
    };
    if !is_rtp {
        if let Some(count) = rtcp_count(body) {
            state.totals.rtcp_frames += 1;
            state.totals.rtcp_packets += count;
        } else {
            state.totals.malformed_rtcp += 1;
        }
        return;
    }
    if body.first().is_some_and(|b| b >> 6 != 2) {
        state.totals.invalid_rtp_version += 1;
    }
    let Some((sequence, timestamp, ssrc)) = rtp_header(body) else {
        state.totals.malformed_rtp += 1;
        return;
    };
    let counters = state.totals.streams.entry(channel).or_default();
    counters.rtp_packets += 1;
    counters.rtp_bytes += body.len() as u64;
    let previous = state.sequences.entry(channel).or_default();
    if previous.ssrc != Some(ssrc) {
        if previous.ssrc.is_some() {
            counters.ssrc_changes += 1;
        }
        *previous = SequenceState {
            ssrc: Some(ssrc),
            highest: sequence,
            seen: 1,
            timestamp,
        };
        return;
    }
    let delta = sequence.wrapping_sub(previous.highest) as i16;
    if delta > 0 {
        let distance = delta as u32;
        if distance > 1 {
            counters.gap_events += 1;
            counters.missing_sequence_numbers += u64::from(distance - 1);
        }
        previous.seen = if distance >= 128 {
            1
        } else {
            (previous.seen << distance) | 1
        };
        previous.highest = sequence;
        let timestamp_delta = timestamp.wrapping_sub(previous.timestamp) as i32;
        if timestamp_delta != 0 {
            counters.timestamp_changes += 1;
        }
        if timestamp_delta < 0 {
            counters.timestamp_regressions += 1;
        }
        previous.timestamp = timestamp;
    } else {
        let distance = previous.highest.wrapping_sub(sequence) as u32;
        if distance < 128 {
            let bit = 1u128 << distance;
            if previous.seen & bit != 0 {
                counters.duplicates += 1;
            } else {
                counters.out_of_order += 1;
                previous.seen |= bit;
            }
        } else {
            counters.out_of_order += 1;
            counters.older_than_duplicate_window += 1;
        }
    }
}
// RFC3550 §5.1 header/CSRC/extension/padding bounds. Does not inspect codec data.
fn rtp_header(body: &[u8]) -> Option<(u16, u32, u32)> {
    if body.len() < 12 || body[0] >> 6 != 2 {
        return None;
    }
    let mut header = 12 + usize::from(body[0] & 15) * 4;
    if header > body.len() {
        return None;
    }
    if body[0] & 16 != 0 {
        if header + 4 > body.len() {
            return None;
        }
        let words = u16::from_be_bytes([body[header + 2], body[header + 3]]) as usize;
        header += 4 + words * 4;
        if header > body.len() {
            return None;
        }
    }
    if body[0] & 32 != 0 {
        let padding = usize::from(*body.last()?);
        if padding == 0 || padding > body.len() - header {
            return None;
        }
    }
    Some((
        u16::from_be_bytes(body[2..4].try_into().ok()?),
        u32::from_be_bytes(body[4..8].try_into().ok()?),
        u32::from_be_bytes(body[8..12].try_into().ok()?),
    ))
}
fn rtcp_count(mut body: &[u8]) -> Option<u64> {
    let mut count = 0;
    while !body.is_empty() {
        if body.len() < 4 || body[0] >> 6 != 2 || !(200..=211).contains(&body[1]) {
            return None;
        }
        let length = (usize::from(u16::from_be_bytes([body[2], body[3]])) + 1) * 4;
        if length > body.len() {
            return None;
        }
        let reports = usize::from(body[0] & 31);
        let minimum = match body[1] {
            200 => 28 + reports * 24, // sender info and reception reports
            201 => 8 + reports * 24,
            202 | 203 => 4 + reports * 4, // at least each SSRC
            204..=206 => 12,
            207 => 8,
            _ => 4,
        };
        if length < minimum {
            return None;
        }
        if body[0] & 32 != 0 {
            if length != body.len() {
                return None;
            }
            let padding = usize::from(body[length - 1]);
            if padding == 0 || padding > length - 4 {
                return None;
            }
        }
        count += 1;
        body = &body[length..];
    }
    (count > 0).then_some(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rtp(seq: u16, time: u32, ssrc: u32) -> Vec<u8> {
        let mut b = vec![0x80, 96];
        b.extend(seq.to_be_bytes());
        b.extend(time.to_be_bytes());
        b.extend(ssrc.to_be_bytes());
        b.extend([1, 2, 3]);
        b
    }
    fn frame(channel: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![b'$', channel];
        v.extend((body.len() as u16).to_be_bytes());
        v.extend(body);
        v
    }
    fn setup() -> &'static [u8] {
        b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n"
    }
    #[test]
    fn fragmented_and_coalesced_sequence_metrics() {
        let mut o = MediaObserver::default();
        let mut data = setup().to_vec();
        for (s, t, id) in [
            (65534, 10, 7),
            (65535, 10, 7),
            (0, 20, 7),
            (3, 30, 7),
            (3, 30, 7),
            (2, 20, 7),
            (2, 20, 7),
            (4, 25, 7),
            (6, 0, 8),
        ] {
            data.extend(frame(0, &rtp(s, t, id)));
        }
        for chunk in data.chunks(3) {
            o.feed(chunk).unwrap();
        }
        let snap = o.snapshot();
        let c = &snap.streams[&0];
        assert_eq!(snap.rtsp_responses, 1);
        assert_eq!(c.rtp_packets, 9);
        assert_eq!(c.gap_events, 1);
        assert_eq!(c.missing_sequence_numbers, 2);
        assert_eq!(c.duplicates, 2);
        assert_eq!(c.out_of_order, 1);
        assert_eq!(c.ssrc_changes, 1);
        assert_eq!(c.timestamp_changes, 3);
        assert_eq!(c.timestamp_regressions, 1);
        assert_eq!(snap.buffered_bytes, 0);
    }
    #[test]
    fn rtcp_compound_and_channel_mapping_prevents_false_rtp() {
        let mut o = MediaObserver::default();
        o.feed(setup()).unwrap();
        let mut compound = vec![0x80, 200, 0, 6];
        compound.extend([0u8; 24]);
        compound.extend([0x80, 201, 0, 1, 0, 0, 0, 7]);
        o.feed(&frame(1, &compound)).unwrap();
        let mut ambiguous = rtp(4, 5, 6);
        ambiguous[1] = 200; // marker+payload72 on known RTP
        o.feed(&frame(0, &ambiguous)).unwrap();
        o.feed(&frame(1, &[0x80, 200, 0, 99])).unwrap();
        let s = o.snapshot();
        assert_eq!(s.rtcp_frames, 1);
        assert_eq!(s.rtcp_packets, 2);
        assert_eq!(s.malformed_rtcp, 1);
        assert_eq!(s.streams[&0].rtp_packets, 1);
        let mut unknown = MediaObserver::default();
        unknown.feed(&frame(9, &compound)).unwrap();
        assert_eq!(unknown.snapshot().rtcp_packets, 2);
    }
    #[test]
    fn extensions_padding_versions_and_response_bodies() {
        let mut o = MediaObserver::default();
        let mut response = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 4\r\n\r\n".to_vec();
        response.extend(b"$xxx");
        response.extend(frame(2, &rtp(1, 1, 1)));
        o.feed(&response).unwrap();
        let mut packet = rtp(2, 2, 1);
        packet[0] = 0xb1; // padding+extension+oneCSRC
        packet.splice(12..12, [0, 0, 0, 3, 0x12, 0x34, 0, 1, 0, 0, 0, 0]);
        packet.extend([0, 2]);
        o.feed(&frame(2, &packet)).unwrap();
        packet[0] = 0x40;
        o.feed(&frame(2, &packet)).unwrap();
        let mut truncated = rtp(3, 3, 1);
        truncated[0] = 0x8f;
        o.feed(&frame(2, &truncated)).unwrap();
        let s = o.snapshot();
        assert_eq!(s.streams[&2].rtp_packets, 2);
        assert_eq!(s.invalid_rtp_version, 1);
        assert_eq!(s.malformed_rtp, 2);
    }
    #[test]
    fn bounded_failure_reset_and_large_coalesced_input() {
        let mut o = MediaObserver::new(128).unwrap();
        let many = frame(0, &rtp(1, 1, 1)).repeat(2000);
        o.feed(&many).unwrap();
        assert_eq!(o.snapshot().streams[&0].rtp_packets, 2000);
        let mut oversized = b"RTSP/1.0 200 OK\r\nContent-Length: 1000\r\n\r\n".to_vec();
        oversized.extend([0; 128]);
        assert_eq!(o.feed(&oversized), Err(ObservationError::BufferLimit));
        assert!(!o.snapshot().enabled);
        assert_eq!(o.snapshot().buffered_bytes, 0);
        assert_eq!(o.feed(&many), Err(ObservationError::Disabled));
        o.reset();
        o.feed(&frame(0, &rtp(1000, 0, 2))).unwrap();
        assert!(o.snapshot().enabled);
        assert_eq!(o.snapshot().resets, 1);
    }
    #[test]
    fn independent_channels_timestamp_wrap_and_old_duplicates() {
        let mut o = MediaObserver::default();
        o.feed(&frame(0, &rtp(1, u32::MAX - 1, 9))).unwrap();
        o.feed(&frame(2, &rtp(400, 100, 11))).unwrap();
        o.feed(&frame(0, &rtp(2, 2, 9))).unwrap(); // normal timestamp wrap
        o.feed(&frame(2, &rtp(401, 100, 11))).unwrap();
        o.feed(&frame(0, &rtp(130, 5, 9))).unwrap();
        o.feed(&frame(0, &rtp(1, 0, 9))).unwrap(); // outside duplicate history
        let s = o.snapshot();
        assert_eq!(s.streams[&0].timestamp_regressions, 0);
        assert_eq!(s.streams[&0].older_than_duplicate_window, 1);
        assert_eq!(s.streams[&0].gap_events, 1);
        assert_eq!(s.streams[&2].gap_events, 0);
        assert_eq!(s.streams[&2].ssrc_changes, 0);
    }
    #[test]
    fn bad_framing_disables_only_observer() {
        let mut o = MediaObserver::default();
        let input = b"INVALID RESPONSE\r\n\r\n";
        let original = input.to_vec();
        assert_eq!(o.feed(input), Err(ObservationError::InvalidFraming));
        assert_eq!(input, original.as_slice());
        assert_eq!(o.snapshot().framing_errors, 1);
        o.reset();
        o.feed(&frame(0, &rtp(100, 0, 1))).unwrap();
        assert_eq!(o.snapshot().streams[&0].gap_events, 0);
    }
    #[test]
    fn keepalive_responses_crlf_and_rtcp_between_fragmented_media() {
        let mut wire = setup().to_vec();
        wire.extend(frame(0, &rtp(1, 1, 1)));
        wire.extend(b"\r\n\r\nRTSP/1.0 200 OK\r\nCSeq: 8\r\nContent-Length: 0\r\n\r\n");
        wire.extend(frame(1, &[0x80, 201, 0, 1, 0, 0, 0, 1]));
        wire.extend(b"RTSP/1.0 200 OK\r\nCSeq: 9\r\nContent-Length: 4\r\n\r\n$xxx");
        wire.extend(frame(0, &rtp(2, 2, 1)));
        for chunk_size in [1, 2, 3, 17, 4096] {
            let mut o = MediaObserver::default();
            for chunk in wire.chunks(chunk_size) {
                o.feed(chunk).unwrap();
            }
            let s = o.snapshot();
            assert_eq!(s.framing_errors, 0);
            assert_eq!(s.rtsp_responses, 3);
            assert_eq!(s.rtcp_frames, 1);
            assert_eq!(s.streams[&0].rtp_packets, 2);
            assert_eq!(s.invalid_rtp_version, 0);
        }
    }
    #[test]
    fn counts_only_snapshot_does_not_retain_sensitive_headers() {
        let mut o = MediaObserver::default();
        o.feed(b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Basic realm=PRIVATE_SECRET\r\n\r\n").unwrap();
        let json = serde_json::to_string(&o.snapshot()).unwrap();
        assert!(!json.contains("PRIVATE_SECRET"));
        assert_eq!(o.snapshot().rtsp_error_responses, 1);
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! Passive client-to-camera RTSP request timing metadata. Never changes bytes.
//! Errors disable only observation; callers must continue normal forwarding.
use rtsp_types::{Message, Method, ParseError};
use zeroize::Zeroize;

const MAX_BUFFER: usize = 64 * 1024;
const MAX_EVENTS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisableReason {
    BufferLimit,
    EventLimit,
    InvalidFraming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedRequest {
    /// A static allowlisted protocol method, never text copied from the wire.
    pub method: &'static str,
    /// One-based count of parsed requests, including suppressed extension methods.
    pub index: u64,
}

#[derive(Debug, Default)]
pub struct RequestObservation {
    pub requests: Vec<ObservedRequest>,
    /// Set only on the feed that disables observation. Subsequent feeds are empty.
    pub disabled: Option<DisableReason>,
}

/// One instance per RTSP TCP connection. Does not retain parsed headers or URLs.
/// Deliberately has no Debug implementation because its partial buffer is private.
#[derive(Default)]
pub struct RequestObserver {
    buffer: Vec<u8>,
    disabled: bool,
    index: u64,
}

impl Drop for RequestObserver {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

impl RequestObserver {
    pub fn enabled(&self) -> bool {
        !self.disabled
    }

    fn disable(&mut self, report: &mut RequestObservation, reason: DisableReason) {
        self.disabled = true;
        self.buffer.zeroize();
        self.buffer.clear();
        report.disabled = Some(reason);
    }

    pub fn feed(&mut self, mut input: &[u8]) -> RequestObservation {
        let mut report = RequestObservation::default();
        if self.disabled {
            return report;
        }
        while !input.is_empty() {
            let available = MAX_BUFFER - self.buffer.len();
            if available == 0 {
                self.disable(&mut report, DisableReason::BufferLimit);
                return report;
            }
            let n = input.len().min(available).min(4096);
            self.buffer.extend_from_slice(&input[..n]);
            input = &input[n..];
            let mut consumed = 0;
            while consumed < self.buffer.len() {
                match Message::<&[u8]>::parse(&self.buffer[consumed..]) {
                    Ok((message, n)) if n > 0 => {
                        if let Message::Request(request) = message {
                            self.index = self.index.saturating_add(1);
                            if let Some(method) = method_name(request.method()) {
                                if report.requests.len() == MAX_EVENTS {
                                    self.disable(&mut report, DisableReason::EventLimit);
                                    return report;
                                }
                                report.requests.push(ObservedRequest {
                                    method,
                                    index: self.index,
                                });
                            }
                        }
                        consumed += n;
                    }
                    Err(ParseError::Incomplete(_)) => break,
                    _ => {
                        self.disable(&mut report, DisableReason::InvalidFraming);
                        return report;
                    }
                }
            }
            self.buffer[..consumed].zeroize();
            self.buffer.drain(..consumed);
            if self.buffer.len() == MAX_BUFFER {
                self.disable(&mut report, DisableReason::BufferLimit);
                return report;
            }
        }
        report
    }
}

fn method_name(method: &Method) -> Option<&'static str> {
    Some(match method {
        Method::Options => "OPTIONS",
        Method::Describe => "DESCRIBE",
        Method::Setup => "SETUP",
        Method::Play => "PLAY",
        Method::Pause => "PAUSE",
        Method::Teardown => "TEARDOWN",
        Method::GetParameter => "GET_PARAMETER",
        Method::SetParameter => "SET_PARAMETER",
        Method::Announce => "ANNOUNCE",
        Method::Record => "RECORD",
        Method::Redirect => "REDIRECT",
        Method::PlayNotify => "PLAY_NOTIFY",
        _ => return None,
    })
}

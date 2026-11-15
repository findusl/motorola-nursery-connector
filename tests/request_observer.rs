// SPDX-License-Identifier: GPL-3.0-or-later
// Include the owned module directly until the parent wires its public module.
use motorola_receiver::request_observer::*;

#[test]
fn fragmented_coalesced_requests_ignore_interleaved_data_and_private_headers() {
    let mut observer = RequestObserver::default();
    let input = b"OPTIONS rtsp://private-secret@camera/path RTSP/1.0\r\nCSeq: 1\r\nAuthorization: private-auth\r\n\r\n$\x01\x00\x04abcdGET_PARAMETER rtsp://private-secret@camera/path RTSP/1.0\r\nCSeq: 2\r\nContent-Length: 4\r\n\r\nbody";
    let mut events = Vec::new();
    for chunk in input.chunks(3) {
        let report = observer.feed(chunk);
        assert!(report.disabled.is_none());
        assert!(!format!("{report:?}").contains("private"));
        events.extend(report.requests);
    }
    assert_eq!(
        events,
        vec![
            ObservedRequest {
                method: "OPTIONS",
                index: 1
            },
            ObservedRequest {
                method: "GET_PARAMETER",
                index: 2
            }
        ]
    );
    assert!(observer.enabled());
}

#[test]
fn extensions_never_become_log_messages_and_coalescing_preserves_indices() {
    let mut observer = RequestObserver::default();
    let report = observer.feed(b"PRIVATE_SECRET * RTSP/1.0\r\nCSeq: 1\r\n\r\nPLAY * RTSP/1.0\r\nCSeq: 2\r\n\r\nOPTIONS * RTSP/1.0\r\nCSeq: 3\r\n\r\n");
    assert!(report.disabled.is_none());
    assert_eq!(
        report.requests,
        vec![
            ObservedRequest {
                method: "PLAY",
                index: 2
            },
            ObservedRequest {
                method: "OPTIONS",
                index: 3
            }
        ]
    );
    assert!(!format!("{report:?}").contains("PRIVATE_SECRET"));
}

#[test]
fn malformed_input_disables_only_observer_and_keeps_prior_events() {
    let mut observer = RequestObserver::default();
    let report = observer.feed(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n\0invalid\r\n\r\n");
    assert_eq!(report.requests.len(), 1);
    assert_eq!(report.disabled, Some(DisableReason::InvalidFraming));
    assert!(!observer.enabled());
    let report = observer.feed(b"PLAY * RTSP/1.0\r\nCSeq: 2\r\n\r\n");
    assert!(report.requests.is_empty());
    assert!(report.disabled.is_none());
}

#[test]
fn retained_partial_input_and_event_output_are_bounded() {
    let mut observer = RequestObserver::default();
    let mut large =
        b"SET_PARAMETER * RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 1000000\r\n\r\n".to_vec();
    large.resize(65537, b'x');
    assert_eq!(
        observer.feed(&large).disabled,
        Some(DisableReason::BufferLimit)
    );
    let mut observer = RequestObserver::default();
    let report = observer.feed(&b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n".repeat(129));
    assert_eq!(report.requests.len(), 128);
    assert_eq!(report.disabled, Some(DisableReason::EventLimit));
}

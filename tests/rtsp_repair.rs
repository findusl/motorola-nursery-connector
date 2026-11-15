// SPDX-License-Identifier: GPL-3.0-or-later
use motorola_receiver::rtsp_repair::*;

const RESPONSE: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 8\r\nContent-Length: 4\r\n\r\nbody";
fn packet() -> Vec<u8> {
    let mut p = vec![0x80, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1];
    p.extend_from_slice(b"unaltered media");
    p
}
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut f = vec![b'$', 0];
    f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    f.extend_from_slice(payload);
    f
}
fn broken() -> (Vec<u8>, Vec<u8>) {
    let f = frame(&packet());
    (
        [&f[..4], RESPONSE, &f[4..]].concat(),
        [RESPONSE, f.as_slice()].concat(),
    )
}

#[test]
fn repairs_inserted_full_response_across_every_fragment_size() {
    let (bad, good) = broken();
    for n in 1..=bad.len() {
        let mut repair = RtspRepair::new(1024).unwrap();
        let mut output = Vec::new();
        for chunk in bad.chunks(n) {
            output.extend(repair.feed(chunk).unwrap());
        }
        output.extend(repair.finish().unwrap());
        assert_eq!(output, good, "fragment size {n}");
        assert_eq!(repair.repairs(), 1);
        assert!(repair.enabled());
    }
}

#[test]
fn coalesced_normal_boundaries_and_payload_strings_are_unchanged() {
    let mut p = packet();
    p.extend_from_slice(RESPONSE);
    let ordinary = [
        RESPONSE,
        frame(&p).as_slice(),
        b"\r\n",
        RESPONSE,
        frame(&packet()).as_slice(),
    ]
    .concat();
    let mut repair = RtspRepair::new(1024).unwrap();
    assert_eq!(repair.feed(&ordinary).unwrap(), ordinary);
    assert_eq!(repair.repairs(), 0);
    assert!(repair.finish().is_ok());
    let (bad, good) = broken();
    let input = [ordinary.as_slice(), bad.as_slice(), ordinary.as_slice()].concat();
    let expected = [ordinary.as_slice(), good.as_slice(), ordinary.as_slice()].concat();
    assert_eq!(repair.feed(&input).unwrap(), expected);
    assert_eq!(repair.repairs(), 1);
}

#[test]
fn waits_for_entire_response_and_entire_original_payload() {
    let (bad, good) = broken();
    let mut repair = RtspRepair::new(1024).unwrap();
    assert!(repair.feed(&bad[..bad.len() - 1]).unwrap().is_empty());
    assert_eq!(repair.repairs(), 0);
    assert_eq!(repair.feed(&bad[bad.len() - 1..]).unwrap(), good);
}

#[test]
fn false_positive_malformed_rtp_and_ambiguous_framing_fail_closed() {
    let mut invalid_rtp = packet();
    invalid_rtp[0] = 0x90; // extension needs absent/impossible length
    invalid_rtp[14] = 255;
    invalid_rtp[15] = 255;
    let f = frame(&invalid_rtp);
    let bad = [&f[..4], RESPONSE, &f[4..]].concat();
    let mut repair = RtspRepair::new(1024).unwrap();
    assert_eq!(repair.feed(&bad), Err(RepairError::InvalidCandidate));
    assert_eq!(repair.repairs(), 0);
    assert_eq!(repair.feed(RESPONSE), Err(RepairError::Disabled));
    let mut repair = RtspRepair::new(1024).unwrap();
    assert_eq!(
        repair.feed(b"junk before RTSP/1.0 200 OK\r\n\r\n"),
        Err(RepairError::InvalidFraming)
    );
}

#[test]
fn bounded_incomplete_response_and_eof_are_errors() {
    assert!(RtspRepair::new(63).is_err());
    assert!(RtspRepair::new(1024 * 1024 + 1).is_err());
    let (bad, _) = broken();
    let mut repair = RtspRepair::new(64).unwrap();
    assert_eq!(repair.feed(&bad), Err(RepairError::BufferLimit));
    let mut repair = RtspRepair::new(1024).unwrap();
    repair.feed(&bad[..bad.len() - 1]).unwrap();
    assert_eq!(repair.finish(), Err(RepairError::Truncated));
    let mut repair = RtspRepair::new(1024).unwrap();
    assert_eq!(
        repair.feed(&[b'$', 0, 255, 255]),
        Err(RepairError::BufferLimit)
    );
}

#[test]
fn nonmatching_interleaved_payload_is_preserved_without_scanning() {
    let p = b"not RTP, RTSP/1.0 later is not a repair candidate";
    let input = frame(p);
    let mut repair = RtspRepair::new(1024).unwrap();
    assert_eq!(repair.feed(&input).unwrap(), input);
    assert_eq!(repair.repairs(), 0);
}

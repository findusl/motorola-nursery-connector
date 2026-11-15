// SPDX-License-Identifier: GPL-3.0-or-later
//! Synthetic tests from the static specification, NOT native-library oracle
//! vectors. Ports, channel IDs and payloads are invented and contain no device
//! credentials, recordings or captured camera traffic.

use motorola_receiver::{
    channel::{ChannelAction, ChannelDirection, ChannelHeader, OpenChannel},
    frame::{apply_mask, Frame, FrameDecoder},
    padding::{pad, unpad, BlockSize},
    CodecError,
};

#[test]
fn literal_open_packet_and_keepalive() {
    let open = OpenChannel {
        local_port: 18554,
        remote_port: 8554,
        request_id: 0x11223344,
    };
    assert_eq!(
        open.encode(),
        [0x7a, 0x48, 0x6a, 0x21, 0x44, 0x33, 0x22, 0x11]
    );
    let wire = open.frame().encode(64).unwrap();
    // Only the first payload word is masked for this eight-byte payload.
    assert_eq!(
        wire,
        [7, 0, 0, 0, 8, 0, 0, 0, 0x71, 0x7d, 0x6a, 0x21, 0x44, 0x33, 0x22, 0x11]
    );
    let decoded = FrameDecoder::new(64).unwrap().push(&wire).unwrap();
    assert_eq!(OpenChannel::decode(&decoded[0].payload).unwrap(), open);
    assert_eq!(
        Frame {
            command: 1,
            payload: vec![]
        }
        .encode(0)
        .unwrap(),
        [1, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn mask_strict_word_boundary_and_symmetry() {
    for length in 0..=65 {
        let original = vec![0; length];
        let mut actual = original.clone();
        apply_mask(&mut actual);
        let masked_bytes = length.saturating_sub(1) / 4 * 4;
        let expected: Vec<_> = (0..length)
            .map(|i| {
                if i < masked_bytes {
                    [0x0b, 0x35, 0, 0][i % 4]
                } else {
                    0
                }
            })
            .collect();
        assert_eq!(actual, expected, "length={length}");
        apply_mask(&mut actual);
        assert_eq!(actual, original, "length={length}");
    }
}

fn fixture_frames() -> Vec<Frame> {
    [0, 1, 4, 5, 8, 15, 16, 17, 31, 32, 33, 63]
        .into_iter()
        .enumerate()
        .map(|(index, length)| Frame {
            command: index as i32,
            payload: (0..length).map(|i| i as u8).collect(),
        })
        .collect()
}

#[test]
fn fragmented_and_coalesced_frames_for_every_split() {
    let expected = fixture_frames();
    let wire: Vec<u8> = expected
        .iter()
        .flat_map(|f| f.encode(64).unwrap())
        .collect();
    for split in 0..=wire.len() {
        let mut decoder = FrameDecoder::new(64).unwrap();
        let mut actual = decoder.push(&wire[..split]).unwrap();
        actual.extend(decoder.push(&wire[split..]).unwrap());
        assert_eq!(actual, expected, "split={split}");
        assert!(decoder.is_idle());
    }
    let mut decoder = FrameDecoder::new(64).unwrap();
    let mut actual = Vec::new();
    for byte in &wire {
        actual.extend(decoder.push(std::slice::from_ref(byte)).unwrap());
        assert!(decoder.buffered_len() <= 72);
    }
    assert_eq!(actual, expected);
}

#[test]
fn lengths_checked_before_body_allocation_and_error_poisoning() {
    let mut decoder = FrameDecoder::new(64).unwrap();
    assert_eq!(
        decoder.push(&[0, 0, 0, 0, 65, 0, 0, 0]),
        Err(CodecError::PayloadTooLarge {
            length: 65,
            maximum: 64
        })
    );
    assert_eq!(decoder.buffered_len(), 8);
    assert_eq!(decoder.push(&[]), Err(CodecError::DecoderPoisoned));
    decoder.reset();
    assert!(decoder.is_idle());
    assert_eq!(
        decoder.push(&[0, 0, 0, 0, 255, 255, 255, 255]),
        Err(CodecError::InvalidLength)
    );
    decoder.reset();
    assert_eq!(
        decoder.push(&[0, 0, 0, 0, 0, 0, 0, 128]),
        Err(CodecError::InvalidLength)
    );
    assert!(matches!(
        FrameDecoder::new(i32::MAX as usize + 1),
        Err(CodecError::InvalidLimit)
    ));
    assert!(matches!(
        Frame {
            command: 0,
            payload: vec![0; 65]
        }
        .encode(64),
        Err(CodecError::PayloadTooLarge { .. })
    ));
}

#[test]
fn partial_headers_and_bodies_are_retained() {
    let mut decoder = FrameDecoder::new(64).unwrap();
    assert!(decoder.push(&[0; 7]).unwrap().is_empty());
    assert_eq!(decoder.buffered_len(), 7);
    assert!(!decoder.is_idle());
    decoder.reset();
    assert!(decoder
        .push(&[7, 0, 0, 0, 8, 0, 0, 0, 1, 2])
        .unwrap()
        .is_empty());
    assert_eq!(decoder.buffered_len(), 10);
    assert!(!decoder.is_idle());
    decoder.reset();
    assert!(decoder.push(&[]).unwrap().is_empty());
    assert!(decoder.is_idle());
}

fn header(sequence: i32) -> ChannelHeader {
    ChannelHeader {
        request_id: 0x11223344,
        sequence,
        direction: ChannelDirection::Initiator,
        local_port: 18554,
        peer_port: 8554,
        reserved: 0,
    }
}

#[test]
fn channel_header_literal_and_ciphertext_boundary() {
    let header = header(-4);
    assert_eq!(
        header.encode(),
        [0x44, 0x33, 0x22, 0x11, 0xfc, 0xff, 0xff, 0xff, 1, 0, 0x7a, 0x48, 0x6a, 0x21, 0, 0]
    );
    let mut payload = header.encode().to_vec();
    payload.extend_from_slice(&[0xaa; 16]);
    let (decoded, ciphertext) = ChannelHeader::split(&payload).unwrap();
    assert_eq!(decoded, header);
    assert_eq!(ciphertext, [0xaa; 16]);
    assert!(ChannelHeader::split(&payload[..15]).is_err());
    payload[8] = 4;
    assert_eq!(
        ChannelHeader::split(&payload),
        Err(CodecError::InvalidDirection(4))
    );
    assert!(OpenChannel::decode(&[0; 7]).is_err());
    assert!(OpenChannel::decode(&[0; 9]).is_err());
}

#[test]
fn close_exchange_and_reject_are_distinct() {
    assert_eq!(
        header(-4).action(),
        ChannelAction::ReplyAndClose { sequence: -2 }
    );
    assert_eq!(
        header(-2).action(),
        ChannelAction::ReplyAndRemove { sequence: -3 }
    );
    assert_eq!(header(-3).action(), ChannelAction::Remove);
    for sequence in [-1, 0, 1, 100, i32::MAX] {
        assert_eq!(header(sequence).action(), ChannelAction::Forward);
    }
    let mut reject = header(0);
    reject.direction = ChannelDirection::Rejected;
    assert_eq!(reject.action(), ChannelAction::Remove);
    reject.sequence = -4;
    assert_eq!(reject.action(), ChannelAction::Remove);
}

#[test]
fn padding_block_boundaries_and_bounds() {
    for block in [BlockSize::Bytes16, BlockSize::Bytes32] {
        for length in [0, 1, 4, 5, 8, 15, 16, 17, 31, 32, 33] {
            let input = vec![0x55; length];
            let padded = pad(&input, block, 96).unwrap();
            let expected_length = (length / block.bytes() + 1) * block.bytes();
            assert_eq!(padded.len(), expected_length);
            assert!(padded[length..]
                .iter()
                .all(|b| *b as usize == expected_length - length));
            assert_eq!(unpad(&padded).unwrap(), input);
        }
    }
    assert_eq!(
        pad(&[], BlockSize::Bytes16, 15),
        Err(CodecError::PayloadTooLarge {
            length: 16,
            maximum: 15
        })
    );
    assert!(unpad(&[0x20; 32]).unwrap().is_empty());
    for invalid in [&[][..], &[0][..], &[0x21][..], &[2][..], &[1, 2][..]] {
        assert_eq!(unpad(invalid), Err(CodecError::InvalidPadding));
    }
}

#[test]
fn debug_does_not_dump_payload() {
    let value = format!(
        "{:?}",
        Frame {
            command: 0,
            payload: b"sensitive-token".to_vec()
        }
    );
    assert!(!value.contains("sensitive"));
    assert!(value.contains("payload_length"));
}

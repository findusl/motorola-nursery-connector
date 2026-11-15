// SPDX-License-Identifier: GPL-3.0-or-later
//! Native-oracle outputs with generated, non-device inputs. These fixtures were
//! measured from the supplied library, unlike synthetic_codec.rs expectations.
//! See fixtures/ORACLE.md for provenance and exact execution command.

use motorola_receiver::frame::{Frame, FrameDecoder};

// command=7; plaintext byte[i]=(17*i+3) mod256. No camera or account data.
const CASES: &[(usize, &str)] = &[
    (0, "0700000000000000"),
    (1, "070000000100000003"),
    (4, "070000000400000003142536"),
    (5, "07000000050000000821253647"),
    (8, "0700000008000000082125364758697a"),
    (15, "070000000f000000082125364c6d697a80a9adbecfe0f1"),
    (16, "0700000010000000082125364c6d697a80a9adbecfe0f102"),
    (17, "0700000011000000082125364c6d697a80a9adbec4d5f10213"),
    (31, "070000001f000000082125364c6d697a80a9adbec4d5f102181135465c5d798a9099bdcedff001"),
    (32, "0700000020000000082125364c6d697a80a9adbec4d5f102181135465c5d798a9099bdcedff00112"),
    (33, "0700000021000000082125364c6d697a80a9adbec4d5f102181135465c5d798a9099bdced4c5011223"),
    (255, "07000000ff000000082125364c6d697a80a9adbec4d5f102181135465c5d798a9099bdced4c50112280145566c4d899aa089cddee4351122387155667cbd99aab0f9ddeef4252132486165768cada9bac0e9edfe04153142585175869c9db9cad0d9fd0e1405415268418596ac8dc9dae0c90d1e2475516278b195a6bcfdd9eaf0391d2e3465617288a1a5b6ccede9fa00292d3e445571829891b5c6dcddf90a10193d4e54458192a881c5d6eccd091a20094d5e64b591a2b8f1d5e6fc3d192a30795d6e74a5a1b2c8e1e5f60c2d293a40696d7e8495b1c2d8d1f5061c1d394a50597d8e9485c1d2e8c105162c0d495a60498d9ea4f5d1e2f83115263c7d596a70b99daebfd0e1"),
    (256, "0700000000010000082125364c6d697a80a9adbec4d5f102181135465c5d798a9099bdced4c50112280145566c4d899aa089cddee4351122387155667cbd99aab0f9ddeef4252132486165768cada9bac0e9edfe04153142585175869c9db9cad0d9fd0e1405415268418596ac8dc9dae0c90d1e2475516278b195a6bcfdd9eaf0391d2e3465617288a1a5b6ccede9fa00292d3e445571829891b5c6dcddf90a10193d4e54458192a881c5d6eccd091a20094d5e64b591a2b8f1d5e6fc3d192a30795d6e74a5a1b2c8e1e5f60c2d293a40696d7e8495b1c2d8d1f5061c1d394a50597d8e9485c1d2e8c105162c0d495a60498d9ea4f5d1e2f83115263c7d596a70b99daebfd0e1f2"),
    (513, "0700000001020000082125364c6d697a80a9adbec4d5f102181135465c5d798a9099bdced4c50112280145566c4d899aa089cddee4351122387155667cbd99aab0f9ddeef4252132486165768cada9bac0e9edfe04153142585175869c9db9cad0d9fd0e1405415268418596ac8dc9dae0c90d1e2475516278b195a6bcfdd9eaf0391d2e3465617288a1a5b6ccede9fa00292d3e445571829891b5c6dcddf90a10193d4e54458192a881c5d6eccd091a20094d5e64b591a2b8f1d5e6fc3d192a30795d6e74a5a1b2c8e1e5f60c2d293a40696d7e8495b1c2d8d1f5061c1d394a50597d8e9485c1d2e8c105162c0d495a60498d9ea4f5d1e2f83115263c7d596a70b99daeb4e5e1f2082125364c6d697a80a9adbec4d5f102181135465c5d798a9099bdced4c50112280145566c4d899aa089cddee4351122387155667cbd99aab0f9ddeef4252132486165768cada9bac0e9edfe04153142585175869c9db9cad0d9fd0e1405415268418596ac8dc9dae0c90d1e2475516278b195a6bcfdd9eaf0391d2e3465617288a1a5b6ccede9fa00292d3e445571829891b5c6dcddf90a10193d4e54458192a881c5d6eccd091a20094d5e64b591a2b8f1d5e6fc3d192a30795d6e74a5a1b2c8e1e5f60c2d293a40696d7e8495b1c2d8d1f5061c1d394a50597d8e9485c1d2e8c105162c0d495a60498d9ea4f5d1e2f83115263c7d596a70b99daeb4e5e1f203"),
];

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid oracle fixture hex"),
            };
            nibble(pair[0]) * 16 + nibble(pair[1])
        })
        .collect()
}

#[test]
fn all_fourteen_native_packet_vectors_match_encoder() {
    assert_eq!(CASES.len(), 14);
    for &(length, hex) in CASES {
        let payload = (0..length).map(|i| (17 * i + 3) as u8).collect();
        let frame = Frame {
            command: 7,
            payload,
        };
        assert_eq!(
            frame.encode(1024).unwrap(),
            decode_hex(hex),
            "native payload length={length}"
        );
    }
}

#[test]
fn all_native_vectors_decode_across_every_byte_boundary() {
    for &(length, hex) in CASES {
        let wire = decode_hex(hex);
        let expected = Frame {
            command: 7,
            payload: (0..length).map(|i| (17 * i + 3) as u8).collect(),
        };
        for split in 0..=wire.len() {
            let mut decoder = FrameDecoder::new(1024).unwrap();
            let mut output = decoder.push(&wire[..split]).unwrap();
            output.extend(decoder.push(&wire[split..]).unwrap());
            assert_eq!(
                output.as_slice(),
                std::slice::from_ref(&expected),
                "native length={length}, split={split}"
            );
            assert!(decoder.is_idle());
        }
    }
}

#[test]
fn coalesced_native_vectors_decode_in_order() {
    let wire: Vec<u8> = CASES.iter().flat_map(|(_, hex)| decode_hex(hex)).collect();
    let expected: Vec<_> = CASES
        .iter()
        .map(|&(length, _)| Frame {
            command: 7,
            payload: (0..length).map(|i| (17 * i + 3) as u8).collect(),
        })
        .collect();
    let mut decoder = FrameDecoder::new(1024).unwrap();
    assert_eq!(decoder.push(&wire).unwrap(), expected);
    assert!(decoder.is_idle());
}

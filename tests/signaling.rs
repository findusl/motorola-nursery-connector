// SPDX-License-Identifier: GPL-3.0-or-later
//! Synthetic fixtures only; no credential, native library, or camera access.
use motorola_receiver::signaling::*;

#[test]
fn registration_and_identity_use_exact_native_termination_rules() {
    let id = generated_id("test-device", "ABCDEFGH-IJKL-MNOP-QRST-UVWXYZABCDEF", 7).unwrap();
    assert_eq!(
        id,
        "test-device_ctok_ABCDEFGH-IJKL-MNOP-QRST-UVWXYZABCDEF#007"
    );
    assert_eq!(register103(&id).unwrap().payload, id.as_bytes());
    assert_eq!(success115(&id).unwrap().payload, id.as_bytes());
    assert_eq!(
        listen200(&id, &[]).unwrap().payload,
        format!("{id}\0").as_bytes()
    );
    assert_eq!(
        generated_id("d", "t", 1000),
        Err(SignalingError::InvalidCounter)
    );
    assert!(generated_id("d;injected", "t", 1).is_err());
}

#[test]
fn request_layouts_match_native_offsets_not_rust_struct_alignment() {
    let frame = host_nic119("device", "generated", 2, 1, 15000).unwrap();
    assert_eq!(frame.command, 119);
    let mut expected = vec![0; 524];
    expected[..6].copy_from_slice(b"device");
    expected[128..133].copy_from_slice(b"4.5.3");
    expected[255..264].copy_from_slice(b"generated");
    expected[512..516].copy_from_slice(&[2, 0, 0, 0]);
    expected[516..520].copy_from_slice(&[1, 0, 0, 0]);
    expected[520..524].copy_from_slice(&[0x98, 0x3a, 0, 0]);
    assert_eq!(frame.payload, expected);

    let frame = connect106("device", "generated", "client-token", "192.0.2.1").unwrap();
    let mut expected = vec![0; 802];
    expected[..6].copy_from_slice(b"device");
    expected[258..267].copy_from_slice(b"generated");
    expected[513..525].copy_from_slice(b"client-token");
    expected[768..777].copy_from_slice(b"192.0.2.1");
    expected[800..802].copy_from_slice(&[0xbb, 0x01]);
    assert_eq!(frame.command, 106);
    assert_eq!(frame.payload, expected);
    assert!(host_nic119(&"x".repeat(128), "id", 1, 1, 1).is_err());
    assert!(connect106("d", &"i".repeat(255), "t", "192.0.2.1").is_err());
}

#[test]
fn bootstrap_server_slots_are_bounded() {
    let mut payload = vec![0; 160];
    for (i, text) in [
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.3",
        "192.0.2.4",
        "192.0.2.5",
    ]
    .iter()
    .enumerate()
    {
        payload[i * 32..i * 32 + text.len()].copy_from_slice(text.as_bytes());
    }
    let servers = parse104(&payload).unwrap();
    assert_eq!(servers.stun_tcp_primary, "192.0.2.1");
    assert_eq!(servers.stun_tcp_secondary, "192.0.2.2");
    assert_eq!(servers.shunt, "192.0.2.3");
    assert_eq!(servers.stun_primary, "192.0.2.4");
    assert_eq!(servers.stun_secondary, "192.0.2.5");
    assert!(parse104(&payload[..159]).is_err());
    payload[..32].fill(b'x');
    assert_eq!(parse104(&payload), Err(SignalingError::MissingTerminator));
}

#[test]
fn capabilities_keep_version_cipher_and_mode_distinct() {
    let mut payload = vec![0; 524];
    payload[128..133].copy_from_slice(b"4.5.3");
    payload[509] = 1;
    payload[512..516].copy_from_slice(&3u32.to_le_bytes());
    payload[516..520].copy_from_slice(&5u32.to_le_bytes());
    assert_eq!(
        parse120(&payload).unwrap(),
        HostCapabilities {
            version: [4, 5, 3],
            cipher_flag: 1,
            host_nic_count: 3,
            host_mode: 5
        }
    );
    payload[128..133].copy_from_slice(b"4.5.x");
    assert_eq!(parse120(&payload), Err(SignalingError::InvalidVersion));
    assert!(parse120(&payload[..520]).is_err());
}

#[test]
fn direct_candidates_support_ipv4_and_native_unbracketed_ipv6() {
    let parsed = parse204(b"first-id;second-id;192.0.2.1:1234;2001:db8::1:5678\0").unwrap();
    assert_eq!(parsed.identity_a, "first-id");
    assert_eq!(parsed.identity_b, "second-id");
    assert_eq!(parsed.candidates[0], "192.0.2.1:1234".parse().unwrap());
    assert_eq!(parsed.candidates[1], "[2001:db8::1]:5678".parse().unwrap());
    let outgoing = listen200("id", &parsed.candidates).unwrap();
    assert_eq!(outgoing.payload, b"id;192.0.2.1:1234;2001:db8::1:5678\0");
    assert!(!format!("{parsed:?}").contains("first-id"));
    for invalid in [
        &b"a;b;192.0.2.1:0\0"[..],
        b"a;b;192.0.2.1:65536\0",
        b"a;b\0",
        b"a;b;192.0.2.1:123",
        b"a;b;host.invalid:123\0",
    ] {
        assert!(parse204(invalid).is_err());
    }
    let oversized = format!(
        "a;b;{}\0",
        vec!["192.0.2.1:1"; MAX_CANDIDATES + 1].join(";")
    );
    assert_eq!(
        parse204(oversized.as_bytes()),
        Err(SignalingError::TooManyCandidates)
    );
}

#[test]
fn discovery_host_cannot_inject_url_authority_or_path() {
    assert_eq!(
        discovery_url("example.invalid").unwrap(),
        "https://example.invalid/api/device/connection"
    );
    assert_eq!(
        discovery_url("192.0.2.1").unwrap(),
        "https://192.0.2.1/api/device/connection"
    );
    assert_eq!(
        discovery_url("2001:db8::1").unwrap(),
        "https://[2001:db8::1]/api/device/connection"
    );
    for invalid in [
        "",
        "https://example.invalid",
        "user@host",
        "host/path",
        "host:443",
        "a..b",
        "-host",
        "host\n",
    ] {
        assert!(discovery_url(invalid).is_err());
    }
}

#[test]
fn direct_response_uses_bounded_c_string_prefix_like_native_strlen() {
    let a = parse204(b"a;b;192.0.2.1:123\0").unwrap();
    for bytes in [
        b"a;b;192.0.2.1:123\0\0".as_slice(),
        b"a;b;192.0.2.1:123\0ignored\0".as_slice(),
    ] {
        assert_eq!(parse204(bytes).unwrap(), a);
    }
}

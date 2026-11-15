// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline I/O tests over in-memory duplex streams. No camera/network access.
//! The read task retains its cursor when the consumer's receive is cancelled.

use motorola_receiver::{
    frame::Frame,
    wire_io::{read_frame, write_frame, MAX_FRAME},
    CodecError,
};
use std::{io::ErrorKind, time::Duration};
use tokio::{
    io::{duplex, AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    time::{sleep, timeout},
};

fn sample(command: i32, length: usize) -> Frame {
    Frame {
        command,
        payload: (0..length).map(|i| (i * 17 + 3) as u8).collect(),
    }
}

#[tokio::test]
async fn fragment_every_byte_and_coalesce_multiple_frames() {
    let expected = [sample(1, 0), sample(7, 8), sample(0, 513)];
    let wire: Vec<_> = expected
        .iter()
        .flat_map(|f| f.encode(MAX_FRAME).unwrap())
        .collect();
    for capacity in [1, 8, 2048] {
        let (mut writer, mut reader) = duplex(capacity);
        let bytes = wire.clone();
        let task = tokio::spawn(async move {
            if capacity == 1 {
                for byte in bytes {
                    writer.write_all(&[byte]).await.unwrap();
                }
            } else {
                writer.write_all(&bytes).await.unwrap();
            }
            writer.shutdown().await.unwrap();
        });
        for frame in &expected {
            let actual = timeout(Duration::from_secs(2), read_frame(&mut reader))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&actual, frame);
        }
        task.await.unwrap();
        let eof = read_frame(&mut reader).await.unwrap_err();
        assert_eq!(
            eof.downcast_ref::<std::io::Error>().unwrap().kind(),
            ErrorKind::UnexpectedEof
        );
    }
}

#[tokio::test]
async fn negative_and_oversized_lengths_rejected_without_waiting_for_payload() {
    for length in [-1, i32::MIN, MAX_FRAME as i32 + 1, i32::MAX] {
        let (mut writer, mut reader) = duplex(8);
        let mut header = [0; 8];
        header[4..].copy_from_slice(&length.to_le_bytes());
        writer.write_all(&header).await.unwrap();
        // Keep writer open: parser must reject the header, not await body/EOF.
        let error = timeout(Duration::from_millis(100), read_frame(&mut reader))
            .await
            .unwrap()
            .unwrap_err();
        if length < 0 {
            assert_eq!(
                error.downcast_ref::<CodecError>(),
                Some(&CodecError::InvalidLength)
            );
        } else {
            assert_eq!(error.to_string(), "frame_limit");
        }
    }
}

#[tokio::test]
async fn incomplete_header_and_payload_report_unexpected_eof() {
    let wire = sample(0, 32).encode(MAX_FRAME).unwrap();
    for length in [0, 1, 7, 8, 9, wire.len() - 1] {
        let (mut writer, mut reader) = duplex(64);
        writer.write_all(&wire[..length]).await.unwrap();
        writer.shutdown().await.unwrap();
        let error = read_frame(&mut reader).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            ErrorKind::UnexpectedEof
        );
    }
}

#[tokio::test]
async fn cancelled_consumer_does_not_cancel_dedicated_reader_cursor() {
    let expected = sample(0, 33);
    let wire = expected.encode(MAX_FRAME).unwrap();
    let (mut writer, mut reader) = duplex(64);
    let (tx, mut rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        let result = read_frame(&mut reader).await;
        tx.send(result).await.unwrap();
    });
    writer.write_all(&wire[..5]).await.unwrap();
    assert!(timeout(Duration::from_millis(10), rx.recv()).await.is_err());
    writer.write_all(&wire[5..]).await.unwrap();
    let actual = timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(actual, expected);
    task.await.unwrap();
}

#[tokio::test]
async fn caller_deadline_drops_a_stalled_read_transport() {
    let (mut writer, mut reader) = duplex(8);
    writer.write_all(&[0; 4]).await.unwrap();
    assert!(timeout(Duration::from_millis(10), read_frame(&mut reader))
        .await
        .is_err());
    // read_exact is not cancellation safe. Never resume this stream after its
    // owning read is cancelled; discard the transport as the session does.
    drop(reader);
    assert_eq!(
        writer.write_all(&[0]).await.unwrap_err().kind(),
        ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn writes_survive_transport_backpressure_when_reader_progresses() {
    let expected = sample(0, 8192);
    let send = expected.clone();
    let (mut writer, mut reader) = duplex(8);
    let task = tokio::spawn(async move { write_frame(&mut writer, &send).await });
    sleep(Duration::from_millis(10)).await;
    let actual = read_frame(&mut reader).await.unwrap();
    assert_eq!(actual, expected);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn oversized_write_rejected_before_any_transport_bytes() {
    let (mut writer, mut reader) = duplex(8);
    let error = write_frame(&mut writer, &sample(0, MAX_FRAME + 1))
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<CodecError>(),
        Some(CodecError::PayloadTooLarge { .. })
    ));
    let mut byte = [0];
    assert!(timeout(Duration::from_millis(10), reader.read(&mut byte))
        .await
        .is_err());
}

#[tokio::test]
async fn stalled_write_has_deadline_and_transport_must_be_discarded() {
    let (mut writer, _held_reader) = duplex(8);
    let result = timeout(
        Duration::from_secs(12),
        write_frame(&mut writer, &sample(0, 32)),
    )
    .await
    .expect("write_frame must enforce its internal deadline");
    assert_eq!(result.unwrap_err().to_string(), "write_timeout");
    // Header bytes may already have been sent. A retry on this same transport
    // would corrupt framing, so callers must drop it after a timeout.
    drop(writer);
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! Verified TLS and bounded line I/O. This module contains no account grammar.
//! Read timeouts/cancellation preserve partial input for OTP/heartbeat polling.
use std::{fmt, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{
    client::TlsStream,
    rustls::{self, pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_LINE_BYTES: usize = 64 * 1024;
pub const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
#[derive(Clone, Copy)]
pub struct Limits {
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub write_timeout: Duration,
    pub read_timeout: Duration,
    pub max_line_bytes: usize,
    pub max_total_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(10),
            max_line_bytes: MAX_LINE_BYTES,
            max_total_bytes: MAX_TOTAL_BYTES,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), TransportError> {
        if self.max_line_bytes == 0
            || self.max_line_bytes > MAX_LINE_BYTES
            || self.max_total_bytes == 0
            || self.max_total_bytes > MAX_TOTAL_BYTES
            || [
                self.connect_timeout,
                self.handshake_timeout,
                self.write_timeout,
                self.read_timeout,
            ]
            .iter()
            .any(Duration::is_zero)
        {
            Err(TransportError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    InvalidLimits,
    InvalidHost,
    InvalidCommand,
    ConnectTimeout,
    ConnectFailed,
    TlsConfiguration,
    HandshakeTimeout,
    HandshakeFailed,
    WriteTimeout,
    WriteFailed,
    ReadTimeout,
    ReadFailed,
    LineLimit,
    TotalLimit,
    TruncatedLine,
    InvalidText,
    Closed,
}
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "account_invalid_limits",
            Self::InvalidHost => "account_invalid_host",
            Self::InvalidCommand => "account_invalid_command",
            Self::ConnectTimeout => "account_connect_timeout",
            Self::ConnectFailed => "account_connect_failed",
            Self::TlsConfiguration => "account_tls_configuration",
            Self::HandshakeTimeout => "account_handshake_timeout",
            Self::HandshakeFailed => "account_handshake_failed",
            Self::WriteTimeout => "account_write_timeout",
            Self::WriteFailed => "account_write_failed",
            Self::ReadTimeout => "account_read_timeout",
            Self::ReadFailed => "account_read_failed",
            Self::LineLimit => "account_line_limit",
            Self::TotalLimit => "account_total_limit",
            Self::TruncatedLine => "account_truncated_line",
            Self::InvalidText => "account_invalid_text",
            Self::Closed => "account_transport_closed",
        })
    }
}
impl std::error::Error for TransportError {}
/// Deliberately no Display; Debug never exposes a server response or token.
pub struct SecretLine(Zeroizing<String>);
impl SecretLine {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
impl AsRef<str> for SecretLine {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl fmt::Debug for SecretLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretLine([REDACTED])")
    }
}

pub struct LineReader<R> {
    reader: R,
    limits: Limits,
    partial: Zeroizing<Vec<u8>>,
    pending: Zeroizing<[u8; 4096]>,
    cursor: usize,
    end: usize,
    received: usize,
    failed: bool,
}
impl<R: AsyncRead + Unpin> LineReader<R> {
    pub fn new(reader: R, limits: Limits) -> Result<Self, TransportError> {
        limits.validate()?;
        Ok(Self {
            reader,
            limits,
            partial: Zeroizing::new(Vec::new()),
            pending: Zeroizing::new([0; 4096]),
            cursor: 0,
            end: 0,
            received: 0,
            failed: false,
        })
    }
    /// Timeout is retryable and retains all already consumed bytes. Other errors
    /// poison the reader; an external cancellation also leaves partial input intact.
    pub async fn read_line(&mut self) -> Result<Option<SecretLine>, TransportError> {
        if self.failed {
            return Err(TransportError::Closed);
        }
        match timeout(self.limits.read_timeout, self.read_inner()).await {
            Err(_) => Err(TransportError::ReadTimeout),
            Ok(Err(e)) => {
                self.failed = true;
                Err(e)
            }
            Ok(result) => result,
        }
    }
    async fn read_inner(&mut self) -> Result<Option<SecretLine>, TransportError> {
        loop {
            if self.cursor == self.end {
                self.pending.zeroize();
                let count = self
                    .reader
                    .read(self.pending.as_mut())
                    .await
                    .map_err(|_| TransportError::ReadFailed)?;
                if count == 0 {
                    return if self.partial.is_empty() {
                        Ok(None)
                    } else {
                        Err(TransportError::TruncatedLine)
                    };
                }
                self.received = self
                    .received
                    .checked_add(count)
                    .ok_or(TransportError::TotalLimit)?;
                if self.received > self.limits.max_total_bytes {
                    return Err(TransportError::TotalLimit);
                }
                self.cursor = 0;
                self.end = count;
            }
            let bytes = &self.pending[self.cursor..self.end];
            let newline = bytes.iter().position(|b| *b == b'\n');
            let count = newline.unwrap_or(bytes.len());
            if self.partial.len() + count > self.limits.max_line_bytes {
                return Err(TransportError::LineLimit);
            }
            self.partial.extend_from_slice(&bytes[..count]);
            self.pending[self.cursor..self.cursor + count].zeroize();
            self.cursor += count;
            if newline.is_some() {
                self.cursor += 1;
                if self.partial.last() == Some(&b'\r') {
                    self.partial.pop();
                }
                if self.partial.contains(&b'\r') {
                    return Err(TransportError::InvalidText);
                }
                let text =
                    std::str::from_utf8(&self.partial).map_err(|_| TransportError::InvalidText)?;
                let line = SecretLine(Zeroizing::new(text.to_owned()));
                self.partial.zeroize();
                return Ok(Some(line));
            }
        }
    }
}

fn command_length(command: &str, limits: Limits, used: usize) -> Result<usize, TransportError> {
    if command.contains(['\r', '\n']) {
        return Err(TransportError::InvalidCommand);
    }
    if command.len() > limits.max_line_bytes {
        return Err(TransportError::LineLimit);
    }
    let count = command.len() + 1;
    if used
        .checked_add(count)
        .is_none_or(|n| n > limits.max_total_bytes)
    {
        return Err(TransportError::TotalLimit);
    }
    Ok(count)
}
async fn write_command<W: AsyncWrite + Unpin>(
    writer: &mut W,
    command: &str,
    deadline: Duration,
) -> Result<(), TransportError> {
    timeout(deadline, async {
        writer.write_all(command.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await
    })
    .await
    .map_err(|_| TransportError::WriteTimeout)?
    .map_err(|_| TransportError::WriteFailed)
}

pub struct AccountTransport {
    reader: LineReader<ReadHalf<TlsStream<TcpStream>>>,
    writer: WriteHalf<TlsStream<TcpStream>>,
    limits: Limits,
    sent: usize,
    failed: bool,
}
impl AccountTransport {
    pub async fn connect(host: &str, port: u16, limits: Limits) -> Result<Self, TransportError> {
        limits.validate()?;
        let name =
            ServerName::try_from(host.to_owned()).map_err(|_| TransportError::InvalidHost)?;
        if !matches!(name, ServerName::DnsName(_)) || port == 0 {
            return Err(TransportError::InvalidHost);
        }
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|_| TransportError::TlsConfiguration)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        let tcp = timeout(limits.connect_timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| TransportError::ConnectTimeout)?
            .map_err(|_| TransportError::ConnectFailed)?;
        let tls = timeout(
            limits.handshake_timeout,
            TlsConnector::from(Arc::new(config)).connect(name, tcp),
        )
        .await
        .map_err(|_| TransportError::HandshakeTimeout)?
        .map_err(|_| TransportError::HandshakeFailed)?;
        let (reader, writer) = tokio::io::split(tls);
        Ok(Self {
            reader: LineReader::new(reader, limits)?,
            writer,
            limits,
            sent: 0,
            failed: false,
        })
    }
    pub async fn send(&mut self, command: &str) -> Result<(), TransportError> {
        if self.failed {
            return Err(TransportError::Closed);
        }
        let count = command_length(command, self.limits, self.sent + self.reader.received)?;
        // Cancellation or a partial write must never allow another command to
        // continue on a stream with an unknown command boundary.
        self.failed = true;
        write_command(&mut self.writer, command, self.limits.write_timeout).await?;
        self.sent += count;
        self.reader.limits.max_total_bytes = self.limits.max_total_bytes - self.sent;
        self.failed = false;
        Ok(())
    }
    pub async fn read_line(&mut self) -> Result<Option<SecretLine>, TransportError> {
        if self.failed {
            return Err(TransportError::Closed);
        }
        let result = self.reader.read_line().await;
        if matches!(result, Ok(None))
            || matches!(result, Err(e) if e != TransportError::ReadTimeout)
        {
            self.failed = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn limits() -> Limits {
        Limits {
            read_timeout: Duration::from_millis(20),
            ..Limits::default()
        }
    }
    #[tokio::test]
    async fn fragmented_batched_crlf_and_clean_eof() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            for b in b"one\ntwo\r\n\n" {
                writer.write_all(&[*b]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut reader = LineReader::new(reader, limits()).unwrap();
        for expected in ["one", "two", ""] {
            assert_eq!(
                reader.read_line().await.unwrap().unwrap().as_str(),
                expected
            );
        }
        assert!(reader.read_line().await.unwrap().is_none());
        task.await.unwrap();
    }
    #[tokio::test]
    async fn timeout_and_external_cancellation_preserve_partial_lines() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut reader = LineReader::new(reader, limits()).unwrap();
        writer.write_all(b"private").await.unwrap();
        assert_eq!(
            reader.read_line().await.unwrap_err(),
            TransportError::ReadTimeout
        );
        writer.write_all(b"-part").await.unwrap();
        assert!(timeout(Duration::from_millis(2), reader.read_line())
            .await
            .is_err());
        writer.write_all(b"-end\nnext\n").await.unwrap();
        let line = reader.read_line().await.unwrap().unwrap();
        assert_eq!(line.as_str(), "private-part-end");
        assert!(!format!("{line:?}").contains("private"));
        assert_eq!(reader.read_line().await.unwrap().unwrap().as_str(), "next");
    }
    async fn failure(bytes: &[u8], limits: Limits) -> TransportError {
        let (mut writer, reader) = tokio::io::duplex(128);
        writer.write_all(bytes).await.unwrap();
        drop(writer);
        let mut reader = LineReader::new(reader, limits).unwrap();
        let e = reader.read_line().await.unwrap_err();
        assert_eq!(
            reader.read_line().await.unwrap_err(),
            TransportError::Closed
        );
        e
    }
    #[tokio::test]
    async fn malformed_truncated_and_size_limits_fail_closed() {
        assert_eq!(
            failure(b"partial", limits()).await,
            TransportError::TruncatedLine
        );
        assert_eq!(
            failure(b"\xff\n", limits()).await,
            TransportError::InvalidText
        );
        assert_eq!(
            failure(b"one\rtwo\n", limits()).await,
            TransportError::InvalidText
        );
        assert_eq!(
            failure(
                b"12345\n",
                Limits {
                    max_line_bytes: 4,
                    ..limits()
                }
            )
            .await,
            TransportError::LineLimit
        );
        assert_eq!(
            failure(
                b"a\nb\nc\n",
                Limits {
                    max_total_bytes: 4,
                    ..limits()
                }
            )
            .await,
            TransportError::TotalLimit
        );
    }
    #[tokio::test]
    async fn invalid_limits_and_non_dns_host_fail_before_network() {
        assert!(matches!(
            AccountTransport::connect("127.0.0.1", 443, limits()).await,
            Err(TransportError::InvalidHost)
        ));
        assert!(matches!(
            AccountTransport::connect("invalid\nname", 443, limits()).await,
            Err(TransportError::InvalidHost)
        ));
        assert!(matches!(
            LineReader::new(
                tokio::io::empty(),
                Limits {
                    max_line_bytes: MAX_LINE_BYTES + 1,
                    ..limits()
                }
            ),
            Err(TransportError::InvalidLimits)
        ));
    }
    #[tokio::test]
    async fn writes_append_lf_and_have_bounded_backpressure() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        write_command(&mut writer, "synthetic", Duration::from_millis(20))
            .await
            .unwrap();
        let mut bytes = [0; 10];
        reader.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"synthetic\n");
        let (mut blocked, _reader) = tokio::io::duplex(1);
        assert_eq!(
            write_command(&mut blocked, "private", Duration::from_millis(5))
                .await
                .unwrap_err(),
            TransportError::WriteTimeout
        );
        let (mut closed, reader) = tokio::io::duplex(1);
        drop(reader);
        assert_eq!(
            write_command(&mut closed, "private", Duration::from_millis(5))
                .await
                .unwrap_err(),
            TransportError::WriteFailed
        );
    }
    #[test]
    fn commands_cannot_inject_lines_or_exceed_combined_budget() {
        for command in ["private\nextra", "private\rextra"] {
            assert_eq!(
                command_length(command, limits(), 0),
                Err(TransportError::InvalidCommand)
            );
        }
        assert_eq!(
            command_length(
                "12345",
                Limits {
                    max_line_bytes: 4,
                    ..limits()
                },
                0
            ),
            Err(TransportError::LineLimit)
        );
        assert_eq!(
            command_length(
                "abc",
                Limits {
                    max_total_bytes: 10,
                    ..limits()
                },
                7
            ),
            Err(TransportError::TotalLimit)
        );
        assert_eq!(
            command_length(
                "abc",
                Limits {
                    max_total_bytes: 10,
                    ..limits()
                },
                6
            ),
            Ok(4)
        );
    }
}

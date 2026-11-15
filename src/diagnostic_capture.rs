// SPDX-License-Identifier: GPL-3.0-or-later
//! Explicit private failure capture, disabled unless a private directory is set.
//! Contains session keys and media: never publish captures. Directory-wide limits
//! survive retries. File writes run off the async executor; the caller may track
//! the returned future separately if its own event loop must remain responsive.
use crate::crypto::TunnelCipher;
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

const MAX_PACKET_BYTES: usize = 1024 * 1024;
const MAX_RING_BYTES: usize = 2 * 1024 * 1024;
const MAX_PACKETS: usize = 32;
const MAX_FILES: usize = 4;
const MAX_DIRECTORY_BYTES: u64 = 32 * 1024 * 1024;
// Decimal byte arrays expand at most fourfold, plus header/JSON metadata.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024 + 64 * 1024;
const LOCK_FILE: &str = ".capture.lock";

#[derive(Serialize)]
struct Packet {
    request_id: i32,
    sequence: i32,
    header: [u8; 16],
    encrypted: Vec<u8>,
    plain: Vec<u8>,
}
impl Drop for Packet {
    fn drop(&mut self) {
        self.header.zeroize();
        self.encrypted.zeroize();
        self.plain.zeroize();
    }
}
#[derive(Serialize)]
struct Snapshot {
    mode: u8,
    key: [u8; 16],
    iv: [u8; 32],
    packets: VecDeque<Packet>,
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
        // Packet Drop wipes both plaintext and encrypted buffers.
    }
}
pub(crate) struct FailureCapture {
    directory: PathBuf,
    packets: VecDeque<Packet>,
    bytes: usize,
    dumps: usize,
}
fn validate_directory(path: &Path) -> Result<()> {
    let m = std::fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && !m.file_type().is_symlink() && m.permissions().mode() & 0o077 == 0,
        "capture_directory_must_be_private"
    );
    Ok(())
}
impl FailureCapture {
    pub fn new(path: &Path) -> Result<Self> {
        validate_directory(path)?;
        Ok(Self {
            directory: path.into(),
            packets: VecDeque::new(),
            bytes: 0,
            dumps: 0,
        })
    }
    pub fn remember(
        &mut self,
        request_id: i32,
        sequence: i32,
        header: [u8; 16],
        encrypted: &[u8],
        plain: &[u8],
    ) {
        let Some(n) = encrypted.len().checked_add(plain.len()) else {
            return;
        };
        if n > MAX_PACKET_BYTES {
            return;
        }
        while self.packets.len() >= MAX_PACKETS || n > MAX_RING_BYTES - self.bytes {
            if let Some(p) = self.packets.pop_front() {
                self.bytes -= p.encrypted.len() + p.plain.len();
            } else {
                break;
            }
        }
        self.bytes += n;
        self.packets.push_back(Packet {
            request_id,
            sequence,
            header,
            encrypted: encrypted.to_vec(),
            plain: plain.to_vec(),
        });
    }
    pub fn dump(
        &mut self,
        cipher: &TunnelCipher,
    ) -> impl std::future::Future<Output = Result<bool>> + Send + 'static {
        let snapshot = if self.dumps >= 2 {
            None
        } else {
            self.dumps += 1;
            let (mode, key, iv) = cipher.diagnostic_material();
            let snapshot = Snapshot {
                mode,
                key: *key,
                iv: *iv,
                packets: std::mem::take(&mut self.packets),
            };
            self.bytes = 0;
            Some(snapshot)
        };
        let directory = self.directory.clone();
        async move {
            let Some(snapshot) = snapshot else {
                return Ok(false);
            };
            tokio::task::spawn_blocking(move || write_snapshot(&directory, snapshot))
                .await
                .context("capture_writer_task_failed")?
        }
    }
}

/// Exclusive, fail-closed cross-attempt/process reservation. A process crash may
/// leave this empty lock behind: captures then stop until the owner removes it.
/// We do not guess whether a lock owner is still running or delete its files.
struct DirectoryLock {
    path: PathBuf,
    _file: File,
}
impl Drop for DirectoryLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct LimitedWriter<W> {
    inner: W,
    remaining: u64,
}
impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(io::Error::other("capture_byte_limit"));
        }
        let count = self.inner.write(bytes)?;
        self.remaining -= count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn write_snapshot(directory: &Path, snapshot: Snapshot) -> Result<bool> {
    validate_directory(directory)?;
    let lock_path = directory.join(LOCK_FILE);
    let lock = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&lock_path)
    {
        Ok(file) => DirectoryLock {
            path: lock_path,
            _file: file,
        },
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    validate_directory(directory)?;
    let mut count = 0usize;
    let mut bytes = 0u64;
    // Count all preexisting regular files, not just names from this version.
    // No existing file is overwritten, pruned or followed through a symlink.
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name() == LOCK_FILE {
            continue;
        }
        let m = std::fs::symlink_metadata(entry.path())?;
        if m.is_file() {
            count += 1;
            bytes = bytes.saturating_add(m.len());
        }
    }
    if count >= MAX_FILES || bytes >= MAX_DIRECTORY_BYTES {
        return Ok(false);
    }
    let limit = (MAX_DIRECTORY_BYTES - bytes).min(MAX_FILE_BYTES);
    let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = directory.join(format!("failure-{}-{epoch}.json", std::process::id()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    let outcome = (|| -> Result<()> {
        // Buffer first: serde byte arrays would otherwise perform millions of
        // tiny writes. The limit counts serialized bytes, not just media bytes.
        let mut writer = LimitedWriter {
            inner: BufWriter::with_capacity(64 * 1024, &file),
            remaining: limit,
        };
        serde_json::to_writer(&mut writer, &snapshot)?;
        writer.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    if outcome.is_err() {
        let _ = std::fs::remove_file(&path);
    }
    outcome?;
    drop(lock);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct PrivateDir(PathBuf);
    impl PrivateDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "motorola-capture-test-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for PrivateDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn snapshot() -> Snapshot {
        Snapshot {
            mode: 1,
            key: [0x11; 16],
            iv: [0x22; 32],
            packets: VecDeque::new(),
        }
    }
    fn files(path: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect()
    }

    #[test]
    fn rejects_public_directory_and_symlink() {
        let dir = PrivateDir::new();
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(FailureCapture::new(&dir.0).is_err());
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = PrivateDir::new();
        let link = parent.0.join("link");
        std::os::unix::fs::symlink(&dir.0, &link).unwrap();
        assert!(FailureCapture::new(&link).is_err());
        assert!(write_snapshot(&link, snapshot()).is_err());
    }

    #[test]
    fn writes_owner_only_file_with_no_lock_left() {
        let dir = PrivateDir::new();
        assert!(write_snapshot(&dir.0, snapshot()).unwrap());
        let paths = files(&dir.0);
        assert_eq!(paths.len(), 1);
        assert_eq!(
            std::fs::metadata(&paths[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let data: serde_json::Value =
            serde_json::from_reader(File::open(&paths[0]).unwrap()).unwrap();
        assert_eq!(data["mode"], 1);
        assert_eq!(data["key"].as_array().unwrap().len(), 16);
    }

    #[test]
    fn file_count_cap_survives_fresh_instances_and_preexisting_files() {
        let dir = PrivateDir::new();
        std::fs::write(dir.0.join("older-version.capture"), b"synthetic").unwrap();
        for _ in 0..3 {
            assert!(write_snapshot(&dir.0, snapshot()).unwrap());
        }
        assert!(!write_snapshot(&dir.0, snapshot()).unwrap());
        assert_eq!(files(&dir.0).len(), 4);
    }

    #[test]
    fn disk_byte_cap_and_partial_cleanup() {
        let dir = PrivateDir::new();
        let old = File::create(dir.0.join("older.capture")).unwrap();
        old.set_len(MAX_DIRECTORY_BYTES).unwrap();
        assert!(!write_snapshot(&dir.0, snapshot()).unwrap());
        old.set_len(MAX_DIRECTORY_BYTES - 1).unwrap();
        assert!(write_snapshot(&dir.0, snapshot()).is_err());
        assert_eq!(files(&dir.0).len(), 1);
    }

    #[test]
    fn existing_lock_including_symlink_fails_closed() {
        let dir = PrivateDir::new();
        let target = dir.0.join("target");
        std::fs::write(&target, b"untouched").unwrap();
        std::os::unix::fs::symlink(&target, dir.0.join(LOCK_FILE)).unwrap();
        assert!(!write_snapshot(&dir.0, snapshot()).unwrap());
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
    }

    #[test]
    fn ring_evicts_oldest_by_count_and_bytes_and_rejects_oversize() {
        let dir = PrivateDir::new();
        let mut capture = FailureCapture::new(&dir.0).unwrap();
        for sequence in 0..40 {
            capture.remember(1, sequence, [0; 16], &[1], &[2]);
        }
        assert_eq!(capture.packets.len(), 32);
        assert_eq!(capture.packets.front().unwrap().sequence, 8);
        let big = vec![3; MAX_PACKET_BYTES];
        capture.remember(1, 40, [0; 16], &big, &[]);
        capture.remember(1, 41, [0; 16], &big, &[]);
        assert_eq!(capture.bytes, MAX_RING_BYTES);
        assert_eq!(capture.packets.len(), 2);
        capture.remember(1, 42, [0; 16], &big, &[1]);
        assert_eq!(capture.packets.len(), 2);
        assert_eq!(capture.packets.back().unwrap().sequence, 41);
    }

    #[tokio::test]
    async fn async_dump_moves_ring_and_limits_attempts() {
        let dir = PrivateDir::new();
        let mut capture = FailureCapture::new(&dir.0).unwrap();
        let mut request = Vec::new();
        for value in [23i64, 5, 8] {
            request.extend_from_slice(&value.to_le_bytes());
        }
        let (_, cipher) = crate::crypto::respond_key_exchange(
            &request,
            crate::crypto::CipherMode::Aes128Cbc,
            1024,
        )
        .unwrap();
        capture.remember(1, 0, [0; 16], &[1, 2], &[3, 4]);
        assert!(capture.dump(&cipher).await.unwrap());
        assert!(capture.packets.is_empty());
        assert_eq!(capture.bytes, 0);
        assert!(capture.dump(&cipher).await.unwrap());
        assert!(!capture.dump(&cipher).await.unwrap());
        assert_eq!(files(&dir.0).len(), 2);
    }
}

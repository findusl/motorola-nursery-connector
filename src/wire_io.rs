// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded frame I/O. A dedicated task must own each read cursor; cancellation
//! requires discarding the connection because read_exact/write_all may be partial.
use crate::{
    frame::{apply_mask, Frame},
    CodecError,
};
use anyhow::{bail, Result};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{timeout, Duration},
};
pub const MAX_FRAME: usize = 256 * 1024;
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame> {
    let mut h = [0; 8];
    r.read_exact(&mut h).await?;
    let command = i32::from_le_bytes(h[..4].try_into().unwrap());
    let n = i32::from_le_bytes(h[4..].try_into().unwrap());
    if n < 0 {
        return Err(CodecError::InvalidLength.into());
    }
    if n as usize > MAX_FRAME {
        bail!("frame_limit");
    }
    let mut payload = vec![0; n as usize];
    r.read_exact(&mut payload).await?;
    apply_mask(&mut payload);
    Ok(Frame { command, payload })
}
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> Result<()> {
    let b = f.encode(MAX_FRAME)?;
    timeout(Duration::from_secs(10), w.write_all(&b))
        .await
        .map_err(|_| anyhow::anyhow!("write_timeout"))??;
    Ok(())
}

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, copy_bidirectional_with_sizes};

/// Match Go `common/pool.RelayBufferSize` (standard build): 32 KiB per direction.
const RELAY_BUFFER_SIZE: usize = 32 * 1024;

/// Relays bytes in both directions until both streams reach EOF.
///
/// Uses 32 KiB buffers per direction (Go relay parity). Tokio's default
/// `copy_bidirectional` uses 8 KiB and generates ~4× more writes into
/// framed transports such as AnyTLS.
///
/// # Errors
///
/// Returns the first stream I/O error reported by Tokio's bidirectional copy.
pub async fn relay<A, B>(left: &mut A, right: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    copy_bidirectional_with_sizes(left, right, RELAY_BUFFER_SIZE, RELAY_BUFFER_SIZE).await
}

/// Like [`relay`], but invokes `peel_right` after each successful right-side
/// read/write so replaceable protocol wrappers (VLESS) can unwrap to the bare
/// carrier mid-session — matching Go `bufio.Copy` + `WriterReplaceable`.
///
/// # Errors
///
/// Returns the first stream I/O error.
pub async fn relay_with_right_peel<A, B, F>(
    left: &mut A,
    right: &mut B,
    mut peel_right: F,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(&mut B),
{
    let mut left_buf = vec![0_u8; RELAY_BUFFER_SIZE];
    let mut right_buf = vec![0_u8; RELAY_BUFFER_SIZE];
    let mut uploaded = 0_u64;
    let mut downloaded = 0_u64;
    let mut left_done = false;
    let mut right_done = false;

    peel_right(right);

    loop {
        if left_done && right_done {
            return Ok((uploaded, downloaded));
        }

        tokio::select! {
            biased;
            result = left.read(&mut left_buf), if !left_done => {
                match result? {
                    0 => {
                        left_done = true;
                        let _ = right.shutdown().await;
                        peel_right(right);
                    }
                    n => {
                        right.write_all(&left_buf[..n]).await?;
                        uploaded += n as u64;
                        peel_right(right);
                    }
                }
            }
            result = right.read(&mut right_buf), if !right_done => {
                match result? {
                    0 => {
                        right_done = true;
                        let _ = left.shutdown().await;
                        peel_right(right);
                    }
                    n => {
                        left.write_all(&right_buf[..n]).await?;
                        downloaded += n as u64;
                        peel_right(right);
                    }
                }
            }
        }
    }
}

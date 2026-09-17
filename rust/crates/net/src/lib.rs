use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, copy_bidirectional_with_sizes};

/// Match Go `common/pool.RelayBufferSize` (standard build): 32 KiB per direction.
pub const RELAY_BUFFER_SIZE: usize = 32 * 1024;

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
/// Handshake traffic uses [`RELAY_BUFFER_SIZE`] (32 KiB). Once `peel_right`
/// returns `true`, the remainder switches to Tokio's sized bidirectional copy
/// (same fast path as Trojan after `WriteHeader`).
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
    F: FnMut(&mut B) -> bool,
{
    let mut left_buf = vec![0_u8; RELAY_BUFFER_SIZE];
    let mut right_buf = vec![0_u8; RELAY_BUFFER_SIZE];
    let mut uploaded = 0_u64;
    let mut downloaded = 0_u64;

    if peel_right(right) {
        return copy_bidirectional_with_sizes(left, right, RELAY_BUFFER_SIZE, RELAY_BUFFER_SIZE)
            .await;
    }

    loop {
        tokio::select! {
            biased;
            result = left.read(&mut left_buf) => {
                match result? {
                    0 => {
                        let _ = right.shutdown().await;
                        // Left finished before peel; drain right→left at 32 KiB.
                        loop {
                            match right.read(&mut right_buf).await? {
                                0 => {
                                    let _ = left.shutdown().await;
                                    let _ = peel_right(right);
                                    return Ok((uploaded, downloaded));
                                }
                                n => {
                                    left.write_all(&right_buf[..n]).await?;
                                    downloaded += n as u64;
                                    if peel_right(right) {
                                        let (u, d) = copy_bidirectional_with_sizes(
                                            left,
                                            right,
                                            RELAY_BUFFER_SIZE,
                                            RELAY_BUFFER_SIZE,
                                        )
                                        .await?;
                                        return Ok((uploaded + u, downloaded + d));
                                    }
                                }
                            }
                        }
                    }
                    n => {
                        right.write_all(&left_buf[..n]).await?;
                        uploaded += n as u64;
                        if peel_right(right) {
                            let (u, d) = copy_bidirectional_with_sizes(
                                left,
                                right,
                                RELAY_BUFFER_SIZE,
                                RELAY_BUFFER_SIZE,
                            )
                            .await?;
                            return Ok((uploaded + u, downloaded + d));
                        }
                    }
                }
            }
            result = right.read(&mut right_buf) => {
                match result? {
                    0 => {
                        let _ = left.shutdown().await;
                        loop {
                            match left.read(&mut left_buf).await? {
                                0 => {
                                    let _ = right.shutdown().await;
                                    let _ = peel_right(right);
                                    return Ok((uploaded, downloaded));
                                }
                                n => {
                                    right.write_all(&left_buf[..n]).await?;
                                    uploaded += n as u64;
                                    if peel_right(right) {
                                        let (u, d) = copy_bidirectional_with_sizes(
                                            left,
                                            right,
                                            RELAY_BUFFER_SIZE,
                                            RELAY_BUFFER_SIZE,
                                        )
                                        .await?;
                                        return Ok((uploaded + u, downloaded + d));
                                    }
                                }
                            }
                        }
                    }
                    n => {
                        left.write_all(&right_buf[..n]).await?;
                        downloaded += n as u64;
                        if peel_right(right) {
                            let (u, d) = copy_bidirectional_with_sizes(
                                left,
                                right,
                                RELAY_BUFFER_SIZE,
                                RELAY_BUFFER_SIZE,
                            )
                            .await?;
                            return Ok((uploaded + u, downloaded + d));
                        }
                    }
                }
            }
        }
    }
}

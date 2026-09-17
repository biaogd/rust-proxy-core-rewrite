use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional_with_sizes};

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

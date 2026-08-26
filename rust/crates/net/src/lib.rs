use tokio::io::{AsyncRead, AsyncWrite};

/// Relays bytes in both directions until both streams reach EOF.
///
/// # Errors
///
/// Returns the first stream I/O error reported by Tokio's bidirectional copy.
pub async fn relay<A, B>(left: &mut A, right: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(left, right).await
}

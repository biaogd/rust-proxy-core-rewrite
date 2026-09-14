use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::aead::SnellStream;

const POOL_SIZE: usize = 10;
const POOL_AGE: Duration = Duration::from_secs(15);

/// Idle `ConnectV2` sessions. Size 10, age 15s (Go `pool.WithSize` / `WithAge`).
pub struct SnellSessionPool<S> {
    idle: Mutex<VecDeque<(Instant, SnellStream<S>)>>,
}

impl<S> std::fmt::Debug for SnellSessionPool<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let idle = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f.debug_struct("SnellSessionPool")
            .field("idle", &idle.len())
            .finish()
    }
}

impl<S> Default for SnellSessionPool<S> {
    fn default() -> Self {
        Self {
            idle: Mutex::new(VecDeque::new()),
        }
    }
}

impl<S> SnellSessionPool<S> {
    /// Empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pops the oldest non-expired idle session.
    pub fn take(&self) -> Option<SnellStream<S>> {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        while let Some((created, stream)) = idle.pop_front() {
            if now.saturating_duration_since(created) > POOL_AGE {
                drop(stream);
                continue;
            }
            return Some(stream);
        }
        None
    }

    /// Returns a session after a successful half-close. Evicts expired/oldest.
    pub fn put(&self, stream: SnellStream<S>) {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        while idle
            .front()
            .is_some_and(|(created, _)| now.saturating_duration_since(*created) > POOL_AGE)
        {
            drop(idle.pop_front());
        }
        if idle.len() >= POOL_SIZE {
            drop(idle.pop_front());
        }
        idle.push_back((now, stream));
    }
}

/// TCP stream that returns to [`SnellSessionPool`] after a reusable half-close.
pub struct PooledSnellStream<S> {
    inner: Option<SnellStream<S>>,
    pool: Arc<SnellSessionPool<S>>,
}

impl<S> PooledSnellStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Marks the session reusable (zero-chunk shutdown, no inner TCP close).
    #[must_use]
    pub fn new(mut stream: SnellStream<S>, pool: Arc<SnellSessionPool<S>>) -> Self {
        stream.set_hold_inner_shutdown(true);
        Self {
            inner: Some(stream),
            pool,
        }
    }
}

impl<S> Drop for PooledSnellStream<S> {
    fn drop(&mut self) {
        if let Some(mut stream) = self.inner.take()
            && stream.can_return_to_pool()
        {
            stream.reset_for_reuse();
            self.pool.put(stream);
        }
    }
}

impl<S> AsyncRead for PooledSnellStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(Err(std::io::Error::other("Snell pooled stream is empty")));
        };
        Pin::new(inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PooledSnellStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(Err(std::io::Error::other("Snell pooled stream is empty")));
        };
        Pin::new(inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(Err(std::io::Error::other("Snell pooled stream is empty")));
        };
        Pin::new(inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(Err(std::io::Error::other("Snell pooled stream is empty")));
        };
        Pin::new(inner).poll_shutdown(cx)
    }
}

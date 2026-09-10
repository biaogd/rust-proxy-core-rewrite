//! Go `openStreams` accounting: delayed decrement after TCP/UDP close.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Matches `constant.DefaultTCPTimeout` / `DefaultUDPTimeout` (5s).
pub(crate) const STREAM_RELEASE_DELAY: Duration = Duration::from_secs(5);

/// One reserved TUIC stream/association slot.
pub(crate) struct StreamLease {
    open_streams: Arc<AtomicU64>,
    delayed: bool,
}

impl StreamLease {
    pub(crate) fn new(open_streams: Arc<AtomicU64>) -> Self {
        Self {
            open_streams,
            delayed: true,
        }
    }

    /// Immediate decrement (open failed). Prevents the delayed Drop timer.
    pub(crate) fn release_now(mut self) {
        self.open_streams.fetch_sub(1, Ordering::AcqRel);
        self.delayed = false;
    }
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        if !self.delayed {
            return;
        }
        let open_streams = Arc::clone(&self.open_streams);
        tokio::spawn(async move {
            tokio::time::sleep(STREAM_RELEASE_DELAY).await;
            open_streams.fetch_sub(1, Ordering::AcqRel);
        });
    }
}

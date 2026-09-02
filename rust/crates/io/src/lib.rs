//! Minimal asynchronous I/O types shared across architectural layers.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use tokio::io::{AsyncRead, AsyncWrite};

const VISION_READ_DIRECT: u8 = 1;
const VISION_WRITE_DIRECT: u8 = 2;

/// Shared control plane for promoting an outer TLS carrier to Vision's raw-TCP mode.
///
/// Read and write promotion are independent because each peer observes the nested TLS
/// application-data boundary at a different time.
#[derive(Clone, Debug, Default)]
pub struct VisionDirectControl {
    state: Arc<AtomicU8>,
}

impl VisionDirectControl {
    /// Requests that future reads bypass the outer TLS record layer.
    pub fn request_read_direct(&self) {
        self.state.fetch_or(VISION_READ_DIRECT, Ordering::Release);
    }

    /// Requests that future writes bypass the outer TLS record layer.
    pub fn request_write_direct(&self) {
        self.state.fetch_or(VISION_WRITE_DIRECT, Ordering::Release);
    }

    /// Returns whether the read direction has entered raw-TCP mode.
    #[must_use]
    pub fn read_is_direct(&self) -> bool {
        self.state.load(Ordering::Acquire) & VISION_READ_DIRECT != 0
    }

    /// Returns whether the write direction has entered raw-TCP mode.
    #[must_use]
    pub fn write_is_direct(&self) -> bool {
        self.state.load(Ordering::Acquire) & VISION_WRITE_DIRECT != 0
    }

    /// Returns whether either direction has entered raw-TCP mode.
    #[must_use]
    pub fn any_is_direct(&self) -> bool {
        self.state.load(Ordering::Acquire) != 0
    }
}

/// An owned asynchronous byte stream accepted by protocol and transport layers.
pub trait DuplexStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> DuplexStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Type-erased duplex stream shared by inbound, outbound and protocol crates.
pub type BoxedStream = Box<dyn DuplexStream>;

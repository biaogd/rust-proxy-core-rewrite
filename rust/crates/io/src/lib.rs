//! Minimal asynchronous I/O types shared across architectural layers.

use tokio::io::{AsyncRead, AsyncWrite};

/// An owned asynchronous byte stream accepted by protocol and transport layers.
pub trait DuplexStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> DuplexStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Type-erased duplex stream shared by inbound, outbound and protocol crates.
pub type BoxedStream = Box<dyn DuplexStream>;

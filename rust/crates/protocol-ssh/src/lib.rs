//! SSH outbound client (Phase 6J-A): password/public-key auth, optional
//! host-key verify, and reused `direct-tcpip` multiplexing.
//!
//! This is not an SSH inbound. UDP, `dialer-proxy`, keepalive knobs beyond
//! the transport socket, and host-key-algorithm preference application stay
//! out of this slice.

mod authority;
mod client;

pub use authority::{AuthorityOptions, spawn_authority};
pub use client::{Client, ClientOptions};

use thiserror::Error;

/// Protocol / dial errors for SSH outbound.
#[derive(Debug, Error)]
pub enum SshProtocolError {
    /// Underlying I/O or socket failure.
    #[error("SSH I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Authentication, host-key, or framing failure.
    #[error("SSH protocol failed: {0}")]
    Protocol(String),
}

impl From<russh::Error> for SshProtocolError {
    fn from(error: russh::Error) -> Self {
        Self::Protocol(error.to_string())
    }
}

impl From<russh::keys::Error> for SshProtocolError {
    fn from(error: russh::keys::Error) -> Self {
        Self::Protocol(error.to_string())
    }
}

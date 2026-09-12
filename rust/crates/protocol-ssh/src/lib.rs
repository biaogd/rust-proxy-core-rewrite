//! SSH outbound client (Phase 6J-A/B): password/public-key auth, optional
//! host-key verify, applied `host-key-algorithms`, transport TCP keepalive,
//! reused `direct-tcpip` multiplexing, and reconnect after a dead session.
//!
//! This is not an SSH inbound. UDP, `dialer-proxy`, and SSH-protocol keepalive
//! identity with Go stay out of this slice.

mod authority;
mod client;

pub use authority::{AuthorityOptions, TestAuthority, spawn_authority};
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

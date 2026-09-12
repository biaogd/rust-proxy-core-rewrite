//! Snell outbound client (Phase 7E-A/B/C/D): versions 1–3 TCP, v3 UDP, Argon2id
//! KDF, Shadowsocks-style AEAD framing, simple-obfs HTTP/TLS on the test
//! authority, and v2 `ConnectV2` session reuse. This is not a Snell inbound.
//!
//! v4/v5 and remaining `obfs-opts` stay out of this slice.

mod aead;
mod authority;
mod client;
mod header;
mod packet;
mod pool;

pub use aead::SnellStream;
pub use authority::{Authority, AuthorityObfs, AuthorityOptions, spawn_authority};
pub use client::{
    ClientOptions, SnellUdpAssociation, associate_udp, connect_tcp, open_tcp, write_connect,
};
pub use pool::{PooledSnellStream, SnellSessionPool};

use thiserror::Error;

/// Protocol / dial errors for Snell outbound.
#[derive(Debug, Error)]
pub enum SnellProtocolError {
    /// Underlying I/O or socket failure.
    #[error("Snell I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Authentication, command, or framing failure.
    #[error("Snell protocol failed: {0}")]
    Protocol(String),
}

/// Clash outbound default when `version` is omitted (matches Go).
pub const DEFAULT_VERSION: u8 = 1;

//! Snell outbound client (Phase 7E-A): versions 1–3 TCP, Argon2id KDF, and
//! Shadowsocks-style AEAD framing. This is not a Snell inbound.
//!
//! v4/v5, UDP, `reuse` pooling, and `obfs-opts` stay out of this slice.

mod aead;
mod authority;
mod client;
mod header;

pub use aead::SnellStream;
pub use authority::{Authority, AuthorityOptions, spawn_authority};
pub use client::{ClientOptions, connect_tcp};

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

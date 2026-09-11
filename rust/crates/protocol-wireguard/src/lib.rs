//! Userspace `WireGuard` outbound (Phase 6I).
//!
//! Library choice, recorded before the implementation:
//!
//! - **Protocol / crypto:** [`defguard_boringtun`] (`Tunn`) owns `Noise_IK`, ChaCha20-Poly1305,
//!   cookies and rekey. This crate does not implement `WireGuard` cryptography.
//!   `defguard_boringtun` is the maintained `BoringTun` fork (BSD-3-Clause) compatible
//!   with workspace `x25519-dalek` 2.x; crates.io `boringtun` 0.6 pins dalek 2.0.0-rc.3.
//! - **TCP/IP:** [`smoltcp`] 0.12 with `Medium::Ip` provides the **outbound**
//!   userspace stack (`TcpSocket::connect`). Packets never enter an OS TUN.
//! - **Independence from Phase 8:** `rewrite-tun` / `tun-rs` / kernel `WireGuard`
//!   UAPI are not used. Mixed/SOCKS → `WireGuard` therefore does not need
//!   administrator privileges.
//! - **`AmneziaWG`** is rejected at config parse until a later slice.
//!
//! 6I-B is single-peer TCP+UDP with optional inner IPv6 and tunnel DNS
//! (`remote-dns-resolve`). Multi-peer and `AmneziaWG` remain rejected.

mod client;
mod keys;
mod stack;
mod tunnel;

pub use client::{Client, ClientOptions};
pub use keys::{decode_key, encode_key};
pub use stack::{WgTcpStream, WgUdpSocket};
pub use tunnel::{NoiseTunnel, TunnelAction};

use thiserror::Error;

/// Protocol / tunnel / stack errors for `WireGuard` outbound.
#[derive(Debug, Error)]
pub enum WireGuardProtocolError {
    /// UDP bind, send, or TCP stack I/O.
    #[error("WireGuard I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Key parse / handshake / boringtun failures.
    #[error("WireGuard protocol failed: {0}")]
    Protocol(String),
    /// No inner address for this destination family.
    #[error("WireGuard has no inner address for this family")]
    UnsupportedFamily,
}

impl WireGuardProtocolError {
    pub(crate) fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }
}

/// Clash / Go default inner MTU when `mtu` is omitted or zero.
pub const DEFAULT_MTU: u16 = 1408;

/// Handshake / first-dial bound used by 6I-A tests and mixed CONNECT.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

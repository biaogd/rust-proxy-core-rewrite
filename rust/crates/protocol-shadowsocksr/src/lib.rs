//! `ShadowsocksR` outbound protocol (SSR-A/B/C: origin, `auth_aes128_*`, `auth_sha1_v4`,
//! `auth_chain_*`, plus plain/http/`tls1.2_ticket`/`random_head` camouflage).
//!
//! Layering (innermost → network):
//! address+data → protocol encode → stream cipher → obfs → TCP.
//!
//! AEAD / SIP022 / SS2022 are not SSR and are rejected. Unimplemented
//! protocol/obfs/cipher combinations fail loudly (no silent downgrade).
//!
//! `tls1.2_ticket_*` is TLS **camouflage only** (not real TLS; no rustls).

#![allow(clippy::doc_markdown)]

mod cipher;
mod client;
mod crypto_util;
mod obfs;
mod protocol;
mod udp;

pub use client::{SsrClientOptions, connect_tcp_on_stream};
pub use udp::{SsrUdpAssociation, associate_udp};

use thiserror::Error;

/// Protocol / dial errors for `ShadowsocksR`.
#[derive(Debug, Error)]
pub enum ShadowsocksRProtocolError {
    /// Unsupported or unimplemented SSR cipher.
    #[error("unsupported ShadowsocksR cipher: {0}")]
    Cipher(String),
    /// Unsupported or unimplemented SSR protocol plugin.
    #[error("unsupported ShadowsocksR protocol: {0}")]
    ProtocolPlugin(String),
    /// Unsupported or unimplemented SSR obfs plugin.
    #[error("unsupported ShadowsocksR obfs: {0}")]
    Obfs(String),
    /// Invalid configuration (params, AEAD/SS2022, etc.).
    #[error("invalid ShadowsocksR configuration: {0}")]
    Configuration(String),
    /// Underlying I/O failure.
    #[error("ShadowsocksR I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Framing / protocol failure after dial.
    #[error("ShadowsocksR protocol failed: {0}")]
    Protocol(String),
}

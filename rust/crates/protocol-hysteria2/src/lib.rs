//! Hysteria2 client and server protocol: HTTP/3 auth + custom QUIC TCP streams
//! (HY2-A), UDP datagrams, Salamander/port-hop, and Brutal congestion (HY2-B).
//!
//! Congestion: stock Quinn `BbrConfig` is used when `up`/`down` are unset (Go
//! default). Brutal is available when upload bandwidth is configured.
//!
//! Server Accept (IN-F): [`server`] owns wire auth/TCP/UDP framing; runtime owns
//! listen/route.

mod auth;
mod bps;
mod client;
mod congestion;
mod salamander;
mod server;
mod socket;
mod tcp;
mod udp;
mod varint;

pub use bps::{parse_bps, parse_hop_interval, parse_ports};
pub use client::{Client, ClientOptions, Session, TlsOptions};
pub use server::{
    Hysteria2ServerStream, ServerAuthOptions, ServerAuthResult, ServerEndpointOptions,
    accept_tcp_request, auth_password_from_headers, authenticate_incoming, bind_server_endpoint,
    encode_tcp_request, encode_tcp_response, encode_tcp_response_ok, is_auth_request,
    load_pem_or_path, lookup_user, parse_destination_authority, parse_tcp_request,
    password_user_table,
};
pub use tcp::Hysteria2Stream;
pub use udp::{
    Defragger, MAX_DATAGRAM_FRAME_SIZE, MAX_UDP_SIZE, UdpMessage, UdpSession, frag_udp_message,
};

use thiserror::Error;

/// Protocol / dial errors for Hysteria2.
#[derive(Debug, Error)]
pub enum Hysteria2ProtocolError {
    /// Underlying I/O or QUIC transport failure.
    #[error("Hysteria2 I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Quinn connect / config failures.
    #[error("Hysteria2 QUIC failed: {0}")]
    Quinn(String),
    /// Auth or framing protocol failure.
    #[error("Hysteria2 protocol failed: {0}")]
    Protocol(String),
}

impl From<quinn::ConnectError> for Hysteria2ProtocolError {
    fn from(error: quinn::ConnectError) -> Self {
        Self::Quinn(error.to_string())
    }
}

impl From<quinn::ConnectionError> for Hysteria2ProtocolError {
    fn from(error: quinn::ConnectionError) -> Self {
        Self::Quinn(error.to_string())
    }
}

/// Matches Go / Hysteria docs: HTTP/3 auth success status.
pub const STATUS_AUTH_OK: u16 = 233;

/// TCP request frame type (QUIC varint).
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// Idle / keepalive defaults matching `sing-quic` hysteria2.
pub const DEFAULT_MAX_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
pub const DEFAULT_KEEP_ALIVE_PERIOD: std::time::Duration = std::time::Duration::from_secs(10);
pub const DEFAULT_STREAM_RECEIVE_WINDOW: u64 = 8 * 1024 * 1024;
pub const DEFAULT_CONN_RECEIVE_WINDOW: u64 = DEFAULT_STREAM_RECEIVE_WINDOW * 5 / 2;

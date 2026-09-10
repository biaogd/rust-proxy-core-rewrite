//! TUIC v5 client protocol: TLS exporter authentication, TCP Connect, and
//! UDP relay over QUIC (Phase 6H-A/B). v4, 0-RTT, inbound and ECH remain
//! out of scope.

mod client;
mod lease;
mod protocol;
mod stream;
mod tls;
mod udp;

pub use client::{Client, ClientOptions, CongestionController, TlsOptions};
pub use protocol::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_AUTHENTICATE, CMD_CONNECT, CMD_DISSOCIATE,
    CMD_HEARTBEAT, CMD_PACKET, MAX_FRAG_SIZE, PACKET_OVERHEAD_GO, Packet, VERSION,
    compute_max_udp_relay_packet_size, decode_address, decode_packet, encode_authenticate,
    encode_connect, encode_dissociate, encode_heartbeat, encode_packet,
};
pub use stream::TuicStream;
pub use udp::{UdpRelayMode, UdpSession};

use thiserror::Error;

/// Protocol / dial errors for TUIC v5.
#[derive(Debug, Error)]
pub enum TuicProtocolError {
    /// QUIC datagram failure, preserved for payload-size retry.
    #[error("TUIC datagram failed: {0}")]
    Datagram(#[from] quinn::SendDatagramError),
    /// Underlying I/O or QUIC transport failure.
    #[error("TUIC I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Quinn connect / config failures.
    #[error("TUIC QUIC failed: {0}")]
    Quinn(String),
    /// Auth or framing protocol failure.
    #[error("TUIC protocol failed: {0}")]
    Protocol(String),
}

impl From<quinn::ConnectError> for TuicProtocolError {
    fn from(error: quinn::ConnectError) -> Self {
        Self::Quinn(error.to_string())
    }
}

impl From<quinn::ConnectionError> for TuicProtocolError {
    fn from(error: quinn::ConnectionError) -> Self {
        Self::Quinn(error.to_string())
    }
}

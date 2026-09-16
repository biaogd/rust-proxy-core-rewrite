//! TUIC v5 client and server protocol: TLS exporter authentication, TCP
//! Connect, and UDP relay over QUIC (Phase 6H outbound + IN-F inbound).
//! v4, 0-RTT, and ECH remain out of scope.

mod client;
mod lease;
mod protocol;
mod server;
mod stream;
mod tls;
mod udp;

pub use client::{Client, ClientOptions, CongestionController, TlsOptions};
pub use protocol::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_AUTHENTICATE, CMD_CONNECT, CMD_DISSOCIATE,
    CMD_HEARTBEAT, CMD_PACKET, ERR_AUTHENTICATION_FAILED, ERR_AUTHENTICATION_TIMEOUT,
    ERR_BAD_COMMAND, ERR_PROTOCOL, MAX_FRAG_SIZE, PACKET_OVERHEAD_GO, Packet, VERSION,
    compute_max_udp_relay_packet_size, decode_address, decode_authenticate, decode_connect,
    decode_dissociate, decode_packet, encode_authenticate, encode_connect, encode_dissociate,
    encode_heartbeat, encode_packet,
};
pub use server::{
    ServerAuthResult, ServerEndpointOptions, TuicServerStream, accept_tcp_connect,
    authenticate_uni_stream, bind_server_endpoint, close_authentication_failed,
    close_authentication_timeout, compute_token, load_pem_or_path, users_table,
    verify_authenticate,
};
pub use stream::TuicStream;
pub use udp::{Defragger, UdpRelayMode, UdpSession};

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

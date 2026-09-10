//! TUIC v5 client protocol: TLS exporter authentication and TCP Connect
//! over QUIC streams (Phase 6H-A). UDP relay, v4, 0-RTT and inbound are
//! out of scope.

mod client;
mod protocol;
mod stream;
mod tls;

pub use client::{Client, ClientOptions, CongestionController, TlsOptions};
pub use protocol::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_AUTHENTICATE, CMD_CONNECT, VERSION, decode_address,
    encode_authenticate, encode_connect,
};
pub use stream::TuicStream;

use thiserror::Error;

/// Protocol / dial errors for TUIC v5.
#[derive(Debug, Error)]
pub enum TuicProtocolError {
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

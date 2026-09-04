//! Trojan outbound adapter over an already established TLS carrier.

use rewrite_model::Destination;
use thiserror::Error;

use crate::BoxedOutboundStream;

#[derive(Debug, Error)]
pub enum TrojanProxyError {
    #[error(transparent)]
    Protocol(#[from] rewrite_protocol_trojan::TrojanProtocolError),
}

/// Starts a Trojan TCP request over an established carrier.
///
/// # Errors
///
/// Returns a protocol error when the destination cannot be encoded.
pub fn connect_trojan_on_stream(
    remote: BoxedOutboundStream,
    destination: &Destination,
    password: &str,
) -> Result<BoxedOutboundStream, TrojanProxyError> {
    rewrite_protocol_trojan::connect_trojan_on_stream(remote, destination, password)
        .map_err(Into::into)
}

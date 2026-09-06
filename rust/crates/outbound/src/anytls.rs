//! `AnyTLS` outbound adapter over an already established TLS carrier.

use rewrite_model::Destination;
use thiserror::Error;

use crate::BoxedOutboundStream;

#[derive(Debug, Error)]
pub enum AnyTlsProxyError {
    #[error(transparent)]
    Protocol(#[from] rewrite_protocol_anytls::AnyTlsProtocolError),
}

/// Starts an `AnyTLS` TCP request over an established TLS carrier.
///
/// # Errors
///
/// Returns a protocol error when authentication, session setup or destination
/// encoding fails.
pub async fn connect_anytls_on_stream(
    remote: BoxedOutboundStream,
    destination: &Destination,
    password: &str,
    client_metadata: &str,
) -> Result<BoxedOutboundStream, AnyTlsProxyError> {
    let options = rewrite_protocol_anytls::AnyTlsConnectOptions {
        client_metadata,
        padding: None,
    };
    rewrite_protocol_anytls::connect_anytls_on_stream(remote, destination, password, &options)
        .await
        .map_err(Into::into)
}

use rewrite_model::Destination;
use thiserror::Error;

use crate::{BoxedOutboundStream, DirectError, DirectTcpOptions, connect_with_options};

#[derive(Debug, Error)]
pub enum SnellProxyError {
    #[error(transparent)]
    Direct(#[from] DirectError),
    #[error(transparent)]
    ProtocolCore(#[from] rewrite_protocol_snell::SnellProtocolError),
}

/// Opens the upstream TCP socket, then writes the Snell AEAD connect header.
///
/// # Errors
///
/// Returns when the server cannot be dialed or the Snell handshake cannot start.
pub async fn connect_snell_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    psk: &[u8],
    version: u8,
    options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, SnellProxyError> {
    let stream = connect_with_options(server, allow_ipv6, options).await?;
    let wrapped = rewrite_protocol_snell::connect_tcp(
        stream,
        destination,
        &rewrite_protocol_snell::ClientOptions {
            psk: psk.to_vec(),
            version,
        },
    )
    .await?;
    Ok(Box::new(wrapped))
}

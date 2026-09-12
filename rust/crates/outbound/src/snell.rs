use rewrite_config::SnellObfs;
use rewrite_model::Destination;
use thiserror::Error;

use crate::{
    BoxedOutboundStream, DirectError, DirectTcpOptions, HttpObfsClient, TlsObfsClient,
    connect_with_options,
};

pub use rewrite_protocol_snell::SnellUdpAssociation;

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
    obfs: Option<&SnellObfs>,
    options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, SnellProxyError> {
    let stream = apply_snell_obfs(
        Box::new(connect_with_options(server, allow_ipv6, options).await?),
        server,
        obfs,
    );
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

/// Opens the upstream TCP socket, then writes the Snell v3 UDP association header.
///
/// # Errors
///
/// Returns when the server cannot be dialed, the version is below 3, or the
/// association header cannot be written.
pub async fn associate_snell_udp_with_options(
    server: &Destination,
    allow_ipv6: bool,
    psk: &[u8],
    version: u8,
    obfs: Option<&SnellObfs>,
    options: DirectTcpOptions<'_>,
) -> Result<SnellUdpAssociation<BoxedOutboundStream>, SnellProxyError> {
    let stream = apply_snell_obfs(
        Box::new(connect_with_options(server, allow_ipv6, options).await?),
        server,
        obfs,
    );
    Ok(rewrite_protocol_snell::associate_udp(
        stream,
        &rewrite_protocol_snell::ClientOptions {
            psk: psk.to_vec(),
            version,
        },
    )
    .await?)
}

fn apply_snell_obfs(
    stream: BoxedOutboundStream,
    server: &Destination,
    obfs: Option<&SnellObfs>,
) -> BoxedOutboundStream {
    match obfs {
        None => stream,
        Some(SnellObfs::Http { host }) => {
            Box::new(HttpObfsClient::new(stream, host.clone(), server.port))
        }
        Some(SnellObfs::Tls { host }) => Box::new(TlsObfsClient::new(stream, host.clone())),
    }
}

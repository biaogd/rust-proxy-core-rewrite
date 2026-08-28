use std::sync::Arc;
use std::time::Duration;

use rewrite_model::Destination;
use thiserror::Error;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::BoxedOutboundStream;
use crate::direct::{DirectError, DirectTcpOptions, connect_with_options};
use crate::tls::{HttpProxyTls, client_config};

mod auth;
mod tcp;
mod udp;

pub use tcp::{connect_socks5, connect_socks5_with_options};
pub use udp::{Socks5UdpAssociation, associate_socks5_udp_with_options};

#[derive(Debug, Error)]
pub enum Socks5ProxyError {
    #[error(transparent)]
    Direct(#[from] DirectError),
    #[error(transparent)]
    Socks(#[from] fast_socks5::SocksError),
    #[error("SOCKS5 proxy rejected the offered authentication method")]
    AuthenticationRejected,
    #[error("SOCKS5 proxy selected an unsupported protocol version")]
    UnsupportedVersion,
    #[error("SOCKS5 proxy returned an invalid address: {0}")]
    InvalidAddress(String),
    #[error("SOCKS5 proxy handshake timed out")]
    HandshakeTimeout,
    #[error("SOCKS5 proxy TLS failed: {0}")]
    Tls(String),
}

async fn connect_control(
    server: &Destination,
    allow_ipv6: bool,
    tls: Option<HttpProxyTls<'_>>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
    options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, Socks5ProxyError> {
    let socket = connect_with_options(server, allow_ipv6, options).await?;
    if let Some(tls) = tls {
        let config =
            client_config(tls, clock).map_err(|error| Socks5ProxyError::Tls(error.to_string()))?;
        let server_name = ServerName::try_from(tls.server_name.to_owned())
            .map_err(|error| Socks5ProxyError::Tls(error.to_string()))?;
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            TlsConnector::from(Arc::new(config)).connect(server_name, socket),
        )
        .await
        .map_err(|_| Socks5ProxyError::HandshakeTimeout)?
        .map_err(|error| Socks5ProxyError::Tls(error.to_string()))?;
        Ok(Box::new(stream))
    } else {
        Ok(Box::new(socket))
    }
}

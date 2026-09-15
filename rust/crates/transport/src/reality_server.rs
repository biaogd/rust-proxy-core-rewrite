//! VLESS REALITY server Accept using shadow-rustls server APIs.

use std::sync::Arc;
use std::time::Duration;

use rewrite_io::BoxedStream;
use shadow_rustls::server::{RealityServerCertResolver, RealityServerConfig};
use shadow_rustls::ServerConfig;
use shadow_tokio_rustls::TlsAcceptor;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::tls::TlsClientError;

/// Cloneable REALITY TLS acceptor (shadow-tokio-rustls).
pub type RealityTlsAcceptor = TlsAcceptor;

/// Options for a REALITY TLS server Accept.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealityAcceptOptions {
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub server_names: Vec<String>,
    pub max_time_difference: Option<Duration>,
}

/// Build a reusable shadow-tokio-rustls acceptor for REALITY.
///
/// Authentication failure returns `None` from the cert resolver and aborts the
/// handshake (dest camouflage fallback is intentionally deferred).
///
/// # Errors
///
/// Returns [`TlsClientError::Configuration`] when the REALITY server config is invalid.
pub fn reality_acceptor(
    options: &RealityAcceptOptions,
) -> Result<TlsAcceptor, TlsClientError> {
    let mut config = RealityServerConfig::new(options.private_key);
    config = config
        .with_short_ids(options.short_ids.iter().copied())
        .map_err(|error| TlsClientError::Configuration(error.to_string()))?
        .with_server_names(options.server_names.iter().cloned())
        .with_max_time_diff(options.max_time_difference);
    let resolver = Arc::new(RealityServerCertResolver::new(config));
    let provider = Arc::new(shadow_rustls::crypto::aws_lc_rs::default_provider());
    let time_provider = Arc::new(shadow_rustls::time_provider::DefaultTimeProvider);
    let server = ServerConfig::builder_with_details(provider, time_provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| TlsClientError::Configuration(error.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    Ok(TlsAcceptor::from(Arc::new(server)))
}

/// Accept a REALITY TLS client over `stream`.
///
/// # Errors
///
/// Returns [`TlsClientError`] when the handshake fails or times out.
pub async fn accept_reality<S>(
    acceptor: &TlsAcceptor,
    stream: S,
) -> Result<BoxedStream, TlsClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::time::timeout(Duration::from_secs(15), acceptor.accept(stream))
        .await
        .map_err(|_| TlsClientError::Timeout)?
        .map(|tls| Box::new(tls) as BoxedStream)
        .map_err(|error| TlsClientError::Handshake(std::io::Error::other(error)))
}

use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use shadow_rustls::client::RealityConfig;
use shadow_rustls::pki_types::ServerName;
use shadow_rustls::{ClientConfig, RootCertStore};
use shadow_tokio_rustls::TlsConnector;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::tls::TlsClientError;

#[derive(Clone, Copy, Debug)]
pub struct RealityConnectOptions<'a> {
    pub server_name: &'a str,
    pub public_key: [u8; 32],
    pub short_id: &'a [u8],
    pub tls13_only: bool,
}

fn load_root_store() -> Result<RootCertStore, TlsClientError> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for certificate in native.certs {
        roots
            .add(certificate)
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
    }
    let embedded = rustls_pemfile::certs(&mut Cursor::new(include_bytes!(
        "../../../../component/ca/ca-certificates.crt"
    )))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
    for certificate in embedded {
        roots
            .add(certificate)
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
    }
    Ok(roots)
}

fn reality_client_config(options: RealityConnectOptions<'_>) -> Result<ClientConfig, TlsClientError> {
    let reality = RealityConfig::new(options.public_key, options.short_id.to_vec())
        .map_err(|error| TlsClientError::Configuration(error.to_string()))?
        .with_client_version([1, 8, 2]);
    let roots = load_root_store()?;
    let provider = Arc::new(shadow_rustls::crypto::aws_lc_rs::default_provider());
    let time_provider = Arc::new(shadow_rustls::time_provider::DefaultTimeProvider);
    let builder = if options.tls13_only {
        ClientConfig::builder_with_details(provider, time_provider)
            .with_protocol_versions(&[&shadow_rustls::version::TLS13])
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?
    } else {
        ClientConfig::builder_with_details(provider, time_provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?
    };
    Ok(builder
        .with_root_certificates(roots)
        .with_reality(reality)
        .with_no_client_auth())
}

/// Performs a VLESS REALITY client handshake over an established TCP stream.
///
/// # Errors
///
/// Returns [`TlsClientError`] when configuration or the handshake fails.
pub async fn connect_reality<S>(
    stream: S,
    options: RealityConnectOptions<'_>,
) -> Result<shadow_tokio_rustls::client::TlsStream<S>, TlsClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let server_name = ServerName::try_from(options.server_name.to_owned())
        .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
    let config = Arc::new(reality_client_config(options)?);
    let connector = TlsConnector::from(config);
    tokio::time::timeout(Duration::from_secs(15), connector.connect(server_name, stream))
        .await
        .map_err(|_| TlsClientError::Timeout)?
        .map_err(|error| TlsClientError::Handshake(std::io::Error::other(error)))
}

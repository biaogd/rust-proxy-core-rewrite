//! Hysteria2 outbound adapter (HY2-A: TCP over QUIC + HTTP/3 auth).

use rewrite_config::ProxyConfig;
use rewrite_model::Destination;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Hysteria2ProxyError {
    #[error(transparent)]
    Protocol(#[from] rewrite_protocol_hysteria2::Hysteria2ProtocolError),
    #[error("Hysteria2 dial failed: {0}")]
    Dial(String),
}

/// Long-lived outbound client matching Go `adapter/outbound.Hysteria2`.
#[derive(Clone)]
pub struct Hysteria2Client {
    inner: std::sync::Arc<rewrite_protocol_hysteria2::Client>,
}

impl std::fmt::Debug for Hysteria2Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hysteria2Client")
    }
}

impl Hysteria2Client {
    /// Builds a client from Clash proxy configuration and trusted roots.
    ///
    /// # Errors
    ///
    /// Returns when the proxy is missing Hysteria2 options.
    pub fn from_proxy(
        proxy: &ProxyConfig,
        custom_roots: &[String],
    ) -> Result<Self, Hysteria2ProxyError> {
        let options = client_options_from_proxy(proxy, custom_roots)?;
        Ok(Self {
            inner: std::sync::Arc::new(rewrite_protocol_hysteria2::Client::new(options)),
        })
    }

    /// Opens a proxied TCP stream to `destination`.
    ///
    /// # Errors
    ///
    /// Returns dial or protocol errors from the underlying client.
    pub async fn create_proxy(
        &self,
        destination: &Destination,
    ) -> Result<crate::BoxedOutboundStream, Hysteria2ProxyError> {
        self.inner.open_tcp(destination).await.map_err(Into::into)
    }

    pub async fn retire(&self) {
        self.inner.close().await;
    }
}

fn client_options_from_proxy(
    proxy: &ProxyConfig,
    custom_roots: &[String],
) -> Result<rewrite_protocol_hysteria2::ClientOptions, Hysteria2ProxyError> {
    let hysteria2 = proxy.hysteria2.as_ref().ok_or_else(|| {
        Hysteria2ProxyError::Dial("Hysteria2 proxy configuration is missing".to_owned())
    })?;
    let server_name = proxy
        .sni
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| proxy.server.clone());
    Ok(rewrite_protocol_hysteria2::ClientOptions {
        server: proxy.server.clone(),
        port: proxy.port,
        password: hysteria2.password.clone(),
        tls: rewrite_protocol_hysteria2::TlsOptions {
            server_name,
            skip_certificate_verification: proxy.skip_cert_verify,
            alpn: hysteria2.alpn.clone(),
            custom_roots: custom_roots.to_vec(),
        },
        disable_reuse: hysteria2.disable_reuse,
    })
}

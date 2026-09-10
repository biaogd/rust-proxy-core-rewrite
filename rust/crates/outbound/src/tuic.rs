//! TUIC v5 outbound adapter (6H-A: TCP over QUIC).

use std::time::Duration;

use rewrite_config::ProxyConfig;
use rewrite_model::Destination;
use rewrite_protocol_tuic::{Client, ClientOptions, CongestionController, TlsOptions};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum TuicProxyError {
    #[error(transparent)]
    Protocol(#[from] rewrite_protocol_tuic::TuicProtocolError),
    #[error("TUIC dial failed: {0}")]
    Dial(String),
}

/// Long-lived outbound client matching Go `adapter/outbound.Tuic` (v5).
#[derive(Clone)]
pub struct TuicClient {
    inner: std::sync::Arc<Client>,
}

impl std::fmt::Debug for TuicClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TuicClient")
    }
}

impl TuicClient {
    /// # Errors
    ///
    /// Returns when the proxy is missing TUIC v5 options or client construction fails.
    pub fn from_proxy(
        proxy: &ProxyConfig,
        custom_roots: &[String],
    ) -> Result<Self, TuicProxyError> {
        Self::from_proxy_with_dial_server(proxy, &proxy.server, custom_roots)
    }

    /// Dials `dial_server` (typically a PSN-resolved IP) while TLS SNI still
    /// uses `proxy.sni` / `proxy.server`.
    ///
    /// # Errors
    ///
    /// Returns when the proxy is missing TUIC options or client construction fails.
    pub fn from_proxy_with_dial_server(
        proxy: &ProxyConfig,
        dial_server: &str,
        custom_roots: &[String],
    ) -> Result<Self, TuicProxyError> {
        let mut options = client_options_from_proxy(proxy, custom_roots)?;
        dial_server.clone_into(&mut options.server);
        let inner = Client::new(options)?;
        Ok(Self {
            inner: std::sync::Arc::new(inner),
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
    ) -> Result<crate::BoxedOutboundStream, TuicProxyError> {
        self.inner.open_tcp(destination).await.map_err(Into::into)
    }

    pub async fn retire(&self) {
        self.inner.close().await;
    }
}

fn client_options_from_proxy(
    proxy: &ProxyConfig,
    custom_roots: &[String],
) -> Result<ClientOptions, TuicProxyError> {
    let tuic = proxy
        .tuic
        .as_ref()
        .ok_or_else(|| TuicProxyError::Dial("TUIC proxy configuration is missing".to_owned()))?;
    let server_name = if tuic.disable_sni {
        String::new()
    } else {
        proxy
            .sni
            .clone()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| proxy.server.clone())
    };
    let congestion = match tuic.congestion_controller.as_str() {
        "" | "cubic" => CongestionController::Cubic,
        "new_reno" => CongestionController::NewReno,
        "bbr" => CongestionController::Bbr,
        other => {
            return Err(TuicProxyError::Dial(format!(
                "unsupported TUIC congestion-controller: {other}"
            )));
        }
    };
    let request_timeout = if tuic.request_timeout_ms == 0 {
        Duration::from_secs(8)
    } else {
        Duration::from_millis(tuic.request_timeout_ms)
    };
    let heartbeat_interval = if tuic.heartbeat_interval_ms == 0 {
        Duration::from_secs(10)
    } else {
        Duration::from_millis(tuic.heartbeat_interval_ms)
    };
    let mut max_open_streams = if tuic.max_open_streams == 0 {
        100
    } else {
        tuic.max_open_streams
    };
    if max_open_streams == 100 {
        max_open_streams = 90;
    }
    max_open_streams = max_open_streams.max(1);
    let skip = proxy.skip_cert_verify || tuic.disable_sni;
    Ok(ClientOptions {
        server: proxy.server.clone(),
        port: proxy.port,
        uuid: Uuid::from_bytes(tuic.uuid),
        password: tuic.password.clone(),
        tls: TlsOptions {
            server_name,
            skip_certificate_verification: skip,
            alpn: tuic.alpn.clone(),
            custom_roots: custom_roots.to_vec(),
        },
        congestion,
        request_timeout,
        heartbeat_interval,
        max_open_streams,
        stream_receive_window: tuic.stream_receive_window,
        connection_receive_window: tuic.connection_receive_window,
    })
}

//! `WireGuard` userspace outbound adapter (6I-A TCP).

use rewrite_config::ProxyConfig;
use rewrite_model::Destination;
use rewrite_protocol_wireguard::{Client, ClientOptions, DEFAULT_MTU};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireGuardProxyError {
    #[error(transparent)]
    Protocol(#[from] rewrite_protocol_wireguard::WireGuardProtocolError),
    #[error("WireGuard dial failed: {0}")]
    Dial(String),
}

/// Long-lived outbound client matching Go `adapter/outbound.WireGuard` for 6I-A.
#[derive(Clone)]
pub struct WireGuardClient {
    inner: std::sync::Arc<Client>,
}

impl std::fmt::Debug for WireGuardClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WireGuardClient")
    }
}

impl WireGuardClient {
    /// Dials `dial_server` (typically a PSN-resolved IP). `bind_interface` /
    /// `routing_mark` apply to the outer UDP socket (TUN auto-route loop avoidance).
    ///
    /// # Errors
    ///
    /// Returns when the proxy is missing `WireGuard` options or UDP bind fails.
    pub async fn from_proxy_with_dial_server(
        proxy: &ProxyConfig,
        dial_server: &str,
        bind_interface: &str,
        routing_mark: i64,
    ) -> Result<Self, WireGuardProxyError> {
        let mut options = client_options_from_proxy(proxy)?;
        dial_server.clone_into(&mut options.server);
        bind_interface.clone_into(&mut options.bind_interface);
        options.routing_mark = routing_mark;
        let inner = Client::new(options).await?;
        Ok(Self {
            inner: std::sync::Arc::new(inner),
        })
    }

    /// Opens a proxied TCP stream to `destination`.
    ///
    /// # Errors
    ///
    /// Returns handshake, IPv4, or userspace-stack connect failures.
    pub async fn create_proxy(
        &self,
        destination: &Destination,
    ) -> Result<crate::BoxedOutboundStream, WireGuardProxyError> {
        self.inner.open_tcp(destination).await.map_err(Into::into)
    }

    #[allow(clippy::unused_async)] // matches TUIC/Hysteria2 retire shape
    pub async fn retire(&self) {
        self.inner.close().await;
    }
}

/// Pool key shared by mixed TCP dials and controller health checks.
///
/// A second `WireGuard` session to the same peer replaces the first on the
/// responder, so health must reuse the dataplane client.
#[must_use]
pub fn wireguard_adapter_identity(
    proxy: &ProxyConfig,
    dial_server: &str,
    bind_interface: &str,
    routing_mark: i64,
) -> String {
    format!(
        "{proxy:?}|dial={dial_server}|bind={}|mark={routing_mark}",
        rewrite_platform::resolve_outbound_bind_identity(bind_interface),
    )
}

fn client_options_from_proxy(proxy: &ProxyConfig) -> Result<ClientOptions, WireGuardProxyError> {
    let wireguard = proxy.wireguard.as_ref().ok_or_else(|| {
        WireGuardProxyError::Dial("WireGuard proxy configuration is missing".to_owned())
    })?;
    Ok(ClientOptions {
        server: proxy.server.clone(),
        port: proxy.port,
        private_key: wireguard.private_key,
        peer_public_key: wireguard.public_key,
        preshared_key: wireguard.preshared_key,
        local_addr: wireguard.local_addr,
        local_prefix_len: wireguard.local_prefix_len,
        mtu: if wireguard.mtu == 0 {
            DEFAULT_MTU
        } else {
            wireguard.mtu
        },
        persistent_keepalive: wireguard.persistent_keepalive,
        reserved: wireguard.reserved,
        bind_interface: String::new(),
        routing_mark: 0,
    })
}

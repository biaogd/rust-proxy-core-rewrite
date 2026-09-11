//! Hysteria2 outbound adapter (HY2-B: TCP + UDP over QUIC).

use std::net::IpAddr;
use std::time::Duration;

use rewrite_config::ProxyConfig;
use rewrite_model::{Destination, Host};
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
    /// Returns when the proxy is missing Hysteria2 options or client construction fails.
    pub fn from_proxy(
        proxy: &ProxyConfig,
        custom_roots: &[String],
    ) -> Result<Self, Hysteria2ProxyError> {
        Self::from_proxy_with_dial_server(proxy, &proxy.server, custom_roots, "", 0)
    }

    /// Like [`Self::from_proxy`], but dials `dial_server` (typically a
    /// PSN-resolved IP) while TLS SNI still uses `proxy.sni` / `proxy.server`.
    /// `bind_interface` / `routing_mark` apply to the QUIC UDP socket (TUN
    /// auto-route loop avoidance), including Salamander and port-hop paths.
    ///
    /// # Errors
    ///
    /// Returns when the proxy is missing Hysteria2 options or client construction fails.
    pub fn from_proxy_with_dial_server(
        proxy: &ProxyConfig,
        dial_server: &str,
        custom_roots: &[String],
        bind_interface: &str,
        routing_mark: i64,
    ) -> Result<Self, Hysteria2ProxyError> {
        let mut options = client_options_from_proxy(proxy, custom_roots)?;
        dial_server.clone_into(&mut options.server);
        bind_interface.clone_into(&mut options.bind_interface);
        options.routing_mark = routing_mark;
        let inner = rewrite_protocol_hysteria2::Client::new(options)?;
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
    ) -> Result<crate::BoxedOutboundStream, Hysteria2ProxyError> {
        self.inner.open_tcp(destination).await.map_err(Into::into)
    }

    pub async fn retire(&self) {
        self.inner.close().await;
    }
}

/// UDP association wrapping a Hysteria2 datagram session.
pub struct Hysteria2UdpAssociation {
    session: rewrite_protocol_hysteria2::UdpSession,
}

/// Opens a Hysteria2 UDP relay session (Go `ListenPacket`).
///
/// # Errors
///
/// Returns dial/auth failures or when the server disabled UDP.
pub async fn associate_hysteria2_udp(
    client: &Hysteria2Client,
) -> Result<Hysteria2UdpAssociation, Hysteria2ProxyError> {
    let session = client.inner.open_udp().await?;
    Ok(Hysteria2UdpAssociation { session })
}

impl Hysteria2UdpAssociation {
    /// Sends `payload` to `destination` through the Hysteria2 UDP relay.
    ///
    /// # Errors
    ///
    /// Returns when the QUIC datagram send fails.
    pub fn send(
        &self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), Hysteria2ProxyError> {
        self.session
            .send(payload, &destination.authority())
            .map_err(Into::into)
    }

    /// Receives the next datagram as `(destination, payload)`.
    ///
    /// # Errors
    ///
    /// Returns once the session or connection is closed, or when the remote
    /// address cannot be parsed as `host:port`.
    pub async fn recv(&mut self) -> Result<(Destination, Vec<u8>), Hysteria2ProxyError> {
        let (payload, addr) = self.session.recv().await?;
        let destination = parse_authority(&addr).ok_or_else(|| {
            Hysteria2ProxyError::Dial(format!("invalid Hysteria2 UDP address: {addr}"))
        })?;
        Ok((destination, payload))
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
    let handshake_timeout = if hysteria2.handshake_timeout_ms == 0 {
        Duration::from_secs(10)
    } else {
        Duration::from_millis(hysteria2.handshake_timeout_ms)
    };
    let obfs_password = if hysteria2.obfs.as_deref() == Some("salamander") {
        hysteria2.obfs_password.clone()
    } else {
        String::new()
    };
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
        up_bps: hysteria2.up_bps,
        down_bps: hysteria2.down_bps,
        obfs_password,
        hop_ports: hysteria2.hop_ports.clone(),
        hop_interval_min_secs: hysteria2.hop_interval_min_secs,
        hop_interval_max_secs: hysteria2.hop_interval_max_secs,
        udp_mtu: hysteria2.udp_mtu,
        handshake_timeout,
        stream_receive_window: hysteria2.stream_receive_window,
        connection_receive_window: hysteria2.connection_receive_window,
        bind_interface: String::new(),
        routing_mark: 0,
    })
}

fn parse_authority(authority: &str) -> Option<Destination> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']')?;
        let port = suffix.strip_prefix(':')?.parse().ok()?;
        (host, port)
    } else {
        let (host, port) = authority.rsplit_once(':')?;
        (host, port.parse().ok()?)
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    Some(Destination {
        host: host
            .parse::<IpAddr>()
            .map_or_else(|_| Host::Domain(host.to_owned()), Host::Ip),
        port,
    })
}

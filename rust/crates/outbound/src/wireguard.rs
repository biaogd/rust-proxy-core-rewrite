//! `WireGuard` userspace outbound adapter (6I-C TCP+UDP+lifecycle).

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use rewrite_config::ProxyConfig;
use rewrite_model::{Destination, Host};
use rewrite_protocol_wireguard::{
    Client, ClientOptions, DEFAULT_MTU, PeerResolveHook, WgUdpSocket,
};
use thiserror::Error;

const TUNNEL_DNS_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Error)]
pub enum WireGuardProxyError {
    #[error(transparent)]
    Protocol(#[from] rewrite_protocol_wireguard::WireGuardProtocolError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("WireGuard dial failed: {0}")]
    Dial(String),
}

/// Long-lived outbound client matching Go `adapter/outbound.WireGuard` for 6I-B.
#[derive(Clone)]
pub struct WireGuardClient {
    inner: std::sync::Arc<Client>,
    dns_servers: Vec<SocketAddr>,
}

impl std::fmt::Debug for WireGuardClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WireGuardClient")
    }
}

impl WireGuardClient {
    /// Dials using a PSN-resolved IP for the outer UDP bind when `dial_server`
    /// is an address. Refresh re-resolves the original YAML `server` hostname
    /// through the same hosts + PSN policy as first connect.
    ///
    /// `bind_interface` / `routing_mark` apply to the outer UDP socket (TUN
    /// auto-route loop avoidance).
    ///
    /// # Errors
    ///
    /// Returns when the proxy is missing `WireGuard` options or UDP bind fails.
    pub async fn from_proxy_with_dial_server(
        proxy: &ProxyConfig,
        dial_server: &str,
        bind_interface: &str,
        routing_mark: i64,
        resolve_peer: Option<PeerResolveHook>,
    ) -> Result<Self, WireGuardProxyError> {
        let mut options = client_options_from_proxy(proxy)?;
        if let Ok(ip) = dial_server.parse::<IpAddr>() {
            options.initial_endpoint = Some(SocketAddr::new(ip, options.port));
        }
        bind_interface.clone_into(&mut options.bind_interface);
        options.routing_mark = routing_mark;
        options.resolve_peer = resolve_peer;
        let dns_servers = tunnel_dns_servers(proxy)?;
        let inner = Client::new(options).await?;
        Ok(Self {
            inner: std::sync::Arc::new(inner),
            dns_servers,
        })
    }

    #[must_use]
    pub fn has_ipv4(&self) -> bool {
        self.inner.has_ipv4()
    }

    #[must_use]
    pub fn has_ipv6(&self) -> bool {
        self.inner.has_ipv6()
    }

    #[must_use]
    pub fn uses_tunnel_dns(&self) -> bool {
        !self.dns_servers.is_empty()
    }

    /// Opens a proxied TCP stream to `destination`.
    ///
    /// # Errors
    ///
    /// Returns handshake, family, or userspace-stack connect failures.
    pub async fn create_proxy(
        &self,
        destination: &Destination,
    ) -> Result<crate::BoxedOutboundStream, WireGuardProxyError> {
        self.inner.open_tcp(destination).await.map_err(Into::into)
    }

    /// Resolves `host` through tunnel-resident DNS (Go `remote-dns-resolve`).
    ///
    /// # Errors
    ///
    /// Returns when no nameserver answers with a usable A/AAAA record.
    pub async fn resolve_host(&self, host: &str) -> Result<IpAddr, WireGuardProxyError> {
        if self.dns_servers.is_empty() {
            return Err(WireGuardProxyError::Dial(
                "WireGuard tunnel DNS is not configured".to_owned(),
            ));
        }
        let socket = self.inner.open_udp().await?;
        let mut last_error = None;
        for server in &self.dns_servers {
            if self.has_ipv4() {
                match query_tunnel_dns(&socket, *server, host, RecordType::A).await {
                    Ok(address) => return Ok(address),
                    Err(error) => last_error = Some(error),
                }
            }
            if self.has_ipv6() {
                match query_tunnel_dns(&socket, *server, host, RecordType::AAAA).await {
                    Ok(address) => return Ok(address),
                    Err(error) => last_error = Some(error),
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            WireGuardProxyError::Dial("WireGuard tunnel DNS returned no address".to_owned())
        }))
    }

    /// Resolves a mixed/health destination.
    ///
    /// Tunnel DNS (`remote-dns-resolve`) is used for domain names when
    /// configured; otherwise `resolve_direct` runs (configured `dns:` or the
    /// system resolver). Family must match the inner `ip` / `ipv6` assignment.
    ///
    /// # Errors
    ///
    /// Returns when the name does not resolve or the family is unsupported.
    pub async fn resolve_destination<F, Fut, E>(
        &self,
        destination: &Destination,
        resolve_direct: F,
    ) -> Result<Destination, WireGuardProxyError>
    where
        F: FnOnce(&str) -> Fut,
        Fut: Future<Output = Result<IpAddr, E>>,
        E: std::fmt::Display,
    {
        let address = match &destination.host {
            Host::Ip(address) => *address,
            Host::Domain(domain) if self.uses_tunnel_dns() => self.resolve_host(domain).await?,
            Host::Domain(domain) => resolve_direct(domain).await.map_err(|error| {
                WireGuardProxyError::Dial(format!("WireGuard destination DNS failed: {error}"))
            })?,
        };
        let supported = match address {
            IpAddr::V4(_) => self.has_ipv4(),
            IpAddr::V6(_) => self.has_ipv6(),
        };
        if supported {
            Ok(Destination {
                host: Host::Ip(address),
                port: destination.port,
            })
        } else {
            Err(WireGuardProxyError::Dial(
                "WireGuard has no inner address for this family".to_owned(),
            ))
        }
    }

    #[allow(clippy::unused_async)] // matches TUIC/Hysteria2 retire shape
    pub async fn retire(&self) {
        self.inner.close().await;
    }
}

/// UDP association wrapping a userspace `WireGuard` datagram socket.
pub struct WireGuardUdpAssociation {
    socket: WgUdpSocket,
}

/// Opens a `WireGuard` UDP socket (Go `ListenPacketContext`).
///
/// # Errors
///
/// Returns handshake or userspace bind failures.
pub async fn associate_wireguard_udp(
    client: &WireGuardClient,
) -> Result<WireGuardUdpAssociation, WireGuardProxyError> {
    let socket = client.inner.open_udp().await?;
    Ok(WireGuardUdpAssociation { socket })
}

impl WireGuardUdpAssociation {
    /// Sends `payload` to `destination`. Domain names must already be resolved.
    ///
    /// # Errors
    ///
    /// Returns when the destination is unresolved or the stack send fails.
    pub async fn send(
        &self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), WireGuardProxyError> {
        let dest = match &destination.host {
            Host::Ip(ip) => SocketAddr::new(*ip, destination.port),
            Host::Domain(_) => {
                return Err(WireGuardProxyError::Dial(
                    "WireGuard UDP destination must be resolved".to_owned(),
                ));
            }
        };
        self.socket.send(dest, payload).await.map_err(Into::into)
    }

    /// Receives the next datagram as `(destination, payload)`.
    ///
    /// # Errors
    ///
    /// Returns once the socket or client is closed.
    pub async fn recv(&mut self) -> Result<(Destination, Vec<u8>), WireGuardProxyError> {
        let (from, payload) = self.socket.recv().await?;
        Ok((
            Destination {
                host: Host::Ip(from.ip()),
                port: from.port(),
            },
            payload,
        ))
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
        local_v4: Some((wireguard.local_addr, wireguard.local_prefix_len))
            .filter(|(addr, prefix)| *addr != Ipv4Addr::UNSPECIFIED || *prefix != 0),
        local_v6: wireguard.local_ipv6,
        mtu: if wireguard.mtu == 0 {
            DEFAULT_MTU
        } else {
            wireguard.mtu
        },
        persistent_keepalive: wireguard.persistent_keepalive,
        reserved: wireguard.reserved,
        bind_interface: String::new(),
        routing_mark: 0,
        refresh_server_ip_interval: Duration::from_secs(wireguard.refresh_server_ip_interval),
        initial_endpoint: None,
        resolve_peer: None,
    })
}

fn tunnel_dns_servers(proxy: &ProxyConfig) -> Result<Vec<SocketAddr>, WireGuardProxyError> {
    let Some(wireguard) = proxy.wireguard.as_ref() else {
        return Ok(Vec::new());
    };
    if !wireguard.remote_dns_resolve || wireguard.dns_servers.is_empty() {
        return Ok(Vec::new());
    }
    wireguard
        .dns_servers
        .iter()
        .map(|server| parse_dns_server(server))
        .collect()
}

fn parse_dns_server(text: &str) -> Result<SocketAddr, WireGuardProxyError> {
    let trimmed = text.trim();
    if let Ok(address) = trimmed.parse::<SocketAddr>() {
        return Ok(address);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(WireGuardProxyError::Dial(format!(
        "WireGuard DNS server {trimmed} must be an IP or IP:port"
    )))
}

fn next_dns_id() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(0xc04c);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    if id == 0 { 1 } else { id }
}

async fn query_tunnel_dns(
    socket: &WgUdpSocket,
    server: SocketAddr,
    host: &str,
    record_type: RecordType,
) -> Result<IpAddr, WireGuardProxyError> {
    let name = Name::from_ascii(host).map_err(|error| {
        WireGuardProxyError::Dial(format!("WireGuard tunnel DNS name: {error}"))
    })?;
    let id = next_dns_id();
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, record_type));
    let query = message.to_vec().map_err(|error| {
        WireGuardProxyError::Dial(format!("WireGuard tunnel DNS encode: {error}"))
    })?;
    socket.send(server, &query).await?;
    let deadline = tokio::time::Instant::now() + TUNNEL_DNS_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(WireGuardProxyError::Dial(
                "WireGuard tunnel DNS timed out".to_owned(),
            ));
        }
        let (from, payload) = match tokio::time::timeout(remaining, socket.recv()).await {
            Ok(Ok(packet)) => packet,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                return Err(WireGuardProxyError::Dial(
                    "WireGuard tunnel DNS timed out".to_owned(),
                ));
            }
        };
        if from != server {
            continue;
        }
        let Ok(response) = Message::from_bytes(&payload) else {
            continue;
        };
        if response.metadata.id != id {
            continue;
        }
        if let Some(address) = dns_answer_ip(&response, record_type) {
            return Ok(address);
        }
        return Err(WireGuardProxyError::Dial(
            "WireGuard tunnel DNS returned no address".to_owned(),
        ));
    }
}

fn dns_answer_ip(message: &Message, record_type: RecordType) -> Option<IpAddr> {
    message.answers.iter().find_map(|record| {
        if record.record_type() != record_type {
            return None;
        }
        match &record.data {
            RData::A(addr) => Some(IpAddr::V4(addr.0)),
            RData::AAAA(addr) => Some(IpAddr::V6(addr.0)),
            _ => None,
        }
    })
}

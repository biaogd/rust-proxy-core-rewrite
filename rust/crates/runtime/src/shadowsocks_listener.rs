use std::future::pending;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use rewrite_config::{Config, ShadowsocksInboundConfig};
use rewrite_inbound::BoxedInboundStream;
use rewrite_model::{Destination, Host, InboundProtocol, Metadata, Network, unmap_ip};
use rewrite_rules::Route;
use rewrite_state::RuntimeState;
use shadowsocks::ProxyListener;
use shadowsocks::ProxySocket;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context as SsContext;
use shadowsocks::crypto::CipherKind;
use shadowsocks::net::UdpSocket as SsUdpSocket;
use shadowsocks::relay::socks5::Address;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::listener::{resolved_route, resolve_udp_target};
use crate::tcp::{apply_host_mapping, mode_decision, resolve_rematch_target};
use crate::tcp::serve_shadowsocks_connection;
use crate::types::RuntimeError;

pub(crate) struct ShadowsocksListener {
    inner: ProxyListener,
    udp: Option<Arc<ProxySocket<SsUdpSocket>>>,
}

impl ShadowsocksListener {
    pub(crate) async fn bind(config: &ShadowsocksInboundConfig) -> Result<Self, RuntimeError> {
        let method = CipherKind::from_str(&config.cipher).map_err(|_| {
            RuntimeError::Config(rewrite_config::ConfigError::InvalidInbound(format!(
                "unsupported shadowsocks inbound cipher: {}",
                config.cipher
            )))
        })?;
        let server = ServerConfig::new(config.listen, &config.password, method).map_err(|error| {
            RuntimeError::Config(rewrite_config::ConfigError::InvalidInbound(error.to_string()))
        })?;
        let context = SsContext::new_shared(ServerType::Server);
        let inner = ProxyListener::bind(context.clone(), &server)
            .await
            .map_err(|error| RuntimeError::Listener(std::io::Error::other(error)))?;
        let udp = if config.udp {
            Some(Arc::new(
                ProxySocket::bind(context, &server)
                    .await
                    .map_err(|error| RuntimeError::Listener(std::io::Error::other(error)))?,
            ))
        } else {
            None
        };
        Ok(Self { inner, udp })
    }
}

struct ShadowsocksInboundStream<S> {
    inner: S,
    local: SocketAddr,
    peer: SocketAddr,
}

impl<S> ShadowsocksInboundStream<S> {
    fn new(inner: S, local: SocketAddr, peer: SocketAddr) -> Self {
        Self { inner, local, peer }
    }
}

impl<S> tokio::io::AsyncRead for ShadowsocksInboundStream<S>
where
    S: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> tokio::io::AsyncWrite for ShadowsocksInboundStream<S>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> rewrite_inbound::InboundStream for ShadowsocksInboundStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer)
    }
}

pub(super) async fn run_shadowsocks_listener(
    listener: ShadowsocksListener,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let ShadowsocksListener { inner, udp } = listener;
    let mut connections = tokio::task::JoinSet::new();
    let mut datagram = vec![0_u8; 65_536];
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = inner.accept() => {
                let Ok((mut inbound, peer)) = accepted else {
                    state.log("error", "shadowsocks inbound accept failed");
                    break;
                };
                let local = inner.local_addr().unwrap_or(peer);
                let connection_config = Arc::clone(&config.borrow());
                let connection_state = Arc::clone(&state);
                let connection_dns_service = Arc::clone(&dns_service);
                let connection_shutdown = shutdown.child_token();
                connections.spawn(async move {
                    if !connection_config.permits_inbound(peer.ip()) {
                        return;
                    }
                    let destination = tokio::select! {
                        () = connection_shutdown.cancelled() => return,
                        result = tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            inbound.handshake(),
                        ) => match result {
                            Ok(Ok(destination)) => match address_to_destination(&destination) {
                                Ok(destination) => destination,
                                Err(error) => {
                                    connection_state.log(
                                        "error",
                                        format!("shadowsocks inbound destination rejected: {error}"),
                                    );
                                    return;
                                }
                            },
                            Ok(Err(error)) => {
                                connection_state.log(
                                    "error",
                                    format!("shadowsocks inbound handshake failed: {error}"),
                                );
                                return;
                            }
                            Err(_) => {
                                connection_state.log("error", "shadowsocks inbound handshake timed out");
                                return;
                            }
                        }
                    };
                    let mut metadata = Metadata::new(destination, InboundProtocol::Shadowsocks);
                    metadata.network = Network::Tcp;
                    metadata.source_ip = Some(unmap_ip(peer.ip()));
                    metadata.source_port = peer.port();
                    metadata.inbound_port = local.port();
                    metadata.inbound_name = "DEFAULT-SHADOWSOCKS".to_owned();
                    let client: BoxedInboundStream =
                        Box::new(ShadowsocksInboundStream::new(inbound, local, peer));
                    serve_shadowsocks_connection(
                        client,
                        metadata,
                        &connection_config,
                        &connection_state,
                        &connection_dns_service,
                        &connection_shutdown,
                    )
                    .await;
                });
            }
            received = recv_shadowsocks_udp(udp.as_deref(), &mut datagram) => {
                if let Ok((length, peer, destination, _)) = received {
                    let payload = datagram[..length].to_vec();
                    let connection_config = Arc::clone(&config.borrow());
                    let connection_state = Arc::clone(&state);
                    let inbound_port = inner.local_addr().map(|address| address.port()).unwrap_or(0);
                    let Some(inbound_socket) = udp.as_ref() else {
                        continue;
                    };
                    let inbound_socket = Arc::clone(inbound_socket);
                    let connection_shutdown = shutdown.child_token();
                    connections.spawn(async move {
                        handle_shadowsocks_udp_packet(
                            inbound_socket,
                            peer,
                            inbound_port,
                            destination,
                            payload,
                            &connection_config,
                            &connection_state,
                            &connection_shutdown,
                        )
                        .await;
                    });
                }
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(join_error)) = result {
                    state.log("error", format!("shadowsocks inbound task failed: {join_error}"));
                }
            }
        }
    }
    shutdown.cancel();
    while let Some(result) = connections.join_next().await {
        if let Err(join_error) = result {
            state.log(
                "error",
                format!("shadowsocks inbound task failed during shutdown: {join_error}"),
            );
        }
    }
}

async fn recv_shadowsocks_udp(
    socket: Option<&ProxySocket<SsUdpSocket>>,
    buffer: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, Address, usize)> {
    match socket {
        Some(socket) => socket
            .recv_from(buffer)
            .await
            .map_err(std::io::Error::other),
        None => pending().await,
    }
}

async fn handle_shadowsocks_udp_packet(
    inbound: Arc<ProxySocket<SsUdpSocket>>,
    peer: SocketAddr,
    inbound_port: u16,
    destination: Address,
    payload: Vec<u8>,
    config: &Config,
    state: &Arc<RuntimeState>,
    shutdown: &CancellationToken,
) {
    if !config.permits_inbound(peer.ip()) {
        return;
    }
    let destination = match address_to_destination(&destination) {
        Ok(destination) => destination,
        Err(error) => {
            state.log(
                "error",
                format!("shadowsocks inbound UDP destination rejected: {error}"),
            );
            return;
        }
    };
    let mut metadata = Metadata::new(destination, InboundProtocol::Shadowsocks);
    metadata.network = Network::Udp;
    metadata.source_ip = Some(unmap_ip(peer.ip()));
    metadata.source_port = peer.port();
    metadata.inbound_port = inbound_port;
    metadata.inbound_name = "DEFAULT-SHADOWSOCKS".to_owned();
    let fake_host = apply_host_mapping(&mut metadata, config, state.as_ref());
    let decision = mode_decision(config, state.as_ref())
        .unwrap_or_else(|| config.rules.evaluate(&metadata));
    let Some((decision, _, _)) =
        resolve_rematch_target(decision, &mut metadata, config, state.as_ref())
    else {
        return;
    };
    let route = resolved_route(&decision.target, config);
    state.log(
        "info",
        format!(
            "[UDP] {} --> {} match {} using {}",
            metadata.source_port,
            metadata.destination.authority(),
            decision.matched_kind.as_deref().unwrap_or("none"),
            decision.target
        ),
    );
    let tracker = state.register(
        &metadata,
        &decision.target,
        decision.matched_kind.as_deref(),
    );
    if matches!(route, Route::Reject | Route::RejectDrop) {
        return;
    }
    if !matches!(route, Route::Direct) && decision.target != "DIRECT" {
        state.log(
            "error",
            format!(
                "shadowsocks inbound UDP outbound {} is not implemented yet",
                decision.target
            ),
        );
        return;
    }
    let target = match resolve_udp_target(&metadata, fake_host.as_deref(), config).await {
        Ok(target) => target,
        Err(error) => {
            state.log(
                "error",
                format!("shadowsocks inbound UDP resolution failed: {error}"),
            );
            return;
        }
    };
    let bind_address = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let outbound = match rewrite_platform::bind_outbound_udp(
        bind_address.parse().expect("static UDP bind address"),
        &config.interface_name,
        config.routing_mark,
    )
    .and_then(UdpSocket::from_std)
    {
        Ok(socket) => socket,
        Err(error) => {
            state.log(
                "error",
                format!("shadowsocks inbound UDP bind failed: {error}"),
            );
            return;
        }
    };
    let uploaded = payload.len() as u64;
    if tokio::select! {
        () = shutdown.cancelled() => return,
        () = tracker.cancelled() => return,
        result = outbound.send_to(&payload, target) => result.is_err(),
    } {
        return;
    }
    let mut response = vec![0_u8; 65_535];
    let received = tokio::select! {
        () = shutdown.cancelled() => return,
        () = tracker.cancelled() => return,
        result = tokio::time::timeout(Duration::from_secs(5), outbound.recv_from(&mut response)) => result,
    };
    let Ok(Ok((length, remote))) = received else {
        return;
    };
    if inbound
        .send_to(
            peer,
            &Address::SocketAddress(remote),
            &response[..length],
        )
        .await
        .is_err()
    {
        return;
    }
    tracker.finish(uploaded, length as u64);
}

fn address_to_destination(address: &Address) -> Result<Destination, &'static str> {
    match address {
        Address::SocketAddress(socket) => Ok(Destination {
            host: Host::Ip(socket.ip()),
            port: socket.port(),
        }),
        Address::DomainNameAddress(domain, port) => {
            if *port == 0 {
                return Err("domain destination requires a nonzero port");
            }
            Ok(Destination {
                host: Host::Domain(domain.clone()),
                port: *port,
            })
        }
    }
}

use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use rewrite_config::{Config, ShadowsocksInboundConfig};
use rewrite_inbound::BoxedInboundStream;
use rewrite_model::{Destination, Host, InboundProtocol, Metadata, Network, unmap_ip};
use rewrite_state::RuntimeState;
use shadowsocks::ProxyListener;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context as SsContext;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::tcp::serve_shadowsocks_connection;
use crate::types::RuntimeError;

pub(crate) struct ShadowsocksListener {
    inner: ProxyListener,
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
        let inner = ProxyListener::bind(context, &server)
            .await
            .map_err(RuntimeError::Listener)?;
        Ok(Self { inner })
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
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.inner.accept() => {
                let Ok((mut inbound, peer)) = accepted else {
                    state.log("error", "shadowsocks inbound accept failed");
                    break;
                };
                let local = listener.inner.local_addr().unwrap_or(peer);
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

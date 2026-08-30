use std::collections::BTreeMap;
use std::future::pending;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use rewrite_config::{Config, ShadowsocksInboundConfig, ShadowsocksShadowTlsConfig, ShadowsocksSimpleObfsConfig};
use rewrite_inbound::BoxedInboundStream;
use rewrite_model::{Destination, Host, InboundProtocol, Metadata, Network, unmap_ip};
use rewrite_outbound::{HttpObfsServer, HttpProxyTls, ShadowTlsServer, ShadowTlsServerConfig, TlsObfsServer};
use rewrite_rules::{Decision, Route};
use rewrite_state::RuntimeState;
use shadowsocks::ProxyListener;
use shadowsocks::ProxySocket;
use shadowsocks::config::{ServerConfig, ServerType, ServerUser, ServerUserManager, method_support_eih};
use shadowsocks::context::Context as SsContext;
use shadowsocks::crypto::CipherKind;
use shadowsocks::net::UdpSocket as SsUdpSocket;
use shadowsocks::relay::socks5::Address;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::listener::{
    dns_adapter_response_addr, resolved_route, resolve_udp_response_source, resolve_udp_target,
    udp_session_mode, UdpSessionMode,
};
use crate::tcp::{
    apply_host_mapping, configured_proxy, direct_tcp_options, mode_decision,
    resolve_rematch_target, serve_shadowsocks_connection,
};
use crate::types::RuntimeError;

fn inbound_udp_destination(metadata: &Metadata, fake_host: Option<&str>) -> Destination {
    fake_host.map_or_else(
        || metadata.destination.clone(),
        |host| Destination {
            host: Host::Domain(host.to_owned()),
            port: metadata.destination.port,
        },
    )
}

pub(crate) struct ShadowsocksListener {
    inner: ProxyListener,
    udp: Option<Arc<ProxySocket<SsUdpSocket>>>,
    inbound_name: String,
    simple_obfs: Option<ShadowsocksSimpleObfsConfig>,
    shadow_tls: Option<ShadowsocksShadowTlsConfig>,
}

impl ShadowsocksListener {
    pub(crate) async fn bind(config: &ShadowsocksInboundConfig) -> Result<Self, RuntimeError> {
        let method = CipherKind::from_str(&config.cipher).map_err(|_| {
            RuntimeError::Config(rewrite_config::ConfigError::InvalidInbound(format!(
                "unsupported shadowsocks inbound cipher: {}",
                config.cipher
            )))
        })?;
        let (server_password, user_keys) = split_shadowsocks_inbound_password(&config.password);
        if !user_keys.is_empty() && !method_support_eih(method) {
            return Err(RuntimeError::Config(
                rewrite_config::ConfigError::InvalidInbound(format!(
                    "shadowsocks inbound cipher {} does not support EIH users",
                    config.cipher
                )),
            ));
        }
        let mut server =
            ServerConfig::new(config.listen, server_password, method).map_err(|error| {
                RuntimeError::Config(rewrite_config::ConfigError::InvalidInbound(error.to_string()))
            })?;
        if !user_keys.is_empty() {
            let mut users = ServerUserManager::new();
            for (index, user_key) in user_keys.iter().enumerate() {
                let name = format!("eih-user-{index}");
                users.add_user(
                    ServerUser::with_encoded_key(name, user_key).map_err(|error| {
                        RuntimeError::Config(rewrite_config::ConfigError::InvalidInbound(
                            error.to_string(),
                        ))
                    })?,
                );
            }
            server.set_user_manager(users);
        }
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
        Ok(Self {
            inner,
            udp,
            inbound_name: config.name.clone(),
            simple_obfs: config.simple_obfs.clone(),
            shadow_tls: config.shadow_tls.clone(),
        })
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

#[allow(clippy::too_many_lines)]
pub(super) async fn run_shadowsocks_listener(
    listener: ShadowsocksListener,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let ShadowsocksListener {
        inner,
        udp,
        inbound_name,
        simple_obfs,
        shadow_tls,
    } = listener;
    let obfs_mode = simple_obfs.as_ref().map(|config| config.mode.as_str());
    let shadow_tls_config = shadow_tls.as_ref().map(shadow_tls_server_config);
    let mut connections = JoinSet::new();
    let mut udp_sessions = ShadowsocksUdpSessions::default();
    let mut datagram = vec![0_u8; 65_536];
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = inner.accept_map({
                let shadow_tls_config = shadow_tls_config.clone();
                move |stream| -> rewrite_outbound::BoxedOutboundStream {
                if let Some(config) = shadow_tls_config {
                    Box::new(ShadowTlsServer::new(stream, config))
                } else {
                match obfs_mode {
                    Some("http") => Box::new(HttpObfsServer::new(stream, None)),
                    Some("tls") => Box::new(TlsObfsServer::new(stream, None)),
                    _ => Box::new(stream),
                }
                }
            }
            }) => {
                let Ok((mut inbound, peer)) = accepted else {
                    state.log("error", "shadowsocks inbound accept failed");
                    break;
                };
                let local = inner.local_addr().unwrap_or(peer);
                let connection_config = Arc::clone(&config.borrow());
                let connection_state = Arc::clone(&state);
                let connection_dns_service = Arc::clone(&dns_service);
                let connection_shutdown = shutdown.child_token();
                let connection_inbound_name = inbound_name.clone();
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
                    connection_inbound_name.clone_into(&mut metadata.inbound_name);
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
            result = udp_sessions.tasks.join_next(), if !udp_sessions.tasks.is_empty() => {
                udp_sessions.reap(result.as_ref());
            }
            received = recv_shadowsocks_udp(udp.as_deref(), &mut datagram) => {
                if let Ok((length, peer, destination, _)) = received {
                    let connection_config = Arc::clone(&config.borrow());
                    let inbound_port = inner.local_addr().map_or(0, |address| address.port());
                    let Some(inbound_socket) = udp.as_ref() else {
                        continue;
                    };
                    let Some(request) = prepare_shadowsocks_udp_packet(
                        peer,
                        inbound_port,
                        &destination,
                        datagram[..length].to_vec(),
                        &inbound_name,
                        &connection_config,
                        &state,
                    ) else {
                        continue;
                    };
                    udp_sessions.dispatch(
                        peer,
                        request,
                        ShadowsocksUdpSessionContext {
                            inbound: Arc::clone(inbound_socket),
                            config: connection_config,
                            state: Arc::clone(&state),
                            dns_service: Arc::clone(&dns_service),
                            shutdown: shutdown.child_token(),
                        },
                    );
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
    udp_sessions.shutdown(&state).await;
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

struct ShadowsocksUdpPacket {
    metadata: Metadata,
    fake_host: Option<String>,
    payload: Vec<u8>,
}

#[derive(Clone)]
struct ShadowsocksUdpSessionContext {
    inbound: Arc<ProxySocket<SsUdpSocket>>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
}

#[derive(Default)]
struct ShadowsocksUdpSessions {
    tasks: JoinSet<(SocketAddr, u64)>,
    entries: BTreeMap<SocketAddr, (u64, mpsc::Sender<ShadowsocksUdpPacket>)>,
    next_id: u64,
}

impl ShadowsocksUdpSessions {
    fn reap(&mut self, result: Option<&Result<(SocketAddr, u64), tokio::task::JoinError>>) {
        if let Some(Ok((source, session_id))) = result
            && self
                .entries
                .get(source)
                .is_some_and(|(current_id, _)| current_id == session_id)
        {
            self.entries.remove(source);
        }
    }

    fn dispatch(
        &mut self,
        source: SocketAddr,
        request: ShadowsocksUdpPacket,
        context: ShadowsocksUdpSessionContext,
    ) {
        if let Some((_, sender)) = self.entries.get(&source) {
            match sender.try_send(request) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    context
                        .state
                        .log("error", "shadowsocks inbound UDP session queue is full");
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(request)) => {
                    self.entries.remove(&source);
                    self.start(source, request, context);
                    return;
                }
            }
        }
        self.start(source, request, context);
    }

    fn start(
        &mut self,
        source: SocketAddr,
        mut request: ShadowsocksUdpPacket,
        context: ShadowsocksUdpSessionContext,
    ) {
        let decision = mode_decision(&context.config, &context.state)
            .unwrap_or_else(|| context.config.rules.evaluate(&request.metadata));
        let Some((decision, _, _)) = resolve_rematch_target(
            decision,
            &mut request.metadata,
            &context.config,
            &context.state,
        ) else {
            return;
        };
        context.state.log(
            "info",
            format!(
                "[UDP] {} --> {} match {} using {}",
                request.metadata.source_port,
                request.metadata.destination.authority(),
                decision.matched_kind.as_deref().unwrap_or("none"),
                decision.target
            ),
        );
        let route = resolved_route(&decision.target, &context.config);
        if matches!(route, Route::Reject | Route::RejectDrop) {
            return;
        }
        let Some(mode) = udp_session_mode(&decision.target, &context.config) else {
            context.state.log(
                "error",
                format!(
                    "shadowsocks inbound UDP target {} is unsupported",
                    decision.target
                ),
            );
            return;
        };
        let session_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let (sender, receiver) = mpsc::channel(64);
        self.entries.insert(source, (session_id, sender));
        self.tasks.spawn(async move {
            run_shadowsocks_inbound_udp_session(
                context.inbound,
                source,
                request,
                receiver,
                context.config,
                context.state,
                context.dns_service,
                decision,
                mode,
                context.shutdown,
            )
            .await;
            (source, session_id)
        });
    }

    async fn shutdown(mut self, state: &RuntimeState) {
        self.entries.clear();
        while let Some(result) = self.tasks.join_next().await {
            if let Err(join_error) = result {
                state.log(
                    "error",
                    format!(
                        "shadowsocks inbound UDP session task failed during shutdown: {join_error}"
                    ),
                );
            }
        }
    }
}

fn prepare_shadowsocks_udp_packet(
    peer: SocketAddr,
    inbound_port: u16,
    destination: &Address,
    payload: Vec<u8>,
    inbound_name: &str,
    config: &Config,
    state: &Arc<RuntimeState>,
) -> Option<ShadowsocksUdpPacket> {
    if !config.permits_inbound(peer.ip()) {
        return None;
    }
    let destination = match address_to_destination(&destination) {
        Ok(destination) => destination,
        Err(error) => {
            state.log(
                "error",
                format!("shadowsocks inbound UDP destination rejected: {error}"),
            );
            return None;
        }
    };
    let mut metadata = Metadata::new(destination, InboundProtocol::Shadowsocks);
    metadata.network = Network::Udp;
    metadata.source_ip = Some(unmap_ip(peer.ip()));
    metadata.source_port = peer.port();
    metadata.inbound_port = inbound_port;
    inbound_name.clone_into(&mut metadata.inbound_name);
    let fake_host = apply_host_mapping(&mut metadata, config, state.as_ref());
    Some(ShadowsocksUdpPacket {
        metadata,
        fake_host,
        payload,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_shadowsocks_inbound_udp_session(
    inbound: Arc<ProxySocket<SsUdpSocket>>,
    peer: SocketAddr,
    first: ShadowsocksUdpPacket,
    requests: mpsc::Receiver<ShadowsocksUdpPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    decision: Decision,
    mode: UdpSessionMode,
    shutdown: CancellationToken,
) {
    match mode {
        UdpSessionMode::Direct => {
            run_shadowsocks_direct_udp_session(
                inbound, peer, first, requests, config, state, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::Dns => {
            run_shadowsocks_dns_udp_session(
                inbound,
                peer,
                first,
                requests,
                config,
                state,
                dns_service,
                decision,
                shutdown,
            )
            .await;
        }
        UdpSessionMode::Socks5(proxy) => {
            run_shadowsocks_socks5_udp_session(
                inbound, peer, first, requests, config, state, proxy, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::Shadowsocks(proxy) => {
            run_shadowsocks_proxy_udp_session(
                inbound, peer, first, requests, config, state, proxy, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::ShadowsocksUot(_) => {
            state.log("error", "shadowsocks inbound UDP over TCP is not supported yet");
        }
    }
}

async fn send_shadowsocks_udp_reply(
    inbound: &ProxySocket<SsUdpSocket>,
    peer: SocketAddr,
    remote: SocketAddr,
    payload: &[u8],
) -> bool {
    inbound
        .send_to(peer, &Address::SocketAddress(remote), payload)
        .await
        .is_ok()
}

#[allow(clippy::too_many_arguments)]
async fn run_shadowsocks_direct_udp_session(
    inbound: Arc<ProxySocket<SsUdpSocket>>,
    peer: SocketAddr,
    first: ShadowsocksUdpPacket,
    mut requests: mpsc::Receiver<ShadowsocksUdpPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    decision: Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let target =
        match resolve_udp_target(&first.metadata, first.fake_host.as_deref(), &config).await {
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
    let tracker = state.register(
        &first.metadata,
        &decision.target,
        decision.matched_kind.as_deref(),
    );
    let mut uploaded = 0_u64;
    let mut downloaded = 0_u64;
    if outbound.send_to(&first.payload, target).await.is_err() {
        tracker.finish(uploaded, downloaded);
        return;
    }
    uploaded = uploaded.saturating_add(first.payload.len() as u64);
    let idle = tokio::time::sleep(UDP_SESSION_TIMEOUT);
    tokio::pin!(idle);
    let mut response = vec![0_u8; 65_535];
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tracker.cancelled() => break,
            request = requests.recv() => {
                let Some(request) = request else { break };
                let target = match resolve_udp_target(
                    &request.metadata,
                    request.fake_host.as_deref(),
                    &config,
                ).await {
                    Ok(target) => target,
                    Err(error) => {
                        state.log(
                            "error",
                            format!("shadowsocks inbound UDP resolution failed: {error}"),
                        );
                        continue;
                    }
                };
                if outbound.send_to(&request.payload, target).await.is_ok() {
                    uploaded = uploaded.saturating_add(request.payload.len() as u64);
                    idle.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_TIMEOUT);
                }
            }
            received = outbound.recv_from(&mut response) => {
                let Ok((length, remote)) = received else { break };
                if !send_shadowsocks_udp_reply(&inbound, peer, remote, &response[..length]).await {
                    break;
                }
                downloaded = downloaded.saturating_add(length as u64);
                idle.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_TIMEOUT);
            }
            () = &mut idle => break,
        }
    }
    tracker.finish(uploaded, downloaded);
}

#[allow(clippy::too_many_arguments)]
async fn run_shadowsocks_dns_udp_session(
    inbound: Arc<ProxySocket<SsUdpSocket>>,
    peer: SocketAddr,
    first: ShadowsocksUdpPacket,
    mut requests: mpsc::Receiver<ShadowsocksUdpPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    decision: Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let tracker = state.register(
        &first.metadata,
        &decision.target,
        decision.matched_kind.as_deref(),
    );
    let mut uploaded = 0_u64;
    let mut downloaded = 0_u64;
    let idle = tokio::time::sleep(UDP_SESSION_TIMEOUT);
    tokio::pin!(idle);
    let mut current = Some(first);
    loop {
        if let Some(request) = current.take() {
            uploaded = uploaded.saturating_add(request.payload.len() as u64);
            match dns_service
                .relay_query(&config, &state, &request.payload)
                .await
            {
                Ok(response) => {
                    let remote = dns_adapter_response_addr(&request.metadata);
                    if !send_shadowsocks_udp_reply(&inbound, peer, remote, &response).await {
                        break;
                    }
                    downloaded = downloaded.saturating_add(response.len() as u64);
                }
                Err(error) => {
                    state.log(
                        "error",
                        format!("shadowsocks inbound UDP DNS relay failed: {error}"),
                    );
                }
            }
            idle.as_mut()
                .reset(tokio::time::Instant::now() + UDP_SESSION_TIMEOUT);
        }
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tracker.cancelled() => break,
            request = requests.recv() => {
                let Some(request) = request else { break };
                current = Some(request);
            }
            () = &mut idle => break,
        }
    }
    tracker.finish(uploaded, downloaded);
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_shadowsocks_socks5_udp_session(
    inbound: Arc<ProxySocket<SsUdpSocket>>,
    peer: SocketAddr,
    first: ShadowsocksUdpPacket,
    mut requests: mpsc::Receiver<ShadowsocksUdpPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    proxy_name: String,
    decision: Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let Some(proxy) = configured_proxy(&config, &proxy_name) else {
        return;
    };
    let server = Destination {
        host: proxy
            .server
            .parse()
            .map_or_else(|_| Host::Domain(proxy.server.clone()), Host::Ip),
        port: proxy.port,
    };
    let tls = proxy.tls.then_some(HttpProxyTls {
        server_name: &proxy.server,
        verification_name: proxy.name_cert_verify.as_deref(),
        skip_certificate_verification: proxy.skip_cert_verify,
        fingerprint: proxy.fingerprint.as_deref(),
        certificate: proxy.certificate.as_deref(),
        private_key: proxy.private_key.as_deref(),
        custom_roots: &config.trust_certificates,
        ech_config: None,
        alpn_protocols: &[],
        tls12_only: false,
        tls13_only: false,
    });
    let association = match rewrite_outbound::associate_socks5_udp_with_options(
        &server,
        config.ipv6,
        proxy.socks5_credentials(),
        tls,
        Some(state.clock()),
        direct_tcp_options(&config),
    )
    .await
    {
        Ok(association) => association,
        Err(error) => {
            state.log(
                "error",
                format!("shadowsocks inbound SOCKS5 UDP association failed: {error}"),
            );
            return;
        }
    };

    let tracker = state.register(
        &first.metadata,
        &decision.target,
        decision.matched_kind.as_deref(),
    );
    let mut uploaded = 0_u64;
    let mut downloaded = 0_u64;
    let idle = tokio::time::sleep(UDP_SESSION_TIMEOUT);
    tokio::pin!(idle);
    let mut current = Some(first);
    loop {
        if let Some(request) = current.take() {
            let destination = inbound_udp_destination(&request.metadata, request.fake_host.as_deref());
            if association
                .send(&destination, &request.payload)
                .await
                .is_err()
            {
                break;
            }
            uploaded = uploaded.saturating_add(request.payload.len() as u64);
            idle.as_mut()
                .reset(tokio::time::Instant::now() + UDP_SESSION_TIMEOUT);
        }
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tracker.cancelled() => break,
            request = requests.recv() => {
                let Some(request) = request else { break };
                current = Some(request);
            }
            response = association.recv() => {
                let Ok((remote, payload)) = response else { break };
                let Some(remote) = resolve_udp_response_source(&remote, config.ipv6).await else {
                    continue;
                };
                if !send_shadowsocks_udp_reply(&inbound, peer, remote, &payload).await {
                    break;
                }
                downloaded = downloaded.saturating_add(payload.len() as u64);
                idle.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_TIMEOUT);
            }
            () = &mut idle => break,
        }
    }
    tracker.finish(uploaded, downloaded);
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_shadowsocks_proxy_udp_session(
    inbound: Arc<ProxySocket<SsUdpSocket>>,
    peer: SocketAddr,
    first: ShadowsocksUdpPacket,
    mut requests: mpsc::Receiver<ShadowsocksUdpPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    proxy_name: String,
    decision: Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let Some(proxy) = configured_proxy(&config, &proxy_name) else {
        return;
    };
    let server = Destination {
        host: proxy
            .server
            .parse()
            .map_or_else(|_| Host::Domain(proxy.server.clone()), Host::Ip),
        port: proxy.port,
    };
    let association = match rewrite_outbound::associate_shadowsocks_udp_with_options(
        &server,
        config.ipv6,
        proxy.password.as_deref().unwrap_or_default(),
        proxy.cipher.as_deref().unwrap_or_default(),
        direct_tcp_options(&config),
    )
    .await
    {
        Ok(association) => association,
        Err(error) => {
            state.log(
                "error",
                format!("shadowsocks inbound Shadowsocks UDP association failed: {error}"),
            );
            return;
        }
    };

    let tracker = state.register(
        &first.metadata,
        &decision.target,
        decision.matched_kind.as_deref(),
    );
    let mut uploaded = 0_u64;
    let mut downloaded = 0_u64;
    let idle = tokio::time::sleep(UDP_SESSION_TIMEOUT);
    tokio::pin!(idle);
    let mut current = Some(first);
    loop {
        if let Some(request) = current.take() {
            let destination = inbound_udp_destination(&request.metadata, request.fake_host.as_deref());
            if association
                .send(&destination, &request.payload)
                .await
                .is_err()
            {
                break;
            }
            uploaded = uploaded.saturating_add(request.payload.len() as u64);
            idle.as_mut()
                .reset(tokio::time::Instant::now() + UDP_SESSION_TIMEOUT);
        }
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tracker.cancelled() => break,
            request = requests.recv() => {
                let Some(request) = request else { break };
                current = Some(request);
            }
            response = association.recv() => {
                let Ok((remote, payload)) = response else { break };
                let Some(remote) = resolve_udp_response_source(&remote, config.ipv6).await else {
                    continue;
                };
                if !send_shadowsocks_udp_reply(&inbound, peer, remote, &payload).await {
                    break;
                }
                downloaded = downloaded.saturating_add(payload.len() as u64);
                idle.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_TIMEOUT);
            }
            () = &mut idle => break,
        }
    }
    tracker.finish(uploaded, downloaded);
}

fn shadow_tls_server_config(config: &ShadowsocksShadowTlsConfig) -> ShadowTlsServerConfig {
    ShadowTlsServerConfig {
        version: config.version,
        password: config.password.clone().unwrap_or_default(),
        users: config
            .users
            .iter()
            .map(|user| (user.name.clone(), user.password.clone()))
            .collect(),
        handshake_dest: config.handshake.dest.clone(),
        strict_mode: config.strict_mode,
    }
}

/// Splits an inbound password into the server PSK and optional EIH user keys.
///
/// Single-hop EIH uses `server_key:user_key`. Extra `:`-separated segments become
/// additional users (AES-128/256 GCM only).
fn split_shadowsocks_inbound_password(password: &str) -> (String, Vec<String>) {
    let mut parts = password.split(':').map(str::to_owned).collect::<Vec<_>>();
    if parts.len() <= 1 {
        return (password.to_owned(), Vec::new());
    }
    let server_password = parts.remove(0);
    (server_password, parts)
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

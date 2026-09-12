use std::collections::BTreeMap;
use std::collections::hash_map::RandomState;
use std::future::pending;
use std::hash::BuildHasher;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rewrite_config::{Config, ListenerKind, ProxyKind};
use rewrite_model::{Destination, Host, Metadata};
use rewrite_rules::Route;
use rewrite_state::RuntimeState;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::tcp::{
    apply_host_mapping, configured_proxy, direct_tcp_options, mode_decision,
    resolve_proxy_dial_server, resolve_rematch_target, serve_connection,
};
use crate::types::LocalTcpListener;

async fn proxy_dial_server(
    proxy: &rewrite_config::ProxyConfig,
    config: &Config,
) -> Result<Destination, String> {
    resolve_proxy_dial_server(
        Destination {
            host: proxy
                .server
                .parse()
                .map_or_else(|_| Host::Domain(proxy.server.clone()), Host::Ip),
            port: proxy.port,
        },
        &config.hosts,
        config.dns.as_ref(),
        config.ipv6,
    )
    .await
}

/// Go tunnel `DefaultUDPTimeout` (equal to `DefaultTCPTimeout`): covers DNS,
/// TCP dial, carrier handshake (TLS/WS/WSS/gRPC), and protocol association,
/// including deferred WebSocket early-data upgrades on first write.
const UDP_SETUP_TIMEOUT: Duration = Duration::from_secs(5);

async fn await_udp_setup<T, E>(
    shutdown: &CancellationToken,
    work: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, String>
where
    E: std::fmt::Display,
{
    tokio::select! {
        () = shutdown.cancelled() => Err("UDP setup cancelled".to_owned()),
        result = tokio::time::timeout(UDP_SETUP_TIMEOUT, work) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(error.to_string()),
            Err(_) => Err("UDP setup timed out".to_owned()),
        }
    }
}

pub(super) async fn run_listener(
    kind: ListenerKind,
    listener: LocalTcpListener,
    udp: Option<Arc<UdpSocket>>,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let mut connections = JoinSet::new();
    let mut udp_sessions = UdpSessions::default();
    let mut datagram = vec![0_u8; 65_535];
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((client, _)) => {
                        let connection_config = Arc::clone(&config.borrow());
                        let connection_state = Arc::clone(&state);
                        let connection_dns_service = Arc::clone(&dns_service);
                        let connection_shutdown = shutdown.child_token();
                        connections.spawn(async move {
                            serve_connection(
                                client,
                                kind,
                                &connection_config,
                                &connection_state,
                                &connection_dns_service,
                                &connection_shutdown,
                            ).await;
                        });
                    }
                    Err(error) => {
                        state.log("error", format!("local listener failed: {error}"));
                        break;
                    }
                }
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(join_error)) = result {
                    state.log("error", format!("connection task failed: {join_error}"));
                }
            }
            result = udp_sessions.tasks.join_next(), if !udp_sessions.tasks.is_empty() => {
                udp_sessions.reap(result.as_ref());
            }
            received = receive_udp(udp.as_ref(), &mut datagram) => {
                if let Ok((length, source)) = received
                    && let Some(socket) = &udp
                {
                    let connection_config = Arc::clone(&config.borrow());
                    let Some(request) = prepare_udp_request(
                        &datagram[..length],
                        source,
                        socket.local_addr().map_or(0, |address| address.port()),
                        &connection_config,
                        &state,
                    ) else {
                        continue;
                    };
                    udp_sessions.dispatch(
                        source,
                        request,
                        UdpSessionContext::new(
                            UdpReplySink::Socks5(Arc::clone(socket)),
                            connection_config,
                            Arc::clone(&state),
                            Arc::clone(&dns_service),
                            shutdown.child_token(),
                        ),
                    );
                }
            }
        }
    }
    drop(listener);
    shutdown.cancel();
    while let Some(result) = connections.join_next().await {
        if let Err(join_error) = result {
            state.log(
                "error",
                format!("connection task failed during listener shutdown: {join_error}"),
            );
        }
    }
    udp_sessions.shutdown(&state).await;
}

pub(super) async fn receive_udp(
    socket: Option<&Arc<UdpSocket>>,
    buffer: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match socket {
        Some(socket) => socket.recv_from(buffer).await,
        None => pending().await,
    }
}

#[derive(Clone)]
pub(super) enum UdpReplySink {
    Socks5(Arc<UdpSocket>),
    Tun { tx: rewrite_tun::TunUdpReplyTx },
}

impl UdpReplySink {
    pub(super) async fn send_datagram(
        &self,
        session_peer: SocketAddr,
        remote: SocketAddr,
        payload: &[u8],
    ) -> std::io::Result<()> {
        match self {
            Self::Socks5(listener) => {
                let packet = rewrite_inbound::encode_socks5_udp(remote, payload);
                listener.send_to(&packet, session_peer).await.map(|_| ())
            }
            Self::Tun { tx } => match tx.try_send((payload.to_vec(), remote, session_peer)) {
                Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Ok(()),
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "TUN UDP reply channel closed",
                )),
            },
        }
    }
}

pub(super) struct UdpSessionPacket {
    metadata: Metadata,
    fake_host: Option<String>,
    payload: Vec<u8>,
    force_dns: bool,
}

impl UdpSessionPacket {
    pub(super) fn from_parts(
        metadata: Metadata,
        fake_host: Option<String>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            metadata,
            fake_host,
            payload,
            force_dns: false,
        }
    }

    pub(super) fn dns_hijack(
        metadata: Metadata,
        fake_host: Option<String>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            metadata,
            fake_host,
            payload,
            force_dns: true,
        }
    }
}

#[derive(Clone)]
pub(super) struct UdpSessionContext {
    reply: UdpReplySink,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
}

impl UdpSessionContext {
    pub(super) fn new(
        reply: UdpReplySink,
        config: Arc<Config>,
        state: Arc<RuntimeState>,
        dns_service: Arc<rewrite_dns::DnsService>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            reply,
            config,
            state,
            dns_service,
            shutdown,
        }
    }
}

#[derive(Clone)]
pub(super) enum UdpSessionMode {
    Direct,
    Dns,
    Socks5(String),
    Shadowsocks(String),
    ShadowsocksUot(String),
    ShadowsocksR(String),
    Vmess(String),
    Vless(String),
    Trojan(String),
    AnyTls(String),
    Hysteria2(String),
    Tuic(String),
    WireGuard(String),
}

#[derive(Default)]
pub(super) struct UdpSessions {
    pub(super) tasks: JoinSet<(SocketAddr, u64)>,
    entries: BTreeMap<SocketAddr, (u64, mpsc::Sender<UdpSessionPacket>)>,
    next_id: u64,
}

impl UdpSessions {
    pub(super) fn reap(
        &mut self,
        result: Option<&Result<(SocketAddr, u64), tokio::task::JoinError>>,
    ) {
        if let Some(Ok((source, session_id))) = result
            && self
                .entries
                .get(source)
                .is_some_and(|(current_id, _)| current_id == session_id)
        {
            self.entries.remove(source);
        }
    }

    pub(super) fn dispatch(
        &mut self,
        source: SocketAddr,
        request: UdpSessionPacket,
        context: UdpSessionContext,
    ) {
        if let Some((_, sender)) = self.entries.get(&source) {
            match sender.try_send(request) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    context.state.log("error", "UDP session queue is full");
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
        mut request: UdpSessionPacket,
        context: UdpSessionContext,
    ) {
        let decision = mode_decision(&context.config, &context.state)
            .unwrap_or_else(|| context.config.rules.evaluate(&request.metadata));
        let Some((decision, target, _)) = resolve_rematch_target(
            decision,
            &mut request.metadata,
            &context.config,
            &context.state,
        ) else {
            return;
        };
        let mode = if request.force_dns {
            UdpSessionMode::Dns
        } else {
            let Some(mode) = udp_session_mode(&target, &context.config) else {
                return;
            };
            mode
        };
        let session_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let (sender, receiver) = mpsc::channel(64);
        self.entries.insert(source, (session_id, sender));
        self.tasks.spawn(async move {
            Box::pin(run_udp_session(
                context.reply,
                source,
                request,
                receiver,
                context.config,
                context.state,
                context.dns_service,
                decision,
                mode,
                context.shutdown,
            ))
            .await;
            (source, session_id)
        });
    }

    pub(super) async fn shutdown(mut self, state: &RuntimeState) {
        self.entries.clear();
        while let Some(result) = self.tasks.join_next().await {
            if let Err(join_error) = result {
                state.log(
                    "error",
                    format!("UDP session task failed during listener shutdown: {join_error}"),
                );
            }
        }
    }

    #[must_use]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub(super) fn contains(&self, source: &SocketAddr) -> bool {
        self.entries.contains_key(source)
    }
}

pub(super) fn udp_session_mode(target: &str, config: &Config) -> Option<UdpSessionMode> {
    if matches!(target, "DIRECT" | "COMPATIBLE") {
        return Some(UdpSessionMode::Direct);
    }
    let proxy = configured_proxy(config, target)?;
    match proxy.kind {
        ProxyKind::Direct => Some(UdpSessionMode::Direct),
        ProxyKind::Dns => Some(UdpSessionMode::Dns),
        ProxyKind::Socks5 if proxy.udp => Some(UdpSessionMode::Socks5(target.to_owned())),
        ProxyKind::Shadowsocks if proxy.udp && proxy.udp_over_tcp => {
            Some(UdpSessionMode::ShadowsocksUot(target.to_owned()))
        }
        ProxyKind::Shadowsocks if proxy.udp => Some(UdpSessionMode::Shadowsocks(target.to_owned())),
        ProxyKind::ShadowsocksR if proxy.udp => {
            Some(UdpSessionMode::ShadowsocksR(target.to_owned()))
        }
        ProxyKind::Vmess if proxy.udp => Some(UdpSessionMode::Vmess(target.to_owned())),
        ProxyKind::Vless if proxy.udp => Some(UdpSessionMode::Vless(target.to_owned())),
        ProxyKind::Trojan if proxy.udp => Some(UdpSessionMode::Trojan(target.to_owned())),
        ProxyKind::AnyTls if proxy.udp => Some(UdpSessionMode::AnyTls(target.to_owned())),
        ProxyKind::Hysteria2 if proxy.udp => Some(UdpSessionMode::Hysteria2(target.to_owned())),
        ProxyKind::Tuic if proxy.udp => Some(UdpSessionMode::Tuic(target.to_owned())),
        ProxyKind::WireGuard if proxy.udp => Some(UdpSessionMode::WireGuard(target.to_owned())),
        ProxyKind::Http
        | ProxyKind::Socks5
        | ProxyKind::Shadowsocks
        | ProxyKind::ShadowsocksR
        | ProxyKind::Vmess
        | ProxyKind::Vless
        | ProxyKind::Trojan
        | ProxyKind::AnyTls
        | ProxyKind::Hysteria2
        | ProxyKind::Tuic
        | ProxyKind::WireGuard
        | ProxyKind::Reject
        | ProxyKind::Rematch => None,
    }
}

pub(super) fn resolved_route(target: &str, config: &Config) -> Route {
    match target {
        "DIRECT" | "COMPATIBLE" => Route::Direct,
        "REJECT" => Route::Reject,
        "REJECT-DROP" => Route::RejectDrop,
        _ => match configured_proxy(config, target).map(|proxy| proxy.kind) {
            Some(ProxyKind::Direct) => Route::Direct,
            Some(ProxyKind::Reject) => Route::Reject,
            _ => Route::Unsupported,
        },
    }
}

pub(super) fn prepare_udp_request(
    packet: &[u8],
    source: SocketAddr,
    inbound_port: u16,
    config: &Config,
    state: &Arc<RuntimeState>,
) -> Option<UdpSessionPacket> {
    let accepted = match rewrite_inbound::decode_socks5_udp(packet, source, inbound_port) {
        Ok(accepted) => accepted,
        Err(error) => {
            state.log("error", format!("SOCKS5 UDP packet rejected: {error}"));
            return None;
        }
    };
    let mut metadata = accepted.metadata.clone();
    // Both pinned default SOCKS and mixed UDP listeners are backed by the Go
    // SOCKS UDP listener and therefore expose DEFAULT-SOCKS, not DEFAULT-MIXED.
    "DEFAULT-SOCKS".clone_into(&mut metadata.inbound_name);
    let fake_host = apply_host_mapping(&mut metadata, config, state);
    Some(UdpSessionPacket {
        metadata,
        fake_host,
        payload: accepted.payload.to_vec(),
        force_dns: false,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_udp_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    decision: rewrite_rules::Decision,
    mode: UdpSessionMode,
    shutdown: CancellationToken,
) {
    match mode {
        UdpSessionMode::Direct => {
            run_direct_udp_session(
                reply, source, first, requests, config, state, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::Dns => {
            run_dns_udp_session(
                reply,
                source,
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
            run_socks5_udp_session(
                reply, source, first, requests, config, state, proxy, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::Shadowsocks(proxy) => {
            run_shadowsocks_udp_session(
                reply, source, first, requests, config, state, proxy, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::ShadowsocksUot(proxy) => {
            run_shadowsocks_uot_session(
                reply, source, first, requests, config, state, proxy, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::ShadowsocksR(proxy) => {
            run_ssr_udp_session(
                reply, source, first, requests, config, state, proxy, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::Vmess(proxy) => {
            Box::pin(run_vmess_udp_session(
                reply, source, first, requests, config, state, proxy, decision, shutdown,
            ))
            .await;
        }
        UdpSessionMode::Vless(proxy) => {
            Box::pin(run_vless_udp_session(
                reply, source, first, requests, config, state, proxy, decision, shutdown,
            ))
            .await;
        }
        UdpSessionMode::Trojan(proxy) => {
            run_trojan_udp_session(
                reply, source, first, requests, config, state, proxy, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::AnyTls(proxy) => {
            run_anytls_udp_session(
                reply, source, first, requests, config, state, proxy, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::Hysteria2(proxy) => {
            run_hysteria2_udp_session(
                reply, source, first, requests, config, state, proxy, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::Tuic(proxy) => {
            Box::pin(run_tuic_udp_session(
                reply, source, first, requests, config, state, proxy, decision, shutdown,
            ))
            .await;
        }
        UdpSessionMode::WireGuard(proxy) => {
            Box::pin(run_wireguard_udp_session(
                reply, source, first, requests, config, state, proxy, decision, shutdown,
            ))
            .await;
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn run_trojan_udp_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    proxy_name: String,
    decision: rewrite_rules::Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let Some(proxy) = configured_proxy(&config, &proxy_name) else {
        return;
    };
    let Some(trojan) = proxy.trojan.as_ref() else {
        return;
    };
    let server = match proxy_dial_server(proxy, &config).await {
        Ok(server) => server,
        Err(error) => {
            state.log(
                "error",
                format!("proxy-server DNS resolution failed: {error}"),
            );
            return;
        }
    };
    let Ok(initial_address) =
        resolve_udp_target(&first.metadata, first.fake_host.as_deref(), &config).await
    else {
        return;
    };
    let initial_destination = Destination {
        host: Host::Ip(initial_address.ip()),
        port: initial_address.port(),
    };
    let outer = match super::tcp::connect_trojan_outer(
        proxy,
        &server,
        trojan,
        config.ipv6,
        &state,
        &config.trust_certificates,
        direct_tcp_options(&config),
    )
    .await
    {
        Ok(outer) => outer,
        Err(error) => {
            state.log("error", format!("Trojan UDP carrier failed: {error}"));
            return;
        }
    };
    let mut association = rewrite_outbound::associate_trojan_udp_on_stream(
        outer,
        &initial_destination,
        &trojan.password,
    );
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
            let destination = udp_proxy_destination(&request);
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
                let Some(remote) = resolve_udp_response_source(&remote, &config).await else {
                    continue;
                };
                if reply.send_datagram(source, remote, &payload).await.is_err() {
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
pub(super) async fn run_anytls_udp_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    proxy_name: String,
    decision: rewrite_rules::Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let Some(proxy) = configured_proxy(&config, &proxy_name) else {
        return;
    };
    if proxy.anytls.is_none() {
        return;
    }
    let server = match proxy_dial_server(proxy, &config).await {
        Ok(server) => server,
        Err(error) => {
            state.log(
                "error",
                format!("proxy-server DNS resolution failed: {error}"),
            );
            return;
        }
    };
    let client = match super::tcp::anytls_client_for_proxy(
        proxy,
        &server,
        config.ipv6,
        &state,
        &config.trust_certificates,
        direct_tcp_options(&config),
    )
    .await
    {
        Ok(client) => client,
        Err(error) => {
            state.log("error", format!("AnyTLS UDP client failed: {error}"));
            return;
        }
    };
    let mut association = match rewrite_outbound::associate_anytls_udp(&client).await {
        Ok(association) => association,
        Err(error) => {
            state.log(
                "error",
                format!("AnyTLS UDP UoT association failed: {error}"),
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
            let destination = udp_proxy_destination(&request);
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
                let Some(remote) = resolve_udp_response_source(&remote, &config).await else {
                    continue;
                };
                if reply.send_datagram(source, remote, &payload).await.is_err() {
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
pub(super) async fn run_hysteria2_udp_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    proxy_name: String,
    decision: rewrite_rules::Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let Some(proxy) = configured_proxy(&config, &proxy_name).cloned() else {
        return;
    };
    if proxy.hysteria2.is_none() {
        return;
    }
    let client = match super::tcp::hysteria2_client_for_proxy(&proxy, &config, &state).await {
        Ok(client) => client,
        Err(error) => {
            state.log("error", format!("Hysteria2 UDP client failed: {error}"));
            return;
        }
    };
    let mut association = match rewrite_outbound::associate_hysteria2_udp(&client).await {
        Ok(association) => association,
        Err(error) => {
            state.log(
                "error",
                format!("Hysteria2 UDP association failed: {error}"),
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
            let destination = udp_proxy_destination(&request);
            if association.send(&destination, &request.payload).is_err() {
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
                let Some(remote) = resolve_udp_response_source(&remote, &config).await else {
                    continue;
                };
                if reply.send_datagram(source, remote, &payload).await.is_err() {
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
pub(super) async fn run_tuic_udp_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    proxy_name: String,
    decision: rewrite_rules::Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let Some(proxy) = configured_proxy(&config, &proxy_name).cloned() else {
        return;
    };
    if proxy.tuic.is_none() {
        return;
    }
    let setup = async {
        let client = super::tcp::tuic_client_for_proxy(&proxy, &config, &state).await?;
        rewrite_outbound::associate_tuic_udp(&client)
            .await
            .map_err(|error| format!("TUIC UDP association failed: {error}"))
    };
    let mut association = match await_udp_setup(&shutdown, setup).await {
        Ok(association) => association,
        Err(error) => {
            state.log("error", format!("TUIC UDP setup failed: {error}"));
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
            let destination = udp_proxy_destination(&request);
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = tracker.cancelled() => break,
                () = &mut idle => break,
                result = association.send(&destination, &request.payload) => {
                    if result.is_err() {
                        break;
                    }
                    uploaded = uploaded.saturating_add(request.payload.len() as u64);
                    idle.as_mut()
                        .reset(tokio::time::Instant::now() + UDP_SESSION_TIMEOUT);
                }
            }
            continue;
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
                let Some(remote) = resolve_udp_response_source(&remote, &config).await else {
                    continue;
                };
                if reply.send_datagram(source, remote, &payload).await.is_err() {
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
pub(super) async fn run_wireguard_udp_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    proxy_name: String,
    decision: rewrite_rules::Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let Some(proxy) = configured_proxy(&config, &proxy_name).cloned() else {
        return;
    };
    if proxy.wireguard.is_none() {
        return;
    }
    let setup = async {
        let client = super::tcp::wireguard_client_for_proxy(&proxy, &config, &state).await?;
        let association = rewrite_outbound::associate_wireguard_udp(&client)
            .await
            .map_err(|error| format!("WireGuard UDP association failed: {error}"))?;
        Ok::<_, String>((client, association))
    };
    let (client, mut association) = match await_udp_setup(&shutdown, setup).await {
        Ok(ready) => ready,
        Err(error) => {
            state.log("error", format!("WireGuard UDP setup failed: {error}"));
            return;
        }
    };
    let tracker = state.register(
        &first.metadata,
        &decision.target,
        decision.matched_kind.as_deref(),
    );
    let mut generation = state.subscribe_network_generation();
    let mut uploaded = 0_u64;
    let mut downloaded = 0_u64;
    let idle = tokio::time::sleep(UDP_SESSION_TIMEOUT);
    tokio::pin!(idle);
    let mut current = Some(first);
    loop {
        if let Some(request) = current.take() {
            let destination = udp_proxy_destination(&request);
            let destination =
                match super::tcp::resolve_wireguard_destination(&client, &destination, &config)
                    .await
                {
                    Ok(destination) => destination,
                    Err(error) => {
                        state.log(
                            "error",
                            format!("WireGuard UDP destination failed: {error}"),
                        );
                        break;
                    }
                };
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = tracker.cancelled() => break,
                _ = generation.changed() => break,
                () = &mut idle => break,
                result = association.send(&destination, &request.payload) => {
                    if result.is_err() {
                        break;
                    }
                    uploaded = uploaded.saturating_add(request.payload.len() as u64);
                    idle.as_mut()
                        .reset(tokio::time::Instant::now() + UDP_SESSION_TIMEOUT);
                }
            }
            continue;
        }
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tracker.cancelled() => break,
            _ = generation.changed() => break,
            request = requests.recv() => {
                let Some(request) = request else { break };
                current = Some(request);
            }
            response = association.recv() => {
                let Ok((remote, payload)) = response else { break };
                let Some(remote) = resolve_udp_response_source(&remote, &config).await else {
                    continue;
                };
                if reply.send_datagram(source, remote, &payload).await.is_err() {
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_direct_udp_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    decision: rewrite_rules::Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let target =
        match resolve_udp_target(&first.metadata, first.fake_host.as_deref(), &config).await {
            Ok(target) => target,
            Err(error) => {
                state.log("error", format!("DIRECT UDP resolution failed: {error}"));
                return;
            }
        };
    let mut outbound = match bind_direct_udp_socket(target, &config) {
        Ok(socket) => socket,
        Err(error) => {
            state.log("error", format!("DIRECT UDP bind failed: {error}"));
            return;
        }
    };
    let mut generation = state.subscribe_network_generation();
    let tracker = state.register(
        &first.metadata,
        &decision.target,
        decision.matched_kind.as_deref(),
    );
    let mut uploaded = 0_u64;
    let mut downloaded = 0_u64;
    if outbound.send_to(&first.payload, target).await.is_err() {
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
            changed = generation.changed() => {
                if changed.is_err() {
                    break;
                }
                match bind_direct_udp_socket(target, &config) {
                    Ok(socket) => outbound = socket,
                    Err(error) => {
                        state.log("error", format!("DIRECT UDP rebind failed: {error}"));
                        break;
                    }
                }
                idle.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_TIMEOUT);
            }
            request = requests.recv() => {
                let Some(request) = request else { break };
                let target = match resolve_udp_target(
                    &request.metadata,
                    request.fake_host.as_deref(),
                    &config,
                ).await {
                    Ok(target) => target,
                    Err(error) => {
                        state.log("error", format!("DIRECT UDP resolution failed: {error}"));
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
                if reply.send_datagram(source, remote, &response[..length]).await.is_err() {
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

fn bind_direct_udp_socket(target: SocketAddr, config: &Config) -> std::io::Result<UdpSocket> {
    let family: SocketAddr = if target.is_ipv6() {
        "[::]:0".parse().expect("static IPv6 wildcard")
    } else {
        "0.0.0.0:0".parse().expect("static IPv4 wildcard")
    };
    rewrite_platform::bind_outbound_udp(family, target, &config.interface_name, config.routing_mark)
        .and_then(UdpSocket::from_std)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_dns_udp_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    decision: rewrite_rules::Decision,
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
            if let Ok(response) = dns_service
                .relay_query(&config, &state, &request.payload)
                .await
            {
                let remote = dns_adapter_response_addr(&request.metadata);
                if reply
                    .send_datagram(source, remote, &response)
                    .await
                    .is_err()
                {
                    break;
                }
                downloaded = downloaded.saturating_add(response.len() as u64);
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

pub(super) fn dns_adapter_response_addr(metadata: &Metadata) -> SocketAddr {
    let address = match metadata.destination.host {
        Host::Ip(address) => address,
        Host::Domain(_) => "127.0.0.2".parse().expect("static DNS adapter address"),
    };
    SocketAddr::new(address, metadata.destination.port)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn run_socks5_udp_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    proxy_name: String,
    decision: rewrite_rules::Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let Some(proxy) = configured_proxy(&config, &proxy_name) else {
        return;
    };
    let server = match proxy_dial_server(proxy, &config).await {
        Ok(server) => server,
        Err(error) => {
            state.log(
                "error",
                format!("proxy-server DNS resolution failed: {error}"),
            );
            return;
        }
    };
    let tls = proxy.tls.then_some(rewrite_outbound::HttpProxyTls {
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
            state.log("error", format!("SOCKS5 UDP association failed: {error}"));
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
            let destination =
                match resolve_udp_target(&request.metadata, request.fake_host.as_deref(), &config)
                    .await
                {
                    Ok(destination) => Destination {
                        host: Host::Ip(destination.ip()),
                        port: destination.port(),
                    },
                    Err(_) => break,
                };
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
                let Some(remote) = resolve_udp_response_source(&remote, &config).await else {
                    continue;
                };
                if reply.send_datagram(source, remote, &payload).await.is_err() {
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
pub(super) async fn run_shadowsocks_udp_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    proxy_name: String,
    decision: rewrite_rules::Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let Some(proxy) = configured_proxy(&config, &proxy_name) else {
        return;
    };
    let server = match proxy_dial_server(proxy, &config).await {
        Ok(server) => server,
        Err(error) => {
            state.log(
                "error",
                format!("proxy-server DNS resolution failed: {error}"),
            );
            return;
        }
    };
    let password = proxy.password.clone().unwrap_or_default();
    let cipher = proxy.cipher.clone().unwrap_or_default();
    let mut association = match rewrite_outbound::associate_shadowsocks_udp_with_options(
        &server,
        config.ipv6,
        &password,
        &cipher,
        direct_tcp_options(&config),
    )
    .await
    {
        Ok(association) => association,
        Err(error) => {
            state.log(
                "error",
                format!("Shadowsocks UDP association failed: {error}"),
            );
            return;
        }
    };
    let mut generation = state.subscribe_network_generation();

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
            let destination = udp_proxy_destination(&request);
            if matches!(destination.host, Host::Ip(address) if address.is_ipv6() && !config.ipv6) {
                break;
            }
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
            changed = generation.changed() => {
                if changed.is_err() {
                    break;
                }
                match rewrite_outbound::associate_shadowsocks_udp_with_options(
                    &server,
                    config.ipv6,
                    &password,
                    &cipher,
                    direct_tcp_options(&config),
                )
                .await
                {
                    Ok(next) => association = next,
                    Err(error) => {
                        state.log(
                            "error",
                            format!("Shadowsocks UDP rebind failed: {error}"),
                        );
                        break;
                    }
                }
                idle.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_TIMEOUT);
            }
            response = association.recv() => {
                let Ok((remote, payload)) = response else { break };
                let Some(remote) = resolve_udp_response_source(&remote, &config).await else {
                    continue;
                };
                if reply.send_datagram(source, remote, &payload).await.is_err() {
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_ssr_udp_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    proxy_name: String,
    decision: rewrite_rules::Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let Some(proxy) = configured_proxy(&config, &proxy_name) else {
        return;
    };
    let Some(ssr) = proxy.ssr.as_ref() else {
        return;
    };
    let server = match proxy_dial_server(proxy, &config).await {
        Ok(server) => server,
        Err(error) => {
            state.log(
                "error",
                format!("ShadowsocksR UDP association failed: {error}"),
            );
            return;
        }
    };
    let mut association = match rewrite_outbound::associate_ssr_udp_with_options(
        &server,
        config.ipv6,
        proxy.password.as_deref().unwrap_or_default(),
        proxy.cipher.as_deref().unwrap_or_default(),
        &ssr.protocol,
        &ssr.protocol_param,
        &ssr.obfs,
        &ssr.obfs_param,
        &proxy.server,
        direct_tcp_options(&config),
    )
    .await
    {
        Ok(association) => association,
        Err(error) => {
            state.log(
                "error",
                format!("ShadowsocksR UDP association failed: {error}"),
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
            let destination = udp_proxy_destination(&request);
            if matches!(destination.host, Host::Ip(address) if address.is_ipv6() && !config.ipv6) {
                break;
            }
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
                let Some(remote) = resolve_udp_response_source(&remote, &config).await else {
                    continue;
                };
                if reply.send_datagram(source, remote, &payload).await.is_err() {
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
pub(super) async fn run_shadowsocks_uot_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    proxy_name: String,
    decision: rewrite_rules::Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let Some(proxy) = configured_proxy(&config, &proxy_name) else {
        return;
    };
    let server = match proxy_dial_server(proxy, &config).await {
        Ok(server) => server,
        Err(error) => {
            state.log(
                "error",
                format!("proxy-server DNS resolution failed: {error}"),
            );
            return;
        }
    };
    let mut association = match rewrite_outbound::associate_shadowsocks_uot_with_options(
        &server,
        config.ipv6,
        proxy.password.as_deref().unwrap_or_default(),
        proxy.cipher.as_deref().unwrap_or_default(),
        proxy.udp_over_tcp_version,
        direct_tcp_options(&config),
    )
    .await
    {
        Ok(association) => association,
        Err(error) => {
            state.log(
                "error",
                format!("Shadowsocks UoT association failed: {error}"),
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
            let destination =
                match resolve_udp_target(&request.metadata, request.fake_host.as_deref(), &config)
                    .await
                {
                    Ok(address) => Destination {
                        host: Host::Ip(address.ip()),
                        port: address.port(),
                    },
                    Err(_) => break,
                };
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
                let Some(remote) = resolve_udp_response_source(&remote, &config).await else {
                    continue;
                };
                if reply.send_datagram(source, remote, &payload).await.is_err() {
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
pub(super) async fn run_vmess_udp_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    proxy_name: String,
    decision: rewrite_rules::Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let Some(proxy) = configured_proxy(&config, &proxy_name) else {
        return;
    };
    let Some(vmess) = proxy.vmess.as_ref() else {
        return;
    };
    let security = match vmess.security {
        rewrite_config::VmessSecurity::Auto => rewrite_outbound::VmessSecurity::Auto,
        rewrite_config::VmessSecurity::None => rewrite_outbound::VmessSecurity::None,
        rewrite_config::VmessSecurity::Aes128Cfb => rewrite_outbound::VmessSecurity::Aes128Cfb,
        rewrite_config::VmessSecurity::Aes128Gcm => rewrite_outbound::VmessSecurity::Aes128Gcm,
        rewrite_config::VmessSecurity::ChaCha20Poly1305 => {
            rewrite_outbound::VmessSecurity::ChaCha20Poly1305
        }
    };
    let packet_mode = match vmess.packet_mode {
        rewrite_config::VmessPacketMode::Standard => rewrite_outbound::VmessPacketMode::Standard,
        rewrite_config::VmessPacketMode::PacketAddr => {
            rewrite_outbound::VmessPacketMode::PacketAddr
        }
        rewrite_config::VmessPacketMode::Xudp => rewrite_outbound::VmessPacketMode::Xudp,
    };
    let setup = async {
        let server = proxy_dial_server(proxy, &config).await?;
        let initial_address =
            resolve_udp_target(&first.metadata, first.fake_host.as_deref(), &config)
                .await
                .map_err(|error| error.to_string())?;
        let initial_destination = Destination {
            host: Host::Ip(initial_address.ip()),
            port: initial_address.port(),
        };
        let outer = super::tcp::connect_vmess_carrier(
            proxy,
            &server,
            vmess,
            config.ipv6,
            &state,
            &config.trust_certificates,
            direct_tcp_options(&config),
        )
        .await?;
        rewrite_outbound::associate_vmess_udp_on_stream(
            outer,
            &initial_destination,
            rewrite_outbound::VmessTcpOptions {
                uuid: vmess.uuid,
                alter_id: vmess.alter_id,
                security,
                global_padding: vmess.global_padding,
                authenticated_length: vmess.authenticated_length,
            },
            packet_mode,
        )
        .await
        .map_err(|error| format!("VMess UDP association failed: {error}"))
    };
    let mut association = match await_udp_setup(&shutdown, setup).await {
        Ok(association) => association,
        Err(error) => {
            state.log("error", format!("VMess UDP setup failed: {error}"));
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
            let destination =
                match resolve_udp_target(&request.metadata, request.fake_host.as_deref(), &config)
                    .await
                {
                    Ok(address) => Destination {
                        host: Host::Ip(address.ip()),
                        port: address.port(),
                    },
                    Err(_) => break,
                };
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
                let Some(remote) = resolve_udp_response_source(&remote, &config).await else {
                    continue;
                };
                if reply.send_datagram(source, remote, &payload).await.is_err() {
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
pub(super) async fn run_vless_udp_session(
    reply: UdpReplySink,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    proxy_name: String,
    decision: rewrite_rules::Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let Some(proxy) = configured_proxy(&config, &proxy_name) else {
        return;
    };
    let Some(vless) = proxy.vless.as_ref() else {
        return;
    };
    let packet_mode = match vless.packet_mode {
        rewrite_config::VlessPacketMode::Standard => rewrite_outbound::VlessPacketMode::Standard,
        rewrite_config::VlessPacketMode::PacketAddr => {
            rewrite_outbound::VlessPacketMode::PacketAddr
        }
        rewrite_config::VlessPacketMode::Xudp => rewrite_outbound::VlessPacketMode::Xudp,
    };
    let setup = async {
        let server = proxy_dial_server(proxy, &config).await?;
        let initial_address =
            resolve_udp_target(&first.metadata, first.fake_host.as_deref(), &config)
                .await
                .map_err(|error| error.to_string())?;
        let initial_destination = Destination {
            host: Host::Ip(initial_address.ip()),
            port: initial_address.port(),
        };
        let (outer, vision_control) = super::tcp::connect_vless_outer(
            proxy,
            &server,
            vless,
            config.ipv6,
            &state,
            &config.trust_certificates,
            direct_tcp_options(&config),
        )
        .await?;
        debug_assert!(vision_control.is_none());
        rewrite_outbound::associate_vless_udp_on_stream(
            outer,
            &initial_destination,
            rewrite_outbound::VlessTcpOptions {
                uuid: vless.uuid,
                flow: vless.flow.map(|flow| match flow {
                    rewrite_config::VlessFlow::XtlsRprxVision => {
                        rewrite_outbound::VlessFlow::XtlsRprxVision
                    }
                }),
            },
            packet_mode,
            vless_xudp_global_id(source),
        )
        .await
        .map_err(|error| format!("VLESS UDP association failed: {error}"))
    };
    let mut association = match await_udp_setup(&shutdown, setup).await {
        Ok(association) => association,
        Err(error) => {
            state.log("error", format!("VLESS UDP setup failed: {error}"));
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
            let destination =
                match resolve_udp_target(&request.metadata, request.fake_host.as_deref(), &config)
                    .await
                {
                    Ok(address) => Destination {
                        host: Host::Ip(address.ip()),
                        port: address.port(),
                    },
                    Err(_) => break,
                };
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
                let Some(remote) = resolve_udp_response_source(&remote, &config).await else {
                    continue;
                };
                if reply.send_datagram(source, remote, &payload).await.is_err() {
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

fn vless_xudp_global_id(source: SocketAddr) -> [u8; 8] {
    static HASHER: OnceLock<RandomState> = OnceLock::new();
    HASHER
        .get_or_init(RandomState::new)
        .hash_one(source.to_string())
        .to_ne_bytes()
}

fn udp_proxy_destination(request: &UdpSessionPacket) -> Destination {
    request.fake_host.as_ref().map_or_else(
        || request.metadata.destination.clone(),
        |host| Destination {
            host: Host::Domain(host.clone()),
            port: request.metadata.destination.port,
        },
    )
}

pub(super) async fn resolve_udp_response_source(
    destination: &Destination,
    config: &Config,
) -> Option<SocketAddr> {
    match &destination.host {
        Host::Ip(address) => {
            if address.is_ipv6() && !config.ipv6 {
                return None;
            }
            Some(SocketAddr::new(*address, destination.port))
        }
        Host::Domain(host) => {
            if let Some(dns) = config.dns.as_ref() {
                return rewrite_dns::resolve_domain(dns, host, config.ipv6)
                    .await
                    .ok()
                    .map(|address| SocketAddr::new(address, destination.port));
            }
            tokio::net::lookup_host((host.as_str(), destination.port))
                .await
                .ok()?
                .find(|address| config.ipv6 || address.is_ipv4())
        }
    }
}

pub(super) async fn resolve_udp_target(
    metadata: &Metadata,
    fake_host: Option<&str>,
    config: &Config,
) -> std::io::Result<SocketAddr> {
    if let Some(host) = fake_host
        && let Some(dns) = config.dns.as_ref()
    {
        return rewrite_dns::resolve_domain(dns, host, config.ipv6)
            .await
            .map(|address| SocketAddr::new(address, metadata.destination.port))
            .map_err(std::io::Error::other);
    }
    match &metadata.destination.host {
        Host::Ip(address) => {
            if address.is_ipv6() && !config.ipv6 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "IPv6 is disabled",
                ));
            }
            Ok(SocketAddr::new(*address, metadata.destination.port))
        }
        Host::Domain(domain) => {
            if let Some(dns) = config.dns.as_ref() {
                return rewrite_dns::resolve_domain(dns, domain, config.ipv6)
                    .await
                    .map(|address| SocketAddr::new(address, metadata.destination.port))
                    .map_err(std::io::Error::other);
            }
            tokio::net::lookup_host((domain.as_str(), metadata.destination.port))
                .await?
                .find(|address| config.ipv6 || address.is_ipv4())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "no permitted UDP address resolved",
                    )
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::vless_xudp_global_id;

    #[test]
    fn vless_xudp_id_is_stable_per_source() {
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12000);
        assert_eq!(vless_xudp_global_id(first), vless_xudp_global_id(first));
    }
}

use std::collections::BTreeMap;
use std::future::pending;
use std::net::SocketAddr;
use std::sync::Arc;
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
    resolve_rematch_target, serve_connection,
};
use crate::types::LocalTcpListener;

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
                        UdpSessionContext {
                            listener: Arc::clone(socket),
                            config: connection_config,
                            state: Arc::clone(&state),
                            dns_service: Arc::clone(&dns_service),
                            shutdown: shutdown.child_token(),
                        },
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

pub(super) struct UdpSessionPacket {
    metadata: Metadata,
    fake_host: Option<String>,
    payload: Vec<u8>,
}

#[derive(Clone)]
pub(super) struct UdpSessionContext {
    listener: Arc<UdpSocket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
}

#[derive(Clone)]
pub(super) enum UdpSessionMode {
    Direct,
    Dns,
    Socks5(String),
    Shadowsocks(String),
    ShadowsocksUot(String),
}

#[derive(Default)]
pub(super) struct UdpSessions {
    tasks: JoinSet<(SocketAddr, u64)>,
    entries: BTreeMap<SocketAddr, (u64, mpsc::Sender<UdpSessionPacket>)>,
    next_id: u64,
}

impl UdpSessions {
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
        request: UdpSessionPacket,
        context: UdpSessionContext,
    ) {
        if let Some((_, sender)) = self.entries.get(&source) {
            match sender.try_send(request) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    context
                        .state
                        .log("error", "SOCKS5 UDP session queue is full");
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
        let Some(mode) = udp_session_mode(&target, &context.config) else {
            return;
        };
        let session_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let (sender, receiver) = mpsc::channel(64);
        self.entries.insert(source, (session_id, sender));
        self.tasks.spawn(async move {
            run_udp_session(
                context.listener,
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
                    format!("UDP session task failed during listener shutdown: {join_error}"),
                );
            }
        }
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
        ProxyKind::Http
        | ProxyKind::Socks5
        | ProxyKind::Shadowsocks
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
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_udp_session(
    listener: Arc<UdpSocket>,
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
                listener, source, first, requests, config, state, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::Dns => {
            run_dns_udp_session(
                listener,
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
                listener, source, first, requests, config, state, proxy, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::Shadowsocks(proxy) => {
            run_shadowsocks_udp_session(
                listener, source, first, requests, config, state, proxy, decision, shutdown,
            )
            .await;
        }
        UdpSessionMode::ShadowsocksUot(proxy) => {
            run_shadowsocks_uot_session(
                listener, source, first, requests, config, state, proxy, decision, shutdown,
            )
            .await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_direct_udp_session(
    listener: Arc<UdpSocket>,
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
    let family: SocketAddr = if target.is_ipv6() {
        "[::]:0".parse().expect("static IPv6 wildcard")
    } else {
        "0.0.0.0:0".parse().expect("static IPv4 wildcard")
    };
    let outbound = match rewrite_platform::bind_outbound_udp(
        family,
        &config.interface_name,
        config.routing_mark,
    )
    .and_then(UdpSocket::from_std)
    {
        Ok(socket) => socket,
        Err(error) => {
            state.log("error", format!("DIRECT UDP bind failed: {error}"));
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
                let packet = rewrite_inbound::encode_socks5_udp(remote, &response[..length]);
                if listener.send_to(&packet, source).await.is_err() {
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
pub(super) async fn run_dns_udp_session(
    listener: Arc<UdpSocket>,
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
                let packet = rewrite_inbound::encode_socks5_udp(remote, &response);
                if listener.send_to(&packet, source).await.is_err() {
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
    listener: Arc<UdpSocket>,
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
    let server = Destination {
        host: proxy
            .server
            .parse()
            .map_or_else(|_| Host::Domain(proxy.server.clone()), Host::Ip),
        port: proxy.port,
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
        client_hello_fingerprint: None,
        client_hello_fingerprint_mlkem: true,
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
                let Some(remote) = resolve_udp_response_source(&remote, config.ipv6).await else {
                    continue;
                };
                let packet = rewrite_inbound::encode_socks5_udp(remote, &payload);
                if listener.send_to(&packet, source).await.is_err() {
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
    listener: Arc<UdpSocket>,
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
                format!("Shadowsocks UDP association failed: {error}"),
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
                let Some(remote) = resolve_udp_response_source(&remote, config.ipv6).await else {
                    continue;
                };
                let packet = rewrite_inbound::encode_socks5_udp(remote, &payload);
                if listener.send_to(&packet, source).await.is_err() {
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
    listener: Arc<UdpSocket>,
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
    let server = Destination {
        host: proxy
            .server
            .parse()
            .map_or_else(|_| Host::Domain(proxy.server.clone()), Host::Ip),
        port: proxy.port,
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
                let Some(remote) = resolve_udp_response_source(&remote, config.ipv6).await else {
                    continue;
                };
                let packet = rewrite_inbound::encode_socks5_udp(remote, &payload);
                if listener.send_to(&packet, source).await.is_err() {
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
    allow_ipv6: bool,
) -> Option<SocketAddr> {
    match destination.host {
        Host::Ip(address) => Some(SocketAddr::new(address, destination.port)),
        Host::Domain(ref host) => tokio::net::lookup_host((host.as_str(), destination.port))
            .await
            .ok()?
            .find(|address| allow_ipv6 || address.is_ipv4()),
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

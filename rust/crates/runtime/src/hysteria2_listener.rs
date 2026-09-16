//! Named `type: hysteria2` QUIC inbound (IN-F first slice).
//!
//! Protocol crate owns HTTP/3 auth + TCP/UDP wire Accept; this module owns
//! listen, caps, route, and relay into the shared stream/UDP boundaries.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use bytes::Bytes;
use rewrite_config::{Config, Hysteria2InboundConfig};
use rewrite_inbound::BoxedInboundStream;
use rewrite_model::{Destination, Host, InboundProtocol, Metadata, Network, unmap_ip};
use rewrite_protocol_hysteria2::{
    Defragger, Hysteria2ServerStream, MAX_DATAGRAM_FRAME_SIZE, ServerAuthOptions,
    ServerEndpointOptions, UdpMessage, accept_tcp_request, authenticate_incoming,
    bind_server_endpoint, frag_udp_message, load_pem_or_path, password_user_table,
};
use rewrite_rules::Route;
use rewrite_state::RuntimeState;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::listener::{UdpSessionMode, resolve_udp_target, resolved_route, udp_session_mode};
use crate::tcp::{
    apply_host_mapping, mode_decision, resolve_rematch_target, serve_shadowsocks_connection,
};
use crate::types::RuntimeError;

const HY2_MAX_INBOUND_CONNECTIONS: usize = 1024;
const HY2_MAX_STREAMS_PER_CONN: usize = 256;
const HY2_MAX_UDP_SESSIONS: usize = 256;
const HY2_UDP_SESSION_CHAN: usize = 1024;
const HY2_UDP_CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const HY2_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const HY2_TCP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const HY2_UDP_SESSION_IDLE: Duration = Duration::from_secs(60);
const HY2_UDP_IDLE_SWEEP: Duration = Duration::from_secs(10);
const HY2_UDP_MTU: usize = 1197;

/// One Hy2 UDP session: client datagram channel, idle clock, cancel token, and
/// a generation id so a retiring worker cannot wipe a recreated same-ID slot.
struct Hy2UdpSessionSlot {
    tx: mpsc::Sender<UdpMessage>,
    last_used: Instant,
    cancel: CancellationToken,
    generation: u64,
}

/// Remove `session_id` only when the map still holds `generation` (this worker's
/// instance). Prevents an evicted worker from deleting a recreated slot.
async fn remove_udp_session_if_owner(
    sessions: &tokio::sync::Mutex<HashMap<u32, Hy2UdpSessionSlot>>,
    defrag_by_session: &tokio::sync::Mutex<HashMap<u32, Defragger>>,
    session_id: u32,
    generation: u64,
) {
    let mut sessions = sessions.lock().await;
    let is_owner = sessions
        .get(&session_id)
        .is_some_and(|slot| slot.generation == generation);
    if !is_owner {
        return;
    }
    sessions.remove(&session_id);
    drop(sessions);
    defrag_by_session.lock().await.remove(&session_id);
}

/// Refresh idle clock when this generation still owns the slot.
fn touch_udp_session(
    sessions: &mut HashMap<u32, Hy2UdpSessionSlot>,
    session_id: u32,
    generation: u64,
) {
    if let Some(slot) = sessions.get_mut(&session_id) {
        if slot.generation == generation {
            slot.last_used = Instant::now();
        }
    }
}

/// Feed a datagram into the per-session defragger, capping orphan entries at
/// `HY2_MAX_UDP_SESSIONS`. When full, retain only sessions that still have a
/// live slot; if still full, drop the fragment without inserting.
fn try_feed_defrag(
    defrag_by_session: &mut HashMap<u32, Defragger>,
    live_sessions: &HashMap<u32, Hy2UdpSessionSlot>,
    message: UdpMessage,
) -> Option<UdpMessage> {
    let session_id = message.session_id;
    if !defrag_by_session.contains_key(&session_id)
        && defrag_by_session.len() >= HY2_MAX_UDP_SESSIONS
    {
        defrag_by_session.retain(|id, _| live_sessions.contains_key(id));
        if defrag_by_session.len() >= HY2_MAX_UDP_SESSIONS {
            return None;
        }
    }
    defrag_by_session
        .entry(session_id)
        .or_default()
        .feed(message)
}

/// Cancel and remove UDP sessions idle longer than `max_idle`, and drop their
/// defrag entries.
fn evict_idle_udp_sessions(
    sessions: &mut HashMap<u32, Hy2UdpSessionSlot>,
    defrag_by_session: &mut HashMap<u32, Defragger>,
    max_idle: Duration,
) {
    let now = Instant::now();
    let idle: Vec<u32> = sessions
        .iter()
        .filter(|(_, slot)| now.duration_since(slot.last_used) > max_idle)
        .map(|(session_id, _)| *session_id)
        .collect();
    for session_id in idle {
        if let Some(slot) = sessions.remove(&session_id) {
            slot.cancel.cancel();
        }
        defrag_by_session.remove(&session_id);
    }
}

pub(crate) struct Hysteria2Listener {
    endpoint: quinn::Endpoint,
    users: HashMap<String, String>,
    inbound_name: String,
    listen: SocketAddr,
}

impl Hysteria2Listener {
    pub(crate) async fn bind(config: &Hysteria2InboundConfig) -> Result<Self, RuntimeError> {
        let certificate = load_pem_or_path(&config.certificate)
            .map_err(|error| RuntimeError::Listener(std::io::Error::other(error.to_string())))?;
        let private_key = load_pem_or_path(&config.private_key)
            .map_err(|error| RuntimeError::Listener(std::io::Error::other(error.to_string())))?;
        let alpn = if config.alpn.is_empty() {
            vec!["h3".to_owned()]
        } else {
            config.alpn.clone()
        };
        let endpoint = bind_server_endpoint(&ServerEndpointOptions {
            listen: config.listen,
            certificate_pem: certificate,
            private_key_pem: private_key,
            alpn,
            salamander_password: config.obfs_password.clone().unwrap_or_default(),
            max_concurrent_bidi_streams: u32::try_from(HY2_MAX_STREAMS_PER_CONN)
                .unwrap_or(u32::MAX),
            ..ServerEndpointOptions::default()
        })
        .map_err(|error| RuntimeError::Listener(std::io::Error::other(error.to_string())))?;
        Ok(Self {
            endpoint,
            users: password_user_table(
                config
                    .users
                    .iter()
                    .map(|user| (user.username.clone(), user.password.clone())),
            ),
            inbound_name: config.name.clone(),
            listen: config.listen,
        })
    }
}

struct Hysteria2InboundStream {
    inner: Hysteria2ServerStream,
    local: SocketAddr,
    peer: SocketAddr,
}

impl Hysteria2InboundStream {
    fn new(inner: Hysteria2ServerStream, local: SocketAddr, peer: SocketAddr) -> Self {
        Self { inner, local, peer }
    }
}

impl AsyncRead for Hysteria2InboundStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hysteria2InboundStream {
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

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl rewrite_inbound::InboundStream for Hysteria2InboundStream {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer)
    }
}

pub(super) async fn run_hysteria2_listener(
    listener: Hysteria2Listener,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let Hysteria2Listener {
        endpoint,
        users,
        inbound_name,
        listen,
    } = listener;
    let active = Arc::new(AtomicUsize::new(0));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    state.log("error", "hysteria2 inbound accept ended");
                    break;
                };
                let connection_config = Arc::clone(&*config.borrow());
                let peer = incoming.remote_address();
                if !connection_config.permits_inbound(peer.ip()) {
                    incoming.ignore();
                    continue;
                }
                if active.load(Ordering::Relaxed) >= HY2_MAX_INBOUND_CONNECTIONS {
                    state.log(
                        "warning",
                        format!(
                            "hysteria2 inbound connection limit reached ({HY2_MAX_INBOUND_CONNECTIONS})"
                        ),
                    );
                    incoming.refuse();
                    continue;
                }
                let users = users.clone();
                let connection_state = Arc::clone(&state);
                let connection_dns = Arc::clone(&dns_service);
                let connection_shutdown = shutdown.child_token();
                let connection_inbound_name = inbound_name.clone();
                let connection_active = Arc::clone(&active);
                let local = endpoint.local_addr().unwrap_or(listen);
                connection_active.fetch_add(1, Ordering::Relaxed);
                connections.spawn(async move {
                    let _guard = ConnectionGuard(connection_active);
                    let connection = match incoming.await {
                        Ok(connection) => connection,
                        Err(_) => return,
                    };
                    handle_hysteria2_connection(
                        connection,
                        peer,
                        local,
                        users,
                        connection_inbound_name,
                        connection_config,
                        connection_state,
                        connection_dns,
                        connection_shutdown,
                    )
                    .await;
                });
            }
            Some(_) = connections.join_next() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    endpoint.close(0_u32.into(), b"listener shutdown");
}

struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_hysteria2_connection(
    connection: quinn::Connection,
    peer: SocketAddr,
    local: SocketAddr,
    users: HashMap<String, String>,
    inbound_name: String,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let authenticated = tokio::select! {
        () = shutdown.cancelled() => return,
        result = tokio::time::timeout(
            HY2_AUTH_TIMEOUT,
            authenticate_incoming(
                connection.clone(),
                &users,
                ServerAuthOptions::default(),
            ),
        ) => result,
    };
    let Ok(Ok(authenticated)) = authenticated else {
        return;
    };
    // Must outlive TCP/UDP: h3 Connection Drop closes Quinn with H3_NO_ERROR.
    let _h3_guard = authenticated.h3_guard;
    let auth = authenticated.result;

    let mut streams = JoinSet::new();
    let udp_enabled = auth.udp_enabled;
    let username = auth.username;
    let udp_shutdown = shutdown.child_token();
    let udp_task = if udp_enabled {
        let udp_connection = connection.clone();
        let udp_config = Arc::clone(&config);
        let udp_state = Arc::clone(&state);
        let udp_inbound_name = inbound_name.clone();
        let udp_username = username.clone();
        Some(tokio::spawn(async move {
            serve_hysteria2_udp(
                udp_connection,
                peer,
                local,
                udp_username,
                udp_inbound_name,
                udp_config,
                udp_state,
                udp_shutdown,
            )
            .await;
        }))
    } else {
        None
    };

    loop {
        if streams.len() >= HY2_MAX_STREAMS_PER_CONN {
            state.log(
                "warning",
                format!("hysteria2 inbound stream limit reached ({HY2_MAX_STREAMS_PER_CONN})"),
            );
        }
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = connection.accept_bi() => {
                let Ok((send, recv)) = accepted else { break };
                if streams.len() >= HY2_MAX_STREAMS_PER_CONN {
                    continue;
                }
                let stream_config = Arc::clone(&config);
                let stream_state = Arc::clone(&state);
                let stream_dns = Arc::clone(&dns_service);
                let stream_shutdown = shutdown.child_token();
                let stream_inbound_name = inbound_name.clone();
                let stream_username = username.clone();
                streams.spawn(async move {
                    let accepted = tokio::select! {
                        () = stream_shutdown.cancelled() => return,
                        result = tokio::time::timeout(
                            HY2_TCP_REQUEST_TIMEOUT,
                            accept_tcp_request(send, recv),
                        ) => result,
                    };
                    let Ok(Ok((destination, stream))) = accepted else {
                        return;
                    };
                    serve_hysteria2_tcp(
                        stream,
                        peer,
                        local,
                        destination,
                        stream_username,
                        stream_inbound_name,
                        &stream_config,
                        &stream_state,
                        &stream_dns,
                        &stream_shutdown,
                    )
                    .await;
                });
            }
            Some(_) = streams.join_next() => {}
        }
    }
    streams.abort_all();
    while streams.join_next().await.is_some() {}
    if let Some(task) = udp_task {
        task.abort();
        let _ = task.await;
    }
    connection.close(0_u32.into(), b"session closed");
}

#[allow(clippy::too_many_arguments)]
async fn serve_hysteria2_tcp(
    stream: Hysteria2ServerStream,
    peer: SocketAddr,
    local: SocketAddr,
    destination: Destination,
    username: String,
    inbound_name: String,
    config: &Config,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    shutdown: &CancellationToken,
) {
    let mut metadata = Metadata::new(destination, InboundProtocol::Hysteria2);
    metadata.network = Network::Tcp;
    metadata.source_ip = Some(unmap_ip(peer.ip()));
    metadata.source_port = peer.port();
    metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut metadata.inbound_name);
    metadata.inbound_user = username;
    let client: BoxedInboundStream = Box::new(Hysteria2InboundStream::new(stream, local, peer));
    serve_shadowsocks_connection(client, metadata, config, state, dns_service, shutdown).await;
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_hysteria2_udp(
    connection: quinn::Connection,
    peer: SocketAddr,
    local: SocketAddr,
    username: String,
    inbound_name: String,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    let sessions: Arc<tokio::sync::Mutex<HashMap<u32, Hy2UdpSessionSlot>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let defrag_by_session: Arc<tokio::sync::Mutex<HashMap<u32, Defragger>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let next_generation = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let mut workers = JoinSet::new();
    let mut idle_sweep = tokio::time::interval(HY2_UDP_IDLE_SWEEP);
    idle_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate first tick so sessions get a full idle window.
    idle_sweep.tick().await;

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            _ = idle_sweep.tick() => {
                let mut sessions_guard = sessions.lock().await;
                let mut defrag_guard = defrag_by_session.lock().await;
                evict_idle_udp_sessions(
                    &mut sessions_guard,
                    &mut defrag_guard,
                    HY2_UDP_SESSION_IDLE,
                );
            }
            datagram = connection.read_datagram() => {
                let Ok(data) = datagram else { break };
                let Some(message) = UdpMessage::parse(&data) else {
                    continue;
                };
                let session_id = message.session_id;
                let reassembled = {
                    let sessions_guard = sessions.lock().await;
                    let mut defrag_guard = defrag_by_session.lock().await;
                    try_feed_defrag(&mut defrag_guard, &sessions_guard, message)
                };
                let Some(message) = reassembled else {
                    continue;
                };
                let mut guard = sessions.lock().await;
                if let Some(slot) = guard.get_mut(&session_id) {
                    slot.last_used = Instant::now();
                    let _ = slot.tx.try_send(message);
                    continue;
                }
                if guard.len() >= HY2_MAX_UDP_SESSIONS {
                    continue;
                }
                let (tx, rx) = mpsc::channel(HY2_UDP_SESSION_CHAN);
                let session_cancel = shutdown.child_token();
                let generation = next_generation.fetch_add(1, Ordering::Relaxed);
                let _ = tx.try_send(message);
                guard.insert(
                    session_id,
                    Hy2UdpSessionSlot {
                        tx,
                        last_used: Instant::now(),
                        cancel: session_cancel.clone(),
                        generation,
                    },
                );
                drop(guard);

                let session_connection = connection.clone();
                let session_config = Arc::clone(&config);
                let session_state = Arc::clone(&state);
                let session_inbound_name = inbound_name.clone();
                let session_username = username.clone();
                let session_map = Arc::clone(&sessions);
                let defrag_map = Arc::clone(&defrag_by_session);
                workers.spawn(async move {
                    serve_hysteria2_udp_session(
                        session_connection,
                        session_id,
                        generation,
                        rx,
                        peer,
                        local,
                        session_username,
                        session_inbound_name,
                        session_config,
                        session_state,
                        session_cancel,
                        Arc::clone(&session_map),
                    )
                    .await;
                    remove_udp_session_if_owner(
                        &session_map,
                        &defrag_map,
                        session_id,
                        generation,
                    )
                    .await;
                });
            }
            Some(_) = workers.join_next() => {}
        }
    }
    workers.abort_all();
    while workers.join_next().await.is_some() {}
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_hysteria2_udp_session(
    connection: quinn::Connection,
    session_id: u32,
    generation: u64,
    mut rx: mpsc::Receiver<UdpMessage>,
    peer: SocketAddr,
    local: SocketAddr,
    username: String,
    inbound_name: String,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
    sessions: Arc<tokio::sync::Mutex<HashMap<u32, Hy2UdpSessionSlot>>>,
) {
    let first = tokio::select! {
        () = shutdown.cancelled() => return,
        message = rx.recv() => message,
    };
    let Some(first) = first else {
        return;
    };
    let destination = match rewrite_protocol_hysteria2::parse_destination_authority(&first.addr) {
        Ok(destination) => destination,
        Err(_) => return,
    };
    let mut packet_metadata = Metadata::new(destination.clone(), InboundProtocol::Hysteria2);
    packet_metadata.network = Network::Udp;
    packet_metadata.source_ip = Some(unmap_ip(peer.ip()));
    packet_metadata.source_port = peer.port();
    packet_metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut packet_metadata.inbound_name);
    packet_metadata.inbound_user = username;

    let Some((decision, target)) =
        route_hy2_udp_datagram(&mut packet_metadata, destination, &config, &state).await
    else {
        return;
    };
    state.log(
        "info",
        format!(
            "[UDP] {} --> {} match {} using {} (Hysteria2)",
            packet_metadata.source_port,
            packet_metadata.destination.authority(),
            decision.matched_kind.as_deref().unwrap_or("none"),
            decision.target
        ),
    );
    serve_hysteria2_udp_direct(
        connection,
        session_id,
        generation,
        rx,
        first,
        packet_metadata,
        decision,
        target,
        &config,
        &state,
        &shutdown,
        &sessions,
    )
    .await;
}

/// Routes one Hy2 UDP datagram destination. Returns `None` when the packet
/// should be dropped (reject / unsupported outbound).
async fn route_hy2_udp_datagram(
    metadata: &mut Metadata,
    destination: Destination,
    config: &Config,
    state: &Arc<RuntimeState>,
) -> Option<(rewrite_rules::Decision, SocketAddr)> {
    metadata.destination = destination;
    let fake_host = apply_host_mapping(metadata, config, state);
    let decision = mode_decision(config, state).unwrap_or_else(|| config.rules.evaluate(metadata));
    let (decision, outbound_target, _) = resolve_rematch_target(decision, metadata, config, state)?;
    let route = resolved_route(&outbound_target, config);
    if matches!(route, Route::Reject | Route::RejectDrop) {
        state.log(
            "info",
            format!(
                "[UDP] {} --> {} match {} using {} (Hysteria2)",
                metadata.source_port,
                metadata.destination.authority(),
                decision.matched_kind.as_deref().unwrap_or("none"),
                decision.target
            ),
        );
        return None;
    }
    let mode = udp_session_mode(&outbound_target, config)?;
    if !matches!(mode, UdpSessionMode::Direct) {
        state.log(
            "error",
            format!(
                "hysteria2 inbound UDP target {} is unsupported in IN-F",
                decision.target
            ),
        );
        return None;
    }
    match resolve_udp_target(metadata, fake_host.as_deref(), config).await {
        Ok(target) => Some((decision, target)),
        Err(error) => {
            state.log(
                "error",
                format!("hysteria2 inbound UDP resolution failed: {error}"),
            );
            None
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_hysteria2_udp_direct(
    connection: quinn::Connection,
    session_id: u32,
    generation: u64,
    mut rx: mpsc::Receiver<UdpMessage>,
    first: UdpMessage,
    first_metadata: Metadata,
    decision: rewrite_rules::Decision,
    target: SocketAddr,
    config: &Config,
    state: &Arc<RuntimeState>,
    shutdown: &CancellationToken,
    sessions: &tokio::sync::Mutex<HashMap<u32, Hy2UdpSessionSlot>>,
) {
    let outbound = match crate::listener::bind_direct_udp_socket(target, config) {
        Ok(socket) => socket,
        Err(error) => {
            state.log(
                "error",
                format!("hysteria2 inbound UDP bind failed: {error}"),
            );
            return;
        }
    };
    let tracker = state.register(
        &first_metadata,
        &decision.target,
        decision.matched_kind.as_deref(),
    );
    let mut uploaded = first.data.len() as u64;
    let mut downloaded = 0_u64;
    if outbound.send_to(&first.data, target).await.is_err() {
        tracker.finish(uploaded, downloaded);
        return;
    }

    loop {
        let mut response = vec![0_u8; 65_536];
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tracker.cancelled() => break,
            received = outbound.recv_from(&mut response) => {
                let Ok((length, source)) = received else { break };
                let destination = Destination {
                    host: Host::Ip(unmap_ip(source.ip())),
                    port: source.port(),
                };
                let reply_addr = destination.authority();
                if !send_hysteria2_udp_to_client(
                    &connection,
                    session_id,
                    &reply_addr,
                    &response[..length],
                    shutdown,
                    tracker.cancelled(),
                )
                .await
                {
                    break;
                }
                downloaded = downloaded.saturating_add(length as u64);
                // Downstream success counts as activity (push / long-lived replies).
                touch_udp_session(&mut *sessions.lock().await, session_id, generation);
            }
            message = rx.recv() => {
                let Some(message) = message else { break };
                let destination = match rewrite_protocol_hysteria2::parse_destination_authority(&message.addr) {
                    Ok(destination) => destination,
                    Err(_) => continue,
                };
                let mut metadata = first_metadata.clone();
                let Some((_decision, next_target)) =
                    route_hy2_udp_datagram(&mut metadata, destination, config, state).await
                else {
                    // Reject / unsupported: drop this datagram, keep association.
                    continue;
                };
                if outbound.send_to(&message.data, next_target).await.is_ok() {
                    uploaded = uploaded.saturating_add(message.data.len() as u64);
                    touch_udp_session(&mut *sessions.lock().await, session_id, generation);
                }
            }
        }
    }
    tracker.finish(uploaded, downloaded);
}

async fn send_hysteria2_udp_to_client<C>(
    connection: &quinn::Connection,
    session_id: u32,
    addr: &str,
    payload: &[u8],
    shutdown: &CancellationToken,
    tracker_cancelled: C,
) -> bool
where
    C: Future<Output = ()>,
{
    let msg = UdpMessage {
        session_id,
        packet_id: 0,
        frag_id: 0,
        frag_count: 1,
        addr: addr.to_owned(),
        data: payload.to_vec(),
    };
    let max = connection
        .max_datagram_size()
        .unwrap_or(MAX_DATAGRAM_FRAME_SIZE)
        .min(HY2_UDP_MTU)
        .max(64);
    let send_all = async {
        if msg.size() <= max {
            let mut buf = vec![0_u8; msg.size()];
            if let Some(n) = msg.serialize(&mut buf) {
                connection
                    .send_datagram(Bytes::copy_from_slice(&buf[..n]))
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
            }
            return Ok::<(), std::io::Error>(());
        }
        let mut frag = msg;
        frag.packet_id = rand::random_range(1..=u16::MAX);
        for part in frag_udp_message(&frag, max) {
            let mut buf = vec![0_u8; part.size()];
            if let Some(n) = part.serialize(&mut buf) {
                connection
                    .send_datagram(Bytes::copy_from_slice(&buf[..n]))
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
            }
        }
        Ok(())
    };
    tokio::select! {
        biased;
        () = shutdown.cancelled() => false,
        () = tracker_cancelled => false,
        result = tokio::time::timeout(HY2_UDP_CLIENT_WRITE_TIMEOUT, send_all) => {
            matches!(result, Ok(Ok(())))
        }
    }
}

#[cfg(test)]
mod hy2_udp_tests {
    use super::*;

    fn incomplete_fragment(session_id: u32) -> UdpMessage {
        UdpMessage {
            session_id,
            packet_id: 1,
            frag_id: 0,
            frag_count: 2,
            addr: "127.0.0.1:9".to_owned(),
            data: vec![0xab],
        }
    }

    #[test]
    fn defrag_map_refuses_insert_when_full_of_live_sessions() {
        let mut defrag = HashMap::new();
        let mut live = HashMap::new();
        for session_id in 0..HY2_MAX_UDP_SESSIONS as u32 {
            let (tx, _rx) = mpsc::channel(1);
            live.insert(
                session_id,
                Hy2UdpSessionSlot {
                    tx,
                    last_used: Instant::now(),
                    cancel: CancellationToken::new(),
                    generation: u64::from(session_id) + 1,
                },
            );
            assert!(
                try_feed_defrag(&mut defrag, &live, incomplete_fragment(session_id)).is_none(),
                "incomplete fragment should not reassemble"
            );
        }
        assert_eq!(defrag.len(), HY2_MAX_UDP_SESSIONS);
        let overflow_id = HY2_MAX_UDP_SESSIONS as u32;
        assert!(
            try_feed_defrag(&mut defrag, &live, incomplete_fragment(overflow_id)).is_none(),
            "must drop when full of live-session defrag entries"
        );
        assert!(
            !defrag.contains_key(&overflow_id),
            "overflow session must not get a defrag entry"
        );
        assert_eq!(defrag.len(), HY2_MAX_UDP_SESSIONS);
    }

    #[test]
    fn defrag_map_reclaims_orphans_when_live_sessions_remain() {
        let mut defrag = HashMap::new();
        let (tx, _rx) = mpsc::channel(1);
        let live = HashMap::from([(
            0_u32,
            Hy2UdpSessionSlot {
                tx,
                last_used: Instant::now(),
                cancel: CancellationToken::new(),
                generation: 1,
            },
        )]);
        for session_id in 0..HY2_MAX_UDP_SESSIONS as u32 {
            let _ = try_feed_defrag(&mut defrag, &live, incomplete_fragment(session_id));
        }
        assert_eq!(defrag.len(), HY2_MAX_UDP_SESSIONS);
        // Orphan entries (1..N) should be retained away; live session 0 kept.
        let new_id = HY2_MAX_UDP_SESSIONS as u32 + 7;
        assert!(
            try_feed_defrag(&mut defrag, &live, incomplete_fragment(new_id)).is_none(),
            "incomplete feed returns None"
        );
        assert!(
            defrag.contains_key(&0),
            "live session defrag entry must survive reclaim"
        );
        assert!(
            defrag.contains_key(&new_id),
            "after reclaiming orphans, a new session may insert"
        );
        assert!(defrag.len() <= HY2_MAX_UDP_SESSIONS);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_eviction_cancels_session_and_clears_defrag() {
        let cancel = CancellationToken::new();
        let (tx, _rx) = mpsc::channel(1);
        let mut sessions = HashMap::new();
        let mut defrag = HashMap::new();
        sessions.insert(
            42,
            Hy2UdpSessionSlot {
                tx,
                last_used: Instant::now(),
                cancel: cancel.clone(),
                generation: 7,
            },
        );
        defrag.insert(42, Defragger::default());
        tokio::time::advance(HY2_UDP_SESSION_IDLE + Duration::from_secs(1)).await;
        evict_idle_udp_sessions(&mut sessions, &mut defrag, HY2_UDP_SESSION_IDLE);
        assert!(sessions.is_empty(), "idle session must be removed");
        assert!(defrag.is_empty(), "idle defrag entry must be removed");
        assert!(cancel.is_cancelled(), "idle eviction must cancel the token");
    }

    #[tokio::test(start_paused = true)]
    async fn old_worker_cleanup_does_not_remove_recreated_session() {
        let sessions = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let defrag = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let session_id = 9_u32;
        let old_cancel = CancellationToken::new();
        {
            let (tx, _rx) = mpsc::channel(1);
            sessions.lock().await.insert(
                session_id,
                Hy2UdpSessionSlot {
                    tx,
                    last_used: Instant::now(),
                    cancel: old_cancel.clone(),
                    generation: 1,
                },
            );
            defrag.lock().await.insert(session_id, Defragger::default());
        }

        // Idle eviction cancels the old worker and clears the slot.
        {
            let mut sessions_guard = sessions.lock().await;
            let mut defrag_guard = defrag.lock().await;
            tokio::time::advance(HY2_UDP_SESSION_IDLE + Duration::from_secs(1)).await;
            evict_idle_udp_sessions(&mut sessions_guard, &mut defrag_guard, HY2_UDP_SESSION_IDLE);
        }
        assert!(old_cancel.is_cancelled());
        assert!(sessions.lock().await.is_empty());

        // Immediate recreate under the same session id with a new generation.
        let new_cancel = CancellationToken::new();
        {
            let (tx, _rx) = mpsc::channel(1);
            sessions.lock().await.insert(
                session_id,
                Hy2UdpSessionSlot {
                    tx,
                    last_used: Instant::now(),
                    cancel: new_cancel.clone(),
                    generation: 2,
                },
            );
            defrag.lock().await.insert(session_id, Defragger::default());
        }

        // Old worker exit must not wipe the recreated slot / defrag state.
        remove_udp_session_if_owner(&sessions, &defrag, session_id, 1).await;
        let sessions_guard = sessions.lock().await;
        let slot = sessions_guard
            .get(&session_id)
            .expect("recreated session must survive old worker cleanup");
        assert_eq!(slot.generation, 2);
        assert!(!new_cancel.is_cancelled());
        drop(sessions_guard);
        assert!(
            defrag.lock().await.contains_key(&session_id),
            "recreated defrag must survive old worker cleanup"
        );

        // Matching generation still cleans up.
        remove_udp_session_if_owner(&sessions, &defrag, session_id, 2).await;
        assert!(sessions.lock().await.is_empty());
        assert!(defrag.lock().await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn downlink_touch_keeps_session_from_idle_eviction() {
        let (tx, _rx) = mpsc::channel(1);
        let mut sessions = HashMap::new();
        let mut defrag = HashMap::new();
        sessions.insert(
            3,
            Hy2UdpSessionSlot {
                tx,
                last_used: Instant::now(),
                cancel: CancellationToken::new(),
                generation: 11,
            },
        );
        defrag.insert(3, Defragger::default());
        tokio::time::advance(HY2_UDP_SESSION_IDLE - Duration::from_secs(5)).await;
        touch_udp_session(&mut sessions, 3, 11);
        tokio::time::advance(Duration::from_secs(10)).await;
        evict_idle_udp_sessions(&mut sessions, &mut defrag, HY2_UDP_SESSION_IDLE);
        assert!(
            sessions.contains_key(&3),
            "fresh downlink activity must refresh idle clock"
        );
        // Wrong generation must not refresh.
        tokio::time::advance(HY2_UDP_SESSION_IDLE + Duration::from_secs(1)).await;
        touch_udp_session(&mut sessions, 3, 99);
        evict_idle_udp_sessions(&mut sessions, &mut defrag, HY2_UDP_SESSION_IDLE);
        assert!(
            sessions.is_empty(),
            "stale generation must not prevent idle eviction"
        );
    }
}

//! Named `type: tuic` QUIC inbound (IN-F TUIC v5 slice).
//!
//! Protocol crate owns TLS-exporter auth + TCP/UDP wire Accept; this module owns
//! listen, caps, route, and relay into the shared stream/UDP boundaries.
//!
//! Unlike Hy2, auth arrives on a uni-stream and races an authentication timeout.
//! TCP/UDP work waits on a watch until auth succeeds.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use bytes::Bytes;
use rewrite_config::{Config, TuicInboundConfig};
use rewrite_inbound::BoxedInboundStream;
use rewrite_model::{Destination, Host, InboundProtocol, Metadata, Network, unmap_ip};
use rewrite_protocol_tuic::{
    CMD_AUTHENTICATE, CMD_DISSOCIATE, CMD_HEARTBEAT, CMD_PACKET, CongestionController, Defragger,
    Packet, ServerEndpointOptions, TuicServerStream, VERSION, accept_tcp_connect,
    bind_server_endpoint, close_authentication_failed, close_authentication_timeout,
    compute_max_udp_relay_packet_size, decode_dissociate, decode_packet, encode_packet,
    load_pem_or_path, users_table, verify_authenticate,
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

const TUIC_MAX_INBOUND_CONNECTIONS: usize = 1024;
const TUIC_MAX_STREAMS_PER_CONN: usize = 256;
const TUIC_MAX_UDP_SESSIONS: usize = 256;
const TUIC_UDP_SESSION_CHAN: usize = 1024;
const TUIC_UDP_CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const TUIC_TCP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const TUIC_UDP_SESSION_IDLE: Duration = Duration::from_secs(60);
const TUIC_UDP_IDLE_SWEEP: Duration = Duration::from_secs(10);

/// Connection-level auth outcome shared across uni / bi / datagram loops.
#[derive(Clone, Debug, Eq, PartialEq)]
enum AuthOutcome {
    Pending,
    Ok(String),
    Failed,
}

/// One TUIC UDP association (`assoc_id`): client packet channel, idle clock,
/// cancel token, and a generation id so a retiring worker cannot wipe a
/// recreated same-ID slot.
struct TuicUdpSessionSlot {
    tx: mpsc::Sender<Packet>,
    last_used: Instant,
    cancel: CancellationToken,
    generation: u64,
}

/// Remove `assoc_id` only when the map still holds `generation` (this worker's
/// instance). Prevents an evicted worker from deleting a recreated slot.
///
/// Lock order is always **sessions → defrag**. Both tables are updated before
/// either lock is released so a concurrent recreate cannot insert a new defrag
/// entry that the retiring worker then deletes.
async fn remove_udp_session_if_owner(
    sessions: &tokio::sync::Mutex<HashMap<u16, TuicUdpSessionSlot>>,
    defrag_by_assoc: &tokio::sync::Mutex<HashMap<u16, Defragger>>,
    assoc_id: u16,
    generation: u64,
) {
    let mut sessions = sessions.lock().await;
    let is_owner = sessions
        .get(&assoc_id)
        .is_some_and(|slot| slot.generation == generation);
    if !is_owner {
        return;
    }
    sessions.remove(&assoc_id);
    // Hold `sessions` while taking `defrag` (same order as idle sweep / feed).
    defrag_by_assoc.lock().await.remove(&assoc_id);
}

/// Cancel and remove a UDP association (Dissociate), holding sessions→defrag.
async fn dissociate_udp_session(
    sessions: &tokio::sync::Mutex<HashMap<u16, TuicUdpSessionSlot>>,
    defrag_by_assoc: &tokio::sync::Mutex<HashMap<u16, Defragger>>,
    assoc_id: u16,
) {
    let mut sessions = sessions.lock().await;
    if let Some(slot) = sessions.remove(&assoc_id) {
        slot.cancel.cancel();
    }
    defrag_by_assoc.lock().await.remove(&assoc_id);
}

/// Refresh idle clock when this generation still owns the slot.
fn touch_udp_session(
    sessions: &mut HashMap<u16, TuicUdpSessionSlot>,
    assoc_id: u16,
    generation: u64,
) {
    if let Some(slot) = sessions.get_mut(&assoc_id) {
        if slot.generation == generation {
            slot.last_used = Instant::now();
        }
    }
}

/// Feed a datagram into the per-assoc defragger, capping orphan entries at
/// `TUIC_MAX_UDP_SESSIONS`. When full, retain only associations that still have
/// a live slot; if still full, drop the fragment without inserting.
fn try_feed_defrag(
    defrag_by_assoc: &mut HashMap<u16, Defragger>,
    live_sessions: &HashMap<u16, TuicUdpSessionSlot>,
    packet: Packet,
) -> Option<Packet> {
    let assoc_id = packet.assoc_id;
    if !defrag_by_assoc.contains_key(&assoc_id) && defrag_by_assoc.len() >= TUIC_MAX_UDP_SESSIONS {
        defrag_by_assoc.retain(|id, _| live_sessions.contains_key(id));
        if defrag_by_assoc.len() >= TUIC_MAX_UDP_SESSIONS {
            return None;
        }
    }
    defrag_by_assoc.entry(assoc_id).or_default().feed(packet)
}

/// Cancel and remove UDP sessions idle longer than `max_idle`, and drop their
/// defrag entries.
fn evict_idle_udp_sessions(
    sessions: &mut HashMap<u16, TuicUdpSessionSlot>,
    defrag_by_assoc: &mut HashMap<u16, Defragger>,
    max_idle: Duration,
) {
    let now = Instant::now();
    let idle: Vec<u16> = sessions
        .iter()
        .filter(|(_, slot)| now.duration_since(slot.last_used) > max_idle)
        .map(|(assoc_id, _)| *assoc_id)
        .collect();
    for assoc_id in idle {
        if let Some(slot) = sessions.remove(&assoc_id) {
            slot.cancel.cancel();
        }
        defrag_by_assoc.remove(&assoc_id);
    }
}

fn map_congestion_controller(raw: &str) -> CongestionController {
    match raw.trim().to_ascii_lowercase().as_str() {
        "bbr" => CongestionController::Bbr,
        "new_reno" | "new-reno" => CongestionController::NewReno,
        _ => CongestionController::Cubic,
    }
}

/// Transition Pending → `next` at most once (auth success, failure, or timeout).
fn try_finish_auth(tx: &watch::Sender<AuthOutcome>, next: AuthOutcome) -> bool {
    tx.send_if_modified(|current| {
        if matches!(current, AuthOutcome::Pending) {
            *current = next;
            true
        } else {
            false
        }
    })
}

async fn wait_auth_ok(
    mut auth_rx: watch::Receiver<AuthOutcome>,
    shutdown: &CancellationToken,
) -> Option<String> {
    loop {
        match &*auth_rx.borrow_and_update() {
            AuthOutcome::Ok(user) => return Some(user.clone()),
            AuthOutcome::Failed => return None,
            AuthOutcome::Pending => {}
        }
        tokio::select! {
            () = shutdown.cancelled() => return None,
            changed = auth_rx.changed() => {
                if changed.is_err() {
                    return None;
                }
            }
        }
    }
}

pub(crate) struct TuicListener {
    endpoint: quinn::Endpoint,
    users: HashMap<[u8; 16], String>,
    inbound_name: String,
    listen: SocketAddr,
    authentication_timeout: Duration,
    max_udp_relay_packet_size: usize,
}

impl TuicListener {
    pub(crate) async fn bind(config: &TuicInboundConfig) -> Result<Self, RuntimeError> {
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
            congestion: map_congestion_controller(&config.congestion_controller),
            max_idle_timeout: Duration::from_millis(config.max_idle_time_ms),
            max_concurrent_bidi_streams: u32::try_from(TUIC_MAX_STREAMS_PER_CONN)
                .unwrap_or(u32::MAX),
            max_concurrent_uni_streams: u32::try_from(TUIC_MAX_STREAMS_PER_CONN)
                .unwrap_or(u32::MAX),
            ..ServerEndpointOptions::default()
        })
        .map_err(|error| RuntimeError::Listener(std::io::Error::other(error.to_string())))?;
        let users = users_table(
            config
                .users
                .iter()
                .map(|user| (user.uuid.clone(), user.password.clone())),
        )
        .map_err(|error| RuntimeError::Listener(std::io::Error::other(error.to_string())))?;
        Ok(Self {
            endpoint,
            users,
            inbound_name: config.name.clone(),
            listen: config.listen,
            authentication_timeout: Duration::from_millis(config.authentication_timeout_ms),
            max_udp_relay_packet_size: compute_max_udp_relay_packet_size(
                config.max_udp_relay_packet_size,
            ),
        })
    }
}

struct TuicInboundStream {
    inner: TuicServerStream,
    local: SocketAddr,
    peer: SocketAddr,
}

impl TuicInboundStream {
    fn new(inner: TuicServerStream, local: SocketAddr, peer: SocketAddr) -> Self {
        Self { inner, local, peer }
    }
}

impl AsyncRead for TuicInboundStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TuicInboundStream {
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

impl rewrite_inbound::InboundStream for TuicInboundStream {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer)
    }
}

pub(super) async fn run_tuic_listener(
    listener: TuicListener,
    config_receiver: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let TuicListener {
        endpoint,
        users,
        inbound_name,
        listen,
        authentication_timeout,
        max_udp_relay_packet_size,
    } = listener;
    let active = Arc::new(AtomicUsize::new(0));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    state.log("error", "tuic inbound accept ended");
                    break;
                };
                let connection_config = Arc::clone(&*config_receiver.borrow());
                let peer = incoming.remote_address();
                if !connection_config.permits_inbound(peer.ip()) {
                    incoming.ignore();
                    continue;
                }
                if active.load(Ordering::Relaxed) >= TUIC_MAX_INBOUND_CONNECTIONS {
                    state.log(
                        "warning",
                        format!(
                            "tuic inbound connection limit reached ({TUIC_MAX_INBOUND_CONNECTIONS})"
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
                    handle_tuic_connection(
                        connection,
                        peer,
                        local,
                        users,
                        connection_inbound_name,
                        authentication_timeout,
                        max_udp_relay_packet_size,
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
async fn handle_tuic_connection(
    connection: quinn::Connection,
    peer: SocketAddr,
    local: SocketAddr,
    users: HashMap<[u8; 16], String>,
    inbound_name: String,
    authentication_timeout: Duration,
    max_udp_relay_packet_size: usize,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let (auth_tx, auth_rx) = watch::channel(AuthOutcome::Pending);

    // Auth timeout races the Authenticate uni-stream.
    let timeout_tx = auth_tx.clone();
    let timeout_connection = connection.clone();
    let timeout_shutdown = shutdown.child_token();
    tokio::spawn(async move {
        tokio::select! {
            () = timeout_shutdown.cancelled() => {}
            () = tokio::time::sleep(authentication_timeout) => {
                if try_finish_auth(&timeout_tx, AuthOutcome::Failed) {
                    close_authentication_timeout(&timeout_connection);
                }
            }
        }
    });

    let sessions: Arc<tokio::sync::Mutex<HashMap<u16, TuicUdpSessionSlot>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let defrag_by_assoc: Arc<tokio::sync::Mutex<HashMap<u16, Defragger>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let next_generation = Arc::new(std::sync::atomic::AtomicU64::new(1));

    let idle_sweep_task = {
        let sessions = Arc::clone(&sessions);
        let defrag = Arc::clone(&defrag_by_assoc);
        let shutdown = shutdown.child_token();
        tokio::spawn(async move {
            let mut idle_sweep = tokio::time::interval(TUIC_UDP_IDLE_SWEEP);
            idle_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Skip the immediate first tick so sessions get a full idle window.
            idle_sweep.tick().await;
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    _ = idle_sweep.tick() => {
                        let mut sessions_guard = sessions.lock().await;
                        let mut defrag_guard = defrag.lock().await;
                        evict_idle_udp_sessions(
                            &mut sessions_guard,
                            &mut defrag_guard,
                            TUIC_UDP_SESSION_IDLE,
                        );
                    }
                }
            }
        })
    };

    let uni_task = {
        let connection = connection.clone();
        let auth_tx = auth_tx.clone();
        let users = users.clone();
        let sessions = Arc::clone(&sessions);
        let defrag = Arc::clone(&defrag_by_assoc);
        let next_generation = Arc::clone(&next_generation);
        let config = Arc::clone(&config);
        let state = Arc::clone(&state);
        let inbound_name = inbound_name.clone();
        let auth_rx = auth_rx.clone();
        let shutdown = shutdown.child_token();
        tokio::spawn(async move {
            serve_tuic_uni_streams(
                connection,
                users,
                auth_tx,
                auth_rx,
                peer,
                local,
                inbound_name,
                max_udp_relay_packet_size,
                config,
                state,
                sessions,
                defrag,
                next_generation,
                shutdown,
            )
            .await;
        })
    };

    let bi_task = {
        let connection = connection.clone();
        let auth_rx = auth_rx.clone();
        let config = Arc::clone(&config);
        let state = Arc::clone(&state);
        let dns_service = Arc::clone(&dns_service);
        let inbound_name = inbound_name.clone();
        let shutdown = shutdown.child_token();
        tokio::spawn(async move {
            serve_tuic_bi_streams(
                connection,
                auth_rx,
                peer,
                local,
                inbound_name,
                config,
                state,
                dns_service,
                shutdown,
            )
            .await;
        })
    };

    let datagram_task = {
        let connection = connection.clone();
        let auth_rx = auth_rx.clone();
        let sessions = Arc::clone(&sessions);
        let defrag = Arc::clone(&defrag_by_assoc);
        let next_generation = Arc::clone(&next_generation);
        let config = Arc::clone(&config);
        let state = Arc::clone(&state);
        let inbound_name = inbound_name.clone();
        let shutdown = shutdown.child_token();
        tokio::spawn(async move {
            serve_tuic_datagrams(
                connection,
                auth_rx,
                peer,
                local,
                inbound_name,
                max_udp_relay_packet_size,
                config,
                state,
                sessions,
                defrag,
                next_generation,
                shutdown,
            )
            .await;
        })
    };

    tokio::select! {
        () = shutdown.cancelled() => {}
        error = connection.closed() => {
            let _ = error;
        }
    }

    idle_sweep_task.abort();
    uni_task.abort();
    bi_task.abort();
    datagram_task.abort();
    let _ = idle_sweep_task.await;
    let _ = uni_task.await;
    let _ = bi_task.await;
    let _ = datagram_task.await;
    connection.close(0_u32.into(), b"session closed");
}

#[allow(clippy::too_many_arguments)]
async fn serve_tuic_uni_streams(
    connection: quinn::Connection,
    users: HashMap<[u8; 16], String>,
    auth_tx: watch::Sender<AuthOutcome>,
    auth_rx: watch::Receiver<AuthOutcome>,
    peer: SocketAddr,
    local: SocketAddr,
    inbound_name: String,
    max_udp_relay_packet_size: usize,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    sessions: Arc<tokio::sync::Mutex<HashMap<u16, TuicUdpSessionSlot>>>,
    defrag_by_assoc: Arc<tokio::sync::Mutex<HashMap<u16, Defragger>>>,
    next_generation: Arc<std::sync::atomic::AtomicU64>,
    shutdown: CancellationToken,
) {
    let mut workers = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = connection.accept_uni() => {
                let Ok(recv) = accepted else { break };
                let connection = connection.clone();
                let users = users.clone();
                let auth_tx = auth_tx.clone();
                let auth_rx = auth_rx.clone();
                let sessions = Arc::clone(&sessions);
                let defrag = Arc::clone(&defrag_by_assoc);
                let next_generation = Arc::clone(&next_generation);
                let config = Arc::clone(&config);
                let state = Arc::clone(&state);
                let inbound_name = inbound_name.clone();
                let stream_shutdown = shutdown.child_token();
                workers.spawn(async move {
                    handle_tuic_uni_stream(
                        connection,
                        recv,
                        users,
                        auth_tx,
                        auth_rx,
                        peer,
                        local,
                        inbound_name,
                        max_udp_relay_packet_size,
                        config,
                        state,
                        sessions,
                        defrag,
                        next_generation,
                        stream_shutdown,
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

#[allow(clippy::too_many_arguments)]
async fn handle_tuic_uni_stream(
    connection: quinn::Connection,
    mut recv: quinn::RecvStream,
    users: HashMap<[u8; 16], String>,
    auth_tx: watch::Sender<AuthOutcome>,
    auth_rx: watch::Receiver<AuthOutcome>,
    peer: SocketAddr,
    local: SocketAddr,
    inbound_name: String,
    max_udp_relay_packet_size: usize,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    sessions: Arc<tokio::sync::Mutex<HashMap<u16, TuicUdpSessionSlot>>>,
    defrag_by_assoc: Arc<tokio::sync::Mutex<HashMap<u16, Defragger>>>,
    next_generation: Arc<std::sync::atomic::AtomicU64>,
    shutdown: CancellationToken,
) {
    let mut head = [0_u8; 2];
    if read_exact_recv(&mut recv, &mut head).await.is_err() {
        return;
    }
    if head[0] != VERSION {
        return;
    }
    match head[1] {
        CMD_AUTHENTICATE => {
            // VER/TYPE already consumed for demux (Authenticate vs Packet vs
            // Dissociate). Finish the fixed-size body and verify — same checks
            // as `authenticate_uni_stream` (read 50 + verify_authenticate).
            let mut rest = [0_u8; 48];
            if read_exact_recv(&mut recv, &mut rest).await.is_err() {
                return;
            }
            let mut frame = [0_u8; 50];
            frame[0] = head[0];
            frame[1] = head[1];
            frame[2..].copy_from_slice(&rest);
            match verify_authenticate(&connection, &users, &frame) {
                Ok(Some(auth)) => {
                    let _ = try_finish_auth(&auth_tx, AuthOutcome::Ok(auth.user));
                }
                Ok(None) | Err(_) => {
                    if try_finish_auth(&auth_tx, AuthOutcome::Failed) {
                        close_authentication_failed(&connection);
                    }
                }
            }
        }
        CMD_PACKET => {
            let Some(username) = wait_auth_ok(auth_rx, &shutdown).await else {
                return;
            };
            let mut buf = head.to_vec();
            let Ok(packet) = read_packet_from_uni_body(&mut recv, &mut buf).await else {
                return;
            };
            if let Some(worker) = dispatch_reassembled_packet(
                packet,
                &connection,
                peer,
                local,
                &username,
                &inbound_name,
                max_udp_relay_packet_size,
                &config,
                &state,
                &sessions,
                &defrag_by_assoc,
                &next_generation,
                &shutdown,
            )
            .await
            {
                worker.await;
            }
        }
        CMD_DISSOCIATE => {
            let Some(_username) = wait_auth_ok(auth_rx, &shutdown).await else {
                return;
            };
            let mut rest = [0_u8; 2];
            if read_exact_recv(&mut recv, &mut rest).await.is_err() {
                return;
            }
            let mut frame = [0_u8; 4];
            frame[0] = head[0];
            frame[1] = head[1];
            frame[2..].copy_from_slice(&rest);
            let Ok(assoc_id) = decode_dissociate(&frame) else {
                return;
            };
            dissociate_udp_session(&sessions, &defrag_by_assoc, assoc_id).await;
        }
        _ => {}
    }
}

async fn read_exact_recv(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0_usize;
    while filled < buf.len() {
        let n = recv
            .read(&mut buf[filled..])
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "stream closed")
            })?;
        filled += n;
    }
    Ok(())
}

async fn read_packet_from_uni_body(
    recv: &mut quinn::RecvStream,
    buf: &mut Vec<u8>,
) -> Result<Packet, ()> {
    let mut tmp = [0_u8; 2048];
    loop {
        match decode_packet(buf) {
            Ok(packet) => return Ok(packet),
            Err(error) => {
                let text = error.to_string();
                if !text.contains("truncated") {
                    return Err(());
                }
            }
        }
        match recv.read(&mut tmp).await {
            Ok(Some(n)) => buf.extend_from_slice(&tmp[..n]),
            Ok(None) => return decode_packet(buf).map_err(|_| ()),
            Err(_) => return Err(()),
        }
        if buf.len() > 65_536 {
            return Err(());
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_tuic_bi_streams(
    connection: quinn::Connection,
    auth_rx: watch::Receiver<AuthOutcome>,
    peer: SocketAddr,
    local: SocketAddr,
    inbound_name: String,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let Some(username) = wait_auth_ok(auth_rx, &shutdown).await else {
        return;
    };
    let mut streams = JoinSet::new();
    loop {
        if streams.len() >= TUIC_MAX_STREAMS_PER_CONN {
            state.log(
                "warning",
                format!("tuic inbound stream limit reached ({TUIC_MAX_STREAMS_PER_CONN})"),
            );
        }
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = connection.accept_bi() => {
                let Ok((send, recv)) = accepted else { break };
                if streams.len() >= TUIC_MAX_STREAMS_PER_CONN {
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
                            TUIC_TCP_REQUEST_TIMEOUT,
                            accept_tcp_connect(send, recv),
                        ) => result,
                    };
                    let Ok(Ok((destination, stream))) = accepted else {
                        return;
                    };
                    serve_tuic_tcp(
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
}

#[allow(clippy::too_many_arguments)]
async fn serve_tuic_tcp(
    stream: TuicServerStream,
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
    let mut metadata = Metadata::new(destination, InboundProtocol::Tuic);
    metadata.network = Network::Tcp;
    metadata.source_ip = Some(unmap_ip(peer.ip()));
    metadata.source_port = peer.port();
    metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut metadata.inbound_name);
    metadata.inbound_user = username;
    let client: BoxedInboundStream = Box::new(TuicInboundStream::new(stream, local, peer));
    serve_shadowsocks_connection(client, metadata, config, state, dns_service, shutdown).await;
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_tuic_datagrams(
    connection: quinn::Connection,
    auth_rx: watch::Receiver<AuthOutcome>,
    peer: SocketAddr,
    local: SocketAddr,
    inbound_name: String,
    max_udp_relay_packet_size: usize,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    sessions: Arc<tokio::sync::Mutex<HashMap<u16, TuicUdpSessionSlot>>>,
    defrag_by_assoc: Arc<tokio::sync::Mutex<HashMap<u16, Defragger>>>,
    next_generation: Arc<std::sync::atomic::AtomicU64>,
    shutdown: CancellationToken,
) {
    let Some(username) = wait_auth_ok(auth_rx, &shutdown).await else {
        return;
    };
    let mut workers = JoinSet::new();

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            datagram = connection.read_datagram() => {
                let Ok(data) = datagram else { break };
                if data.len() >= 2 && data[0] == VERSION && data[1] == CMD_HEARTBEAT {
                    continue;
                }
                let Ok(packet) = decode_packet(&data) else {
                    continue;
                };
                if let Some(task) = dispatch_reassembled_packet(
                    packet,
                    &connection,
                    peer,
                    local,
                    &username,
                    &inbound_name,
                    max_udp_relay_packet_size,
                    &config,
                    &state,
                    &sessions,
                    &defrag_by_assoc,
                    &next_generation,
                    &shutdown,
                )
                .await
                {
                    workers.spawn(task);
                }
            }
            Some(_) = workers.join_next() => {}
        }
    }
    workers.abort_all();
    while workers.join_next().await.is_some() {}
}

/// Feed `packet` through defrag; create/route a UDP session when complete.
/// Returns a worker future when a new session is spawned.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
async fn dispatch_reassembled_packet(
    packet: Packet,
    connection: &quinn::Connection,
    peer: SocketAddr,
    local: SocketAddr,
    username: &str,
    inbound_name: &str,
    max_udp_relay_packet_size: usize,
    config: &Arc<Config>,
    state: &Arc<RuntimeState>,
    sessions: &Arc<tokio::sync::Mutex<HashMap<u16, TuicUdpSessionSlot>>>,
    defrag_by_assoc: &Arc<tokio::sync::Mutex<HashMap<u16, Defragger>>>,
    next_generation: &Arc<std::sync::atomic::AtomicU64>,
    shutdown: &CancellationToken,
) -> Option<impl Future<Output = ()> + Send + 'static> {
    let assoc_id = packet.assoc_id;
    let reassembled = {
        let sessions_guard = sessions.lock().await;
        let mut defrag_guard = defrag_by_assoc.lock().await;
        try_feed_defrag(&mut defrag_guard, &sessions_guard, packet)
    };
    let Some(packet) = reassembled else {
        return None;
    };

    let mut guard = sessions.lock().await;
    if let Some(slot) = guard.get_mut(&assoc_id) {
        slot.last_used = Instant::now();
        let _ = slot.tx.try_send(packet);
        return None;
    }
    if guard.len() >= TUIC_MAX_UDP_SESSIONS {
        return None;
    }
    let (tx, rx) = mpsc::channel(TUIC_UDP_SESSION_CHAN);
    let session_cancel = shutdown.child_token();
    let generation = next_generation.fetch_add(1, Ordering::Relaxed);
    let _ = tx.try_send(packet);
    guard.insert(
        assoc_id,
        TuicUdpSessionSlot {
            tx,
            last_used: Instant::now(),
            cancel: session_cancel.clone(),
            generation,
        },
    );
    drop(guard);

    let session_connection = connection.clone();
    let session_config = Arc::clone(config);
    let session_state = Arc::clone(state);
    let session_inbound_name = inbound_name.to_owned();
    let session_username = username.to_owned();
    let session_map = Arc::clone(sessions);
    let defrag_map = Arc::clone(defrag_by_assoc);
    Some(async move {
        serve_tuic_udp_session(
            session_connection,
            assoc_id,
            generation,
            rx,
            peer,
            local,
            session_username,
            session_inbound_name,
            max_udp_relay_packet_size,
            session_config,
            session_state,
            session_cancel,
            Arc::clone(&session_map),
        )
        .await;
        remove_udp_session_if_owner(&session_map, &defrag_map, assoc_id, generation).await;
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_tuic_udp_session(
    connection: quinn::Connection,
    assoc_id: u16,
    generation: u64,
    mut rx: mpsc::Receiver<Packet>,
    peer: SocketAddr,
    local: SocketAddr,
    username: String,
    inbound_name: String,
    max_udp_relay_packet_size: usize,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
    sessions: Arc<tokio::sync::Mutex<HashMap<u16, TuicUdpSessionSlot>>>,
) {
    let first = tokio::select! {
        () = shutdown.cancelled() => return,
        message = rx.recv() => message,
    };
    let Some(first) = first else {
        return;
    };
    let Some(destination) = first.addr.clone() else {
        return;
    };
    let mut packet_metadata = Metadata::new(destination.clone(), InboundProtocol::Tuic);
    packet_metadata.network = Network::Udp;
    packet_metadata.source_ip = Some(unmap_ip(peer.ip()));
    packet_metadata.source_port = peer.port();
    packet_metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut packet_metadata.inbound_name);
    packet_metadata.inbound_user = username;

    let Some((decision, target)) =
        route_tuic_udp_datagram(&mut packet_metadata, destination, &config, &state).await
    else {
        return;
    };
    state.log(
        "info",
        format!(
            "[UDP] {} --> {} match {} using {} (Tuic)",
            packet_metadata.source_port,
            packet_metadata.destination.authority(),
            decision.matched_kind.as_deref().unwrap_or("none"),
            decision.target
        ),
    );
    serve_tuic_udp_direct(
        connection,
        assoc_id,
        generation,
        rx,
        first,
        packet_metadata,
        decision,
        target,
        max_udp_relay_packet_size,
        &config,
        &state,
        &shutdown,
        &sessions,
    )
    .await;
}

/// Routes one TUIC UDP datagram destination. Returns `None` when the packet
/// should be dropped (reject / unsupported outbound).
async fn route_tuic_udp_datagram(
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
                "[UDP] {} --> {} match {} using {} (Tuic)",
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
                "tuic inbound UDP target {} is unsupported in IN-F",
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
                format!("tuic inbound UDP resolution failed: {error}"),
            );
            None
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_tuic_udp_direct(
    connection: quinn::Connection,
    assoc_id: u16,
    generation: u64,
    mut rx: mpsc::Receiver<Packet>,
    first: Packet,
    first_metadata: Metadata,
    decision: rewrite_rules::Decision,
    target: SocketAddr,
    max_udp_relay_packet_size: usize,
    config: &Config,
    state: &Arc<RuntimeState>,
    shutdown: &CancellationToken,
    sessions: &tokio::sync::Mutex<HashMap<u16, TuicUdpSessionSlot>>,
) {
    let outbound = match crate::listener::bind_direct_udp_socket(target, config) {
        Ok(socket) => socket,
        Err(error) => {
            state.log("error", format!("tuic inbound UDP bind failed: {error}"));
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
                if !send_tuic_udp_to_client(
                    &connection,
                    assoc_id,
                    &destination,
                    &response[..length],
                    max_udp_relay_packet_size,
                    shutdown,
                    tracker.cancelled(),
                )
                .await
                {
                    break;
                }
                downloaded = downloaded.saturating_add(length as u64);
                // Downstream success counts as activity (push / long-lived replies).
                touch_udp_session(&mut *sessions.lock().await, assoc_id, generation);
            }
            message = rx.recv() => {
                let Some(message) = message else { break };
                let Some(destination) = message.addr.clone() else {
                    continue;
                };
                let mut metadata = first_metadata.clone();
                let Some((_decision, next_target)) =
                    route_tuic_udp_datagram(&mut metadata, destination, config, state).await
                else {
                    // Reject / unsupported: drop this datagram, keep association.
                    continue;
                };
                if outbound.send_to(&message.data, next_target).await.is_ok() {
                    uploaded = uploaded.saturating_add(message.data.len() as u64);
                    touch_udp_session(&mut *sessions.lock().await, assoc_id, generation);
                }
            }
        }
    }
    tracker.finish(uploaded, downloaded);
}

async fn send_tuic_udp_to_client<C>(
    connection: &quinn::Connection,
    assoc_id: u16,
    destination: &Destination,
    payload: &[u8],
    max_udp_relay_packet_size: usize,
    shutdown: &CancellationToken,
    tracker_cancelled: C,
) -> bool
where
    C: Future<Output = ()>,
{
    let send_all = async {
        let pkt_id = rand::random::<u16>();
        let max_payload = max_udp_relay_packet_size.max(1);
        if payload.len() <= max_payload {
            let packet = Packet {
                assoc_id,
                pkt_id,
                frag_total: 1,
                frag_id: 0,
                addr: Some(destination.clone()),
                data: payload.to_vec(),
            };
            let encoded =
                encode_packet(&packet).map_err(|error| std::io::Error::other(error.to_string()))?;
            connection
                .send_datagram(Bytes::from(encoded))
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            return Ok::<(), std::io::Error>(());
        }
        let frag_count = u8::try_from(payload.len().div_ceil(max_payload).max(1))
            .map_err(|_| std::io::Error::other("TUIC UDP fragment count exceeds 255"))?;
        let mut offset = 0_usize;
        let mut frag_id = 0_u8;
        let mut addr = Some(destination.clone());
        while offset < payload.len() {
            let end = (offset + max_payload).min(payload.len());
            let fragment = Packet {
                assoc_id,
                pkt_id,
                frag_total: frag_count,
                frag_id,
                addr: addr.take(),
                data: payload[offset..end].to_vec(),
            };
            let encoded = encode_packet(&fragment)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            connection
                .send_datagram(Bytes::from(encoded))
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            offset = end;
            frag_id = frag_id.saturating_add(1);
        }
        Ok(())
    };
    tokio::select! {
        biased;
        () = shutdown.cancelled() => false,
        () = tracker_cancelled => false,
        result = tokio::time::timeout(TUIC_UDP_CLIENT_WRITE_TIMEOUT, send_all) => {
            matches!(result, Ok(Ok(())))
        }
    }
}

#[cfg(test)]
mod tuic_udp_tests {
    use super::*;

    fn incomplete_fragment(assoc_id: u16) -> Packet {
        Packet {
            assoc_id,
            pkt_id: 1,
            frag_total: 2,
            frag_id: 0,
            addr: Some(Destination {
                host: Host::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                port: 9,
            }),
            data: vec![0xab],
        }
    }

    #[test]
    fn defrag_map_refuses_insert_when_full_of_live_sessions() {
        let mut defrag = HashMap::new();
        let mut live = HashMap::new();
        for assoc_id in 0..TUIC_MAX_UDP_SESSIONS as u16 {
            let (tx, _rx) = mpsc::channel(1);
            live.insert(
                assoc_id,
                TuicUdpSessionSlot {
                    tx,
                    last_used: Instant::now(),
                    cancel: CancellationToken::new(),
                    generation: u64::from(assoc_id) + 1,
                },
            );
            assert!(
                try_feed_defrag(&mut defrag, &live, incomplete_fragment(assoc_id)).is_none(),
                "incomplete fragment should not reassemble"
            );
        }
        assert_eq!(defrag.len(), TUIC_MAX_UDP_SESSIONS);
        let overflow_id = TUIC_MAX_UDP_SESSIONS as u16;
        assert!(
            try_feed_defrag(&mut defrag, &live, incomplete_fragment(overflow_id)).is_none(),
            "must drop when full of live-session defrag entries"
        );
        assert!(
            !defrag.contains_key(&overflow_id),
            "overflow session must not get a defrag entry"
        );
        assert_eq!(defrag.len(), TUIC_MAX_UDP_SESSIONS);
    }

    #[test]
    fn defrag_map_reclaims_orphans_when_live_sessions_remain() {
        let mut defrag = HashMap::new();
        let (tx, _rx) = mpsc::channel(1);
        let live = HashMap::from([(
            0_u16,
            TuicUdpSessionSlot {
                tx,
                last_used: Instant::now(),
                cancel: CancellationToken::new(),
                generation: 1,
            },
        )]);
        for assoc_id in 0..TUIC_MAX_UDP_SESSIONS as u16 {
            let _ = try_feed_defrag(&mut defrag, &live, incomplete_fragment(assoc_id));
        }
        assert_eq!(defrag.len(), TUIC_MAX_UDP_SESSIONS);
        let new_id = TUIC_MAX_UDP_SESSIONS as u16 + 7;
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
        assert!(defrag.len() <= TUIC_MAX_UDP_SESSIONS);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_eviction_cancels_session_and_clears_defrag() {
        let cancel = CancellationToken::new();
        let (tx, _rx) = mpsc::channel(1);
        let mut sessions = HashMap::new();
        let mut defrag = HashMap::new();
        sessions.insert(
            42,
            TuicUdpSessionSlot {
                tx,
                last_used: Instant::now(),
                cancel: cancel.clone(),
                generation: 7,
            },
        );
        defrag.insert(42, Defragger::default());
        tokio::time::advance(TUIC_UDP_SESSION_IDLE + Duration::from_secs(1)).await;
        evict_idle_udp_sessions(&mut sessions, &mut defrag, TUIC_UDP_SESSION_IDLE);
        assert!(sessions.is_empty(), "idle session must be removed");
        assert!(defrag.is_empty(), "idle defrag entry must be removed");
        assert!(cancel.is_cancelled(), "idle eviction must cancel the token");
    }

    #[tokio::test(start_paused = true)]
    async fn old_worker_cleanup_does_not_remove_recreated_session() {
        let sessions = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let defrag = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let assoc_id = 9_u16;
        let old_cancel = CancellationToken::new();
        {
            let (tx, _rx) = mpsc::channel(1);
            sessions.lock().await.insert(
                assoc_id,
                TuicUdpSessionSlot {
                    tx,
                    last_used: Instant::now(),
                    cancel: old_cancel.clone(),
                    generation: 1,
                },
            );
            defrag.lock().await.insert(assoc_id, Defragger::default());
        }

        {
            let mut sessions_guard = sessions.lock().await;
            let mut defrag_guard = defrag.lock().await;
            tokio::time::advance(TUIC_UDP_SESSION_IDLE + Duration::from_secs(1)).await;
            evict_idle_udp_sessions(
                &mut sessions_guard,
                &mut defrag_guard,
                TUIC_UDP_SESSION_IDLE,
            );
        }
        assert!(old_cancel.is_cancelled());
        assert!(sessions.lock().await.is_empty());

        let new_cancel = CancellationToken::new();
        {
            let (tx, _rx) = mpsc::channel(1);
            sessions.lock().await.insert(
                assoc_id,
                TuicUdpSessionSlot {
                    tx,
                    last_used: Instant::now(),
                    cancel: new_cancel.clone(),
                    generation: 2,
                },
            );
            defrag.lock().await.insert(assoc_id, Defragger::default());
        }

        remove_udp_session_if_owner(&sessions, &defrag, assoc_id, 1).await;
        let sessions_guard = sessions.lock().await;
        let slot = sessions_guard
            .get(&assoc_id)
            .expect("recreated session must survive old worker cleanup");
        assert_eq!(slot.generation, 2);
        assert!(!new_cancel.is_cancelled());
        drop(sessions_guard);
        assert!(
            defrag.lock().await.contains_key(&assoc_id),
            "recreated defrag must survive old worker cleanup"
        );

        remove_udp_session_if_owner(&sessions, &defrag, assoc_id, 2).await;
        assert!(sessions.lock().await.is_empty());
        assert!(defrag.lock().await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_cleanup_cannot_drop_recreated_defrag() {
        for round in 0..256_u16 {
            let sessions = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
            let defrag = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
            let assoc_id = round;
            {
                let (tx, _rx) = mpsc::channel(1);
                sessions.lock().await.insert(
                    assoc_id,
                    TuicUdpSessionSlot {
                        tx,
                        last_used: Instant::now(),
                        cancel: CancellationToken::new(),
                        generation: 1,
                    },
                );
                defrag.lock().await.insert(assoc_id, Defragger::default());
            }

            let cleanup_sessions = Arc::clone(&sessions);
            let cleanup_defrag = Arc::clone(&defrag);
            let cleanup = tokio::spawn(async move {
                remove_udp_session_if_owner(&cleanup_sessions, &cleanup_defrag, assoc_id, 1).await;
            });

            let recreate_sessions = Arc::clone(&sessions);
            let recreate_defrag = Arc::clone(&defrag);
            let recreate = tokio::spawn(async move {
                loop {
                    let mut sessions_guard = recreate_sessions.lock().await;
                    let stale = sessions_guard
                        .get(&assoc_id)
                        .is_some_and(|slot| slot.generation == 1);
                    if stale {
                        drop(sessions_guard);
                        tokio::task::yield_now().await;
                        continue;
                    }
                    let (tx, _rx) = mpsc::channel(1);
                    sessions_guard.insert(
                        assoc_id,
                        TuicUdpSessionSlot {
                            tx,
                            last_used: Instant::now(),
                            cancel: CancellationToken::new(),
                            generation: 2,
                        },
                    );
                    recreate_defrag
                        .lock()
                        .await
                        .insert(assoc_id, Defragger::default());
                    break;
                }
            });

            cleanup.await.expect("cleanup join");
            recreate.await.expect("recreate join");

            let sessions_guard = sessions.lock().await;
            let defrag_guard = defrag.lock().await;
            match sessions_guard.get(&assoc_id).map(|slot| slot.generation) {
                Some(2) => assert!(
                    defrag_guard.contains_key(&assoc_id),
                    "round {round}: gen2 session must keep its defrag entry"
                ),
                None => assert!(
                    !defrag_guard.contains_key(&assoc_id),
                    "round {round}: no session implies no defrag left by cleanup"
                ),
                Some(other) => panic!("round {round}: unexpected generation {other}"),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn downlink_touch_keeps_session_from_idle_eviction() {
        let (tx, _rx) = mpsc::channel(1);
        let mut sessions = HashMap::new();
        let mut defrag = HashMap::new();
        sessions.insert(
            3,
            TuicUdpSessionSlot {
                tx,
                last_used: Instant::now(),
                cancel: CancellationToken::new(),
                generation: 11,
            },
        );
        defrag.insert(3, Defragger::default());
        tokio::time::advance(TUIC_UDP_SESSION_IDLE - Duration::from_secs(5)).await;
        touch_udp_session(&mut sessions, 3, 11);
        tokio::time::advance(Duration::from_secs(10)).await;
        evict_idle_udp_sessions(&mut sessions, &mut defrag, TUIC_UDP_SESSION_IDLE);
        assert!(
            sessions.contains_key(&3),
            "fresh downlink activity must refresh idle clock"
        );
        tokio::time::advance(TUIC_UDP_SESSION_IDLE + Duration::from_secs(1)).await;
        touch_udp_session(&mut sessions, 3, 99);
        evict_idle_udp_sessions(&mut sessions, &mut defrag, TUIC_UDP_SESSION_IDLE);
        assert!(
            sessions.is_empty(),
            "stale generation must not prevent idle eviction"
        );
    }

    #[test]
    fn congestion_controller_mapping() {
        assert_eq!(
            map_congestion_controller("cubic"),
            CongestionController::Cubic
        );
        assert_eq!(map_congestion_controller("bbr"), CongestionController::Bbr);
        assert_eq!(
            map_congestion_controller("new_reno"),
            CongestionController::NewReno
        );
        assert_eq!(
            map_congestion_controller("new-reno"),
            CongestionController::NewReno
        );
    }
}

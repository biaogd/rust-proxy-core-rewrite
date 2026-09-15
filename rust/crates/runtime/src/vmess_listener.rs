//! IN-E named `type: vmess` inbound (TLS, optional WSS / gRPC Gun).
//!
//! After the TLS handshake (and optional WebSocket upgrade or Gun stream),
//! `accept_vmess_request` authenticates the AEAD AuthID (`alterId = 0` only)
//! and decodes the destination; TCP joins `serve_shadowsocks_connection`
//! after `into_tcp_relay`, and UDP uses standard body-record datagrams or
//! Mux/XUDP multi-destination frames (wire-identical to VLESS XUDP inside
//! VMess body records).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use rewrite_config::{Config, ControllerTls, VmessInboundConfig};
use rewrite_inbound::BoxedInboundStream;
use rewrite_model::{Destination, Host, InboundProtocol, Metadata, Network, unmap_ip};
use rewrite_protocol_vmess::{
    AuthIdReplayCache, DEFAULT_AUTH_ID_REPLAY_CAPACITY, VmessAcceptOptions, VmessCommand,
    VmessServerSession, VmessServerWriter, VmessUserEntry, VmessXudpReadBuffer,
    accept_vmess_request, encode_xudp_server_frame, uuid_table,
};
use rewrite_rules::Route;
use rewrite_state::RuntimeState;
use rewrite_transport::{BoxedStream, V2rayGrpcServerConnection, accept_websocket_path};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::listener::{UdpSessionMode, resolve_udp_target, resolved_route, udp_session_mode};
use crate::tcp::{
    apply_host_mapping, mode_decision, resolve_rematch_target, serve_shadowsocks_connection,
};
use crate::types::RuntimeError;

const VMESS_MAX_INBOUND_CONNECTIONS: usize = 1024;
const VMESS_MAX_GRPC_STREAMS: usize = 256;
const VMESS_GRPC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const VMESS_UDP_CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const VMESS_XUDP_MAX_SESSIONS: usize = 64;
const VMESS_XUDP_SESSION_IDLE: Duration = Duration::from_secs(60);
const VMESS_XUDP_IDLE_SWEEP: Duration = Duration::from_secs(10);

type XudpReply = (u16, SocketAddr, Vec<u8>);

/// One mux session owns a dedicated UDP socket so replies cannot demux by
/// destination address (multiple sessions may share the same remote target).
struct XudpMuxSession {
    socket: Arc<UdpSocket>,
    cancel: CancellationToken,
    reader: tokio::task::JoinHandle<()>,
    last_used: Instant,
}

impl Drop for XudpMuxSession {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.reader.abort();
    }
}

/// VMess Mux/XUDP session table (same lifecycle as VLESS `XudpMuxTable`).
struct XudpMuxTable {
    sessions: HashMap<u16, XudpMuxSession>,
    lru: VecDeque<u16>,
    max_sessions: usize,
    parent_cancel: CancellationToken,
}

impl Drop for XudpMuxTable {
    fn drop(&mut self) {
        self.shutdown_all();
    }
}

impl XudpMuxTable {
    fn new(max_sessions: usize, parent_cancel: CancellationToken) -> Self {
        Self {
            sessions: HashMap::new(),
            lru: VecDeque::new(),
            max_sessions: max_sessions.max(1),
            parent_cancel,
        }
    }

    fn touch(&mut self, session_id: u16) {
        if !self.sessions.contains_key(&session_id) {
            return;
        }
        self.lru.retain(|id| *id != session_id);
        self.lru.push_back(session_id);
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.last_used = Instant::now();
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.sessions.len()
    }

    #[cfg(test)]
    fn contains(&self, session_id: u16) -> bool {
        self.sessions.contains_key(&session_id)
    }

    fn get_socket(&self, session_id: u16) -> Option<Arc<UdpSocket>> {
        self.sessions
            .get(&session_id)
            .map(|session| Arc::clone(&session.socket))
    }

    fn evict_oldest(&mut self) -> Option<u16> {
        while let Some(session_id) = self.lru.pop_front() {
            if self.sessions.remove(&session_id).is_some() {
                return Some(session_id);
            }
        }
        None
    }

    fn evict_idle(&mut self, max_idle: Duration) {
        let now = Instant::now();
        let idle: Vec<u16> = self
            .sessions
            .iter()
            .filter(|(_, session)| now.duration_since(session.last_used) > max_idle)
            .map(|(session_id, _)| *session_id)
            .collect();
        for session_id in idle {
            let _ = self.sessions.remove(&session_id);
            self.lru.retain(|id| *id != session_id);
        }
    }

    fn insert_session(
        &mut self,
        session_id: u16,
        socket: UdpSocket,
        reply_tx: mpsc::Sender<XudpReply>,
    ) -> Arc<UdpSocket> {
        if self.sessions.contains_key(&session_id) {
            let _ = self.sessions.remove(&session_id);
            self.lru.retain(|id| *id != session_id);
        } else {
            self.evict_idle(VMESS_XUDP_SESSION_IDLE);
            while self.sessions.len() >= self.max_sessions {
                let _ = self.evict_oldest();
            }
        }
        let socket = Arc::new(socket);
        let cancel = self.parent_cancel.child_token();
        let reader =
            spawn_xudp_session_reader(session_id, Arc::clone(&socket), cancel.clone(), reply_tx);
        self.lru.push_back(session_id);
        self.sessions.insert(
            session_id,
            XudpMuxSession {
                socket: Arc::clone(&socket),
                cancel,
                reader,
                last_used: Instant::now(),
            },
        );
        socket
    }

    fn shutdown_all(&mut self) {
        self.sessions.clear();
        self.lru.clear();
    }
}

fn spawn_xudp_session_reader(
    session_id: u16,
    socket: Arc<UdpSocket>,
    cancel: CancellationToken,
    reply_tx: mpsc::Sender<XudpReply>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_536];
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                received = socket.recv_from(&mut buffer) => {
                    let Ok((length, source)) = received else { break };
                    let payload = buffer[..length].to_vec();
                    if reply_tx.send((session_id, source, payload)).await.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

async fn ensure_xudp_session(
    table: &mut XudpMuxTable,
    session_id: u16,
    bind_target: SocketAddr,
    config: &Config,
    reply_tx: &mpsc::Sender<XudpReply>,
) -> Option<Arc<UdpSocket>> {
    table.evict_idle(VMESS_XUDP_SESSION_IDLE);
    if let Some(socket) = table.get_socket(session_id) {
        table.touch(session_id);
        return Some(socket);
    }
    let socket = crate::listener::bind_direct_udp_socket(bind_target, config).ok()?;
    Some(table.insert_session(session_id, socket, reply_tx.clone()))
}

pub(crate) struct VmessListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    users: HashMap<[u8; 16], VmessUserEntry>,
    inbound_name: String,
    listen: SocketAddr,
    ws_path: Option<String>,
    grpc_service_name: Option<String>,
}

impl VmessListener {
    pub(crate) async fn bind(
        config: &VmessInboundConfig,
        clock: Arc<rewrite_services::AdjustedClock>,
    ) -> Result<Self, RuntimeError> {
        let tls = rewrite_controller::prepare_tls_config(
            &ControllerTls {
                certificate: config.certificate.clone(),
                private_key: config.private_key.clone(),
                client_auth_type: String::new(),
                client_auth_cert: String::new(),
                ech_key: String::new(),
            },
            clock,
        )
        .map_err(RuntimeError::Listener)?;
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(RuntimeError::Listener)?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            users: uuid_table(config.users.iter().map(|user| {
                (
                    user.uuid.as_str(),
                    VmessUserEntry {
                        username: user.username.clone(),
                    },
                )
            })),
            inbound_name: config.name.clone(),
            listen: config.listen,
            ws_path: config.ws_path.clone(),
            grpc_service_name: config.grpc_service_name.clone(),
        })
    }
}

struct VmessInboundStream<S> {
    inner: S,
    local: SocketAddr,
    peer: SocketAddr,
}

impl<S> VmessInboundStream<S> {
    fn new(inner: S, local: SocketAddr, peer: SocketAddr) -> Self {
        Self { inner, local, peer }
    }
}

impl<S> AsyncRead for VmessInboundStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for VmessInboundStream<S>
where
    S: AsyncWrite + Unpin,
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

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> rewrite_inbound::InboundStream for VmessInboundStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer)
    }
}

pub(super) async fn run_vmess_listener(
    listener: VmessListener,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let VmessListener {
        listener,
        acceptor,
        users,
        inbound_name,
        listen,
        ws_path,
        grpc_service_name,
    } = listener;
    let replay_cache = Arc::new(std::sync::Mutex::new(AuthIdReplayCache::new(
        DEFAULT_AUTH_ID_REPLAY_CAPACITY,
    )));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((tcp, peer)) = accepted else {
                    state.log("error", "vmess inbound accept failed");
                    break;
                };
                let connection_config = Arc::clone(&*config.borrow());
                if !connection_config.permits_inbound(peer.ip()) {
                    continue;
                }
                if connections.len() >= VMESS_MAX_INBOUND_CONNECTIONS {
                    state.log(
                        "warning",
                        format!(
                            "vmess inbound connection limit reached ({VMESS_MAX_INBOUND_CONNECTIONS})"
                        ),
                    );
                    continue;
                }
                let local = tcp.local_addr().unwrap_or(listen);
                let acceptor = acceptor.clone();
                let users = users.clone();
                let connection_state = Arc::clone(&state);
                let connection_dns = Arc::clone(&dns_service);
                let connection_shutdown = shutdown.child_token();
                let connection_inbound_name = inbound_name.clone();
                let connection_ws_path = ws_path.clone();
                let connection_grpc_service = grpc_service_name.clone();
                let connection_replay = Arc::clone(&replay_cache);
                connections.spawn(async move {
                    Box::pin(handle_vmess_inbound(
                        tcp,
                        peer,
                        local,
                        acceptor,
                        users,
                        connection_config,
                        connection_state,
                        connection_dns,
                        connection_shutdown,
                        connection_inbound_name,
                        connection_ws_path,
                        connection_grpc_service,
                        connection_replay,
                    ))
                    .await;
                });
            }
            Some(result) = connections.join_next() => {
                if let Err(error) = result {
                    state.log("error", format!("vmess inbound task failed: {error}"));
                }
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

#[allow(clippy::too_many_arguments)]
async fn handle_vmess_inbound(
    tcp: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    acceptor: TlsAcceptor,
    users: HashMap<[u8; 16], VmessUserEntry>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
    inbound_name: String,
    ws_path: Option<String>,
    grpc_service_name: Option<String>,
    replay_cache: Arc<std::sync::Mutex<AuthIdReplayCache>>,
) {
    let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            state.log(
                "error",
                format!("vmess inbound TLS handshake failed: {error}"),
            );
            return;
        }
        Err(_) => {
            state.log("error", "vmess inbound TLS handshake timed out");
            return;
        }
    };

    if let Some(service_name) = grpc_service_name {
        serve_vmess_grpc_connection(
            tls,
            service_name,
            peer,
            local,
            users,
            config,
            state,
            dns_service,
            shutdown,
            inbound_name,
            replay_cache,
        )
        .await;
        return;
    }

    if let Some(path) = ws_path {
        let websocket =
            match tokio::time::timeout(Duration::from_secs(10), accept_websocket_path(tls, &path))
                .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    state.log(
                        "error",
                        format!("vmess inbound WebSocket upgrade failed: {error}"),
                    );
                    return;
                }
                Err(_) => {
                    state.log("error", "vmess inbound WebSocket upgrade timed out");
                    return;
                }
            };
        Box::pin(dispatch_vmess_session(
            websocket,
            peer,
            local,
            users,
            config,
            state,
            dns_service,
            shutdown,
            inbound_name,
            replay_cache,
        ))
        .await;
        return;
    }

    Box::pin(dispatch_vmess_session(
        tls,
        peer,
        local,
        users,
        config,
        state,
        dns_service,
        shutdown,
        inbound_name,
        replay_cache,
    ))
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn serve_vmess_grpc_connection<S>(
    stream: S,
    service_name: String,
    peer: SocketAddr,
    local: SocketAddr,
    users: HashMap<[u8; 16], VmessUserEntry>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
    inbound_name: String,
    replay_cache: Arc<std::sync::Mutex<AuthIdReplayCache>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = tokio::select! {
        () = shutdown.cancelled() => return,
        result = tokio::time::timeout(
            VMESS_GRPC_HANDSHAKE_TIMEOUT,
            V2rayGrpcServerConnection::handshake(stream, &service_name),
        ) => match result {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                state.log(
                    "error",
                    format!("vmess inbound gRPC handshake failed: {error}"),
                );
                return;
            }
            Err(_) => {
                state.log("error", "vmess inbound gRPC handshake timed out");
                return;
            }
        },
    };
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = connection.accept() => {
                match accepted {
                    Some(Ok(stream)) => {
                        if streams.len() >= VMESS_MAX_GRPC_STREAMS {
                            state.log(
                                "warning",
                                format!(
                                    "vmess inbound gRPC stream limit reached ({VMESS_MAX_GRPC_STREAMS})"
                                ),
                            );
                            continue;
                        }
                        let users = users.clone();
                        let config = Arc::clone(&config);
                        let state = Arc::clone(&state);
                        let dns_service = Arc::clone(&dns_service);
                        let shutdown = shutdown.child_token();
                        let inbound_name = inbound_name.clone();
                        let replay_cache = Arc::clone(&replay_cache);
                        streams.spawn(async move {
                            dispatch_vmess_session(
                                stream,
                                peer,
                                local,
                                users,
                                config,
                                state,
                                dns_service,
                                shutdown,
                                inbound_name,
                                replay_cache,
                            )
                            .await;
                        });
                    }
                    Some(Err(error)) => {
                        state.log(
                            "error",
                            format!("vmess inbound gRPC stream accept failed: {error}"),
                        );
                        break;
                    }
                    None => break,
                }
            }
            Some(result) = streams.join_next() => {
                if let Err(error) = result {
                    state.log("error", format!("vmess inbound gRPC stream task failed: {error}"));
                }
            }
        }
    }
    streams.abort_all();
    while streams.join_next().await.is_some() {}
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_vmess_session<S>(
    mut stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    users: HashMap<[u8; 16], VmessUserEntry>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
    inbound_name: String,
    replay_cache: Arc<std::sync::Mutex<AuthIdReplayCache>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let accepted = match tokio::time::timeout(
        Duration::from_secs(10),
        accept_vmess_request(
            &mut stream,
            &users,
            VmessAcceptOptions {
                replay_cache: Some(replay_cache.as_ref()),
                ..VmessAcceptOptions::default()
            },
        ),
    )
    .await
    {
        Ok(Ok(accepted)) => accepted,
        Ok(Err(_)) => return,
        Err(_) => {
            state.log("error", "vmess inbound authentication timed out");
            return;
        }
    };
    let (request, session) = accepted;

    match request.command {
        VmessCommand::Tcp => {
            serve_vmess_tcp(
                stream,
                session,
                peer,
                local,
                request.destination,
                request.username,
                inbound_name,
                &config,
                &state,
                &dns_service,
                &shutdown,
            )
            .await;
        }
        VmessCommand::Udp => {
            serve_vmess_udp(
                stream,
                session,
                peer,
                local,
                request.destination,
                request.username,
                inbound_name,
                &config,
                &state,
                &shutdown,
            )
            .await;
        }
        VmessCommand::Mux => {
            serve_vmess_xudp(
                stream,
                session,
                peer,
                local,
                request.username,
                inbound_name,
                &config,
                &state,
                &shutdown,
            )
            .await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_vmess_tcp<S>(
    stream: S,
    session: VmessServerSession,
    peer: SocketAddr,
    local: SocketAddr,
    destination: Destination,
    username: String,
    inbound_name: String,
    config: &Config,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    shutdown: &CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let relay: BoxedStream = session.into_tcp_relay(Box::new(stream));
    let mut metadata = Metadata::new(destination, InboundProtocol::Vmess);
    metadata.network = Network::Tcp;
    metadata.source_ip = Some(unmap_ip(peer.ip()));
    metadata.source_port = peer.port();
    metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut metadata.inbound_name);
    metadata.inbound_user = username;
    let client: BoxedInboundStream = Box::new(VmessInboundStream::new(relay, local, peer));
    serve_shadowsocks_connection(client, metadata, config, state, dns_service, shutdown).await;
}

#[allow(clippy::too_many_arguments)]
async fn serve_vmess_udp<S>(
    stream: S,
    session: VmessServerSession,
    peer: SocketAddr,
    local: SocketAddr,
    destination: Destination,
    username: String,
    inbound_name: String,
    config: &Config,
    state: &Arc<RuntimeState>,
    shutdown: &CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut metadata = Metadata::new(destination, InboundProtocol::Vmess);
    metadata.network = Network::Udp;
    metadata.source_ip = Some(unmap_ip(peer.ip()));
    metadata.source_port = peer.port();
    metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut metadata.inbound_name);
    metadata.inbound_user = username;

    let fake_host = apply_host_mapping(&mut metadata, config, state);
    let decision = mode_decision(config, state).unwrap_or_else(|| config.rules.evaluate(&metadata));
    let Some((decision, outbound_target, _)) =
        resolve_rematch_target(decision, &mut metadata, config, state)
    else {
        return;
    };
    let route = resolved_route(&outbound_target, config);
    if matches!(route, Route::Reject | Route::RejectDrop) {
        return;
    }
    let Some(mode) = udp_session_mode(&outbound_target, config) else {
        state.log(
            "error",
            format!(
                "vmess inbound UDP target {} is unsupported",
                decision.target
            ),
        );
        return;
    };
    state.log(
        "info",
        format!(
            "[UDP] {} --> {} match {} using {} (VMess)",
            metadata.source_port,
            metadata.destination.authority(),
            decision.matched_kind.as_deref().unwrap_or("none"),
            decision.target
        ),
    );
    match mode {
        UdpSessionMode::Direct => {
            serve_vmess_udp_direct(
                stream, session, metadata, fake_host, decision, config, state, shutdown,
            )
            .await;
        }
        _ => {
            state.log(
                "error",
                format!(
                    "vmess inbound UDP target {} is unsupported in IN-E",
                    decision.target
                ),
            );
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_vmess_udp_direct<S>(
    stream: S,
    session: VmessServerSession,
    metadata: Metadata,
    fake_host: Option<String>,
    decision: rewrite_rules::Decision,
    config: &Config,
    state: &Arc<RuntimeState>,
    shutdown: &CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let target = match resolve_udp_target(&metadata, fake_host.as_deref(), config).await {
        Ok(target) => target,
        Err(error) => {
            state.log(
                "error",
                format!("vmess inbound UDP resolution failed: {error}"),
            );
            return;
        }
    };
    let outbound = match crate::listener::bind_direct_udp_socket(target, config) {
        Ok(socket) => socket,
        Err(error) => {
            state.log("error", format!("vmess inbound UDP bind failed: {error}"));
            return;
        }
    };
    let tracker = state.register(
        &metadata,
        &decision.target,
        decision.matched_kind.as_deref(),
    );
    let mut uploaded = 0_u64;
    let mut downloaded = 0_u64;

    let (mut reader, mut writer) = tokio::io::split(stream);
    let (mut body_reader, mut body_writer) = session.into_udp_halves();
    let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(16);
    let reader_shutdown = shutdown.child_token();
    let reader_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = reader_shutdown.cancelled() => break,
                frame = body_reader.read_body(&mut reader) => {
                    match frame {
                        Ok(payload) => {
                            if frame_tx.send(payload).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    loop {
        let mut response = vec![0_u8; 65_536];
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tracker.cancelled() => break,
            received = outbound.recv_from(&mut response) => {
                let Ok((length, _source)) = received else { break };
                if !write_vmess_udp_to_client(
                    &mut body_writer,
                    &mut writer,
                    &response[..length],
                    shutdown,
                    tracker.cancelled(),
                )
                .await
                {
                    break;
                }
                downloaded = downloaded.saturating_add(length as u64);
            }
            payload = frame_rx.recv() => {
                let Some(payload) = payload else { break };
                if outbound.send_to(&payload, target).await.is_ok() {
                    uploaded = uploaded.saturating_add(payload.len() as u64);
                }
            }
        }
    }
    reader_task.abort();
    let _ = reader_task.await;
    tracker.finish(uploaded, downloaded);
}

async fn write_vmess_udp_to_client<W, C>(
    body_writer: &mut VmessServerWriter,
    writer: &mut W,
    payload: &[u8],
    shutdown: &CancellationToken,
    tracker_cancelled: C,
) -> bool
where
    W: AsyncWrite + Unpin,
    C: Future<Output = ()>,
{
    tokio::select! {
        biased;
        () = shutdown.cancelled() => false,
        () = tracker_cancelled => false,
        result = tokio::time::timeout(
            VMESS_UDP_CLIENT_WRITE_TIMEOUT,
            body_writer.write_body(writer, payload),
        ) => matches!(result, Ok(Ok(()))),
    }
}

async fn write_vmess_xudp_to_client<W, C>(
    body_writer: &mut VmessServerWriter,
    writer: &mut W,
    session_id: u16,
    destination: &Destination,
    payload: &[u8],
    shutdown: &CancellationToken,
    tracker_cancelled: C,
) -> bool
where
    W: AsyncWrite + Unpin,
    C: Future<Output = ()>,
{
    let Ok(frame) = encode_xudp_server_frame(session_id, destination, payload) else {
        return false;
    };
    tokio::select! {
        biased;
        () = shutdown.cancelled() => false,
        () = tracker_cancelled => false,
        result = tokio::time::timeout(
            VMESS_UDP_CLIENT_WRITE_TIMEOUT,
            body_writer.write_body(writer, &frame),
        ) => matches!(result, Ok(Ok(()))),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_vmess_xudp<S>(
    stream: S,
    session: VmessServerSession,
    peer: SocketAddr,
    local: SocketAddr,
    username: String,
    inbound_name: String,
    config: &Config,
    state: &Arc<RuntimeState>,
    shutdown: &CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (mut body_reader, mut body_writer) = session.into_udp_halves();
    let mut xudp_buffer = VmessXudpReadBuffer::new();

    let first = match tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let record = body_reader.read_body(&mut reader).await?;
            xudp_buffer.push(&record);
            if let Some(packet) = xudp_buffer.try_parse_client_packet()? {
                return Ok::<_, rewrite_protocol_vmess::VmessProtocolError>(packet);
            }
        }
    })
    .await
    {
        Ok(Ok(packet)) => packet,
        _ => return,
    };
    let (first_session_id, first_destination, first_payload) = first;

    let mut base_metadata = Metadata::new(first_destination.clone(), InboundProtocol::Vmess);
    base_metadata.network = Network::Udp;
    base_metadata.source_ip = Some(unmap_ip(peer.ip()));
    base_metadata.source_port = peer.port();
    base_metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut base_metadata.inbound_name);
    base_metadata.inbound_user = username;

    let Some((first_decision, first_target)) =
        route_xudp_datagram(&mut base_metadata, first_destination, config, state).await
    else {
        return;
    };
    state.log(
        "info",
        format!(
            "[UDP] {} --> {} match {} using {} (VMess XUDP)",
            base_metadata.source_port,
            base_metadata.destination.authority(),
            first_decision.matched_kind.as_deref().unwrap_or("none"),
            first_decision.target
        ),
    );

    let (reply_tx, mut reply_rx) = mpsc::channel::<XudpReply>(32);
    let mut sessions = XudpMuxTable::new(VMESS_XUDP_MAX_SESSIONS, shutdown.child_token());
    let Some(first_socket) = ensure_xudp_session(
        &mut sessions,
        first_session_id,
        first_target,
        config,
        &reply_tx,
    )
    .await
    else {
        state.log(
            "error",
            format!("vmess inbound XUDP bind failed for session {first_session_id}"),
        );
        return;
    };
    let tracker = state.register(
        &base_metadata,
        &first_decision.target,
        first_decision.matched_kind.as_deref(),
    );
    let mut uploaded = 0_u64;
    let mut downloaded = 0_u64;
    if first_socket
        .send_to(&first_payload, first_target)
        .await
        .is_err()
    {
        sessions.shutdown_all();
        tracker.finish(uploaded, downloaded);
        return;
    }
    uploaded = uploaded.saturating_add(first_payload.len() as u64);

    let (frame_tx, mut frame_rx) = mpsc::channel::<(u16, Destination, Vec<u8>)>(16);
    let reader_shutdown = shutdown.child_token();
    let reader_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = reader_shutdown.cancelled() => break,
                record = body_reader.read_body(&mut reader) => {
                    match record {
                        Ok(record) => {
                            xudp_buffer.push(&record);
                            loop {
                                match xudp_buffer.try_parse_client_packet() {
                                    Ok(Some(packet)) => {
                                        if frame_tx.send(packet).await.is_err() {
                                            return;
                                        }
                                    }
                                    Ok(None) => break,
                                    Err(_) => return,
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    let mut idle_sweep = tokio::time::interval(VMESS_XUDP_IDLE_SWEEP);
    idle_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    idle_sweep.tick().await;

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tracker.cancelled() => break,
            _ = idle_sweep.tick() => {
                sessions.evict_idle(VMESS_XUDP_SESSION_IDLE);
            }
            reply = reply_rx.recv() => {
                let Some((session_id, source, payload)) = reply else { break };
                let destination = Destination {
                    host: Host::Ip(unmap_ip(source.ip())),
                    port: source.port(),
                };
                sessions.touch(session_id);
                if !write_vmess_xudp_to_client(
                    &mut body_writer,
                    &mut writer,
                    session_id,
                    &destination,
                    &payload,
                    shutdown,
                    tracker.cancelled(),
                )
                .await
                {
                    break;
                }
                downloaded = downloaded.saturating_add(payload.len() as u64);
            }
            packet = frame_rx.recv() => {
                let Some((session_id, destination, payload)) = packet else { break };
                let mut packet_metadata = base_metadata.clone();
                let Some((_decision, target)) =
                    route_xudp_datagram(&mut packet_metadata, destination, config, state).await
                else {
                    continue;
                };
                let Some(socket) =
                    ensure_xudp_session(&mut sessions, session_id, target, config, &reply_tx)
                        .await
                else {
                    state.log(
                        "error",
                        format!("vmess inbound XUDP bind failed for session {session_id}"),
                    );
                    continue;
                };
                if socket.send_to(&payload, target).await.is_ok() {
                    uploaded = uploaded.saturating_add(payload.len() as u64);
                }
            }
        }
    }
    sessions.shutdown_all();
    reader_task.abort();
    let _ = reader_task.await;
    tracker.finish(uploaded, downloaded);
}

async fn route_xudp_datagram(
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
                "[UDP] {} --> {} match {} using {} (VMess XUDP)",
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
                "vmess inbound XUDP target {} is unsupported in IN-E",
                decision.target
            ),
        );
        return None;
    }
    let target = match resolve_udp_target(metadata, fake_host.as_deref(), config).await {
        Ok(target) => target,
        Err(error) => {
            state.log(
                "error",
                format!("vmess inbound XUDP resolution failed: {error}"),
            );
            return None;
        }
    };
    Some((decision, target))
}

#[cfg(test)]
mod xudp_table_tests {
    use super::*;

    #[tokio::test]
    async fn xudp_table_evicts_lru_when_at_capacity() {
        let (reply_tx, _reply_rx) = mpsc::channel::<XudpReply>(8);
        let mut table = XudpMuxTable::new(2, CancellationToken::new());
        for session_id in [1_u16, 2, 3] {
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            table.insert_session(session_id, socket, reply_tx.clone());
        }
        assert_eq!(table.len(), 2);
        assert!(!table.contains(1));
        assert!(table.contains(2));
        assert!(table.contains(3));
        table.shutdown_all();
    }

    #[tokio::test]
    async fn xudp_parent_cancel_stops_session_readers() {
        let parent = CancellationToken::new();
        let (reply_tx, mut reply_rx) = mpsc::channel::<XudpReply>(4);
        let mut table = XudpMuxTable::new(4, parent.child_token());
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        table.insert_session(1, socket, reply_tx);
        parent.cancel();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), reply_rx.recv())
                .await
                .expect("reader must observe parent cancel")
                .is_none()
        );
        table.shutdown_all();
    }
}

//! IN-D named `type: vless` inbound (TLS / REALITY, optional WSS / gRPC Gun).
//!
//! After the TLS or REALITY handshake (and optional WebSocket upgrade or Gun
//! stream), `accept_vless_request` authenticates the UUID and decodes the
//! destination; TCP joins the shared `serve_shadowsocks_connection` boundary
//! and UDP uses the standard fixed-destination framing or Mux/XUDP
//! multi-destination frames. Vision (`flow: xtls-rprx-vision`) is supported on
//! certificate TLS; REALITY is native-TCP only in this slice (no Vision).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use rewrite_config::{Config, ControllerTls, VlessInboundConfig};
use rewrite_inbound::BoxedInboundStream;
use rewrite_model::{Destination, Host, InboundProtocol, Metadata, Network, unmap_ip};
use rewrite_protocol_vless::{
    VisionStream, VlessCommand, VlessFlow, VlessServerStream, VlessUserEntry, accept_vless_request,
    read_vless_udp_payload, read_xudp_client_packet, uuid_table, write_vless_udp_payload,
    write_xudp_server_packet,
};
use rewrite_rules::Route;
use rewrite_state::RuntimeState;
use rewrite_transport::{
    BoxedStream, RealityAcceptOptions, RealityTlsAcceptor, V2rayGrpcServerConnection,
    VisionDirectControl, accept_reality, accept_vision_tls, accept_websocket_path,
    reality_acceptor,
};
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

const VLESS_MAX_INBOUND_CONNECTIONS: usize = 1024;
const VLESS_MAX_GRPC_STREAMS: usize = 256;
const VLESS_GRPC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound client-side UDP writes so a stalled reader cannot pin the select loop
/// past connection cancel / controller close.
const VLESS_UDP_CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap concurrent mux UDP associations on one VLESS TCP connection.
const VLESS_XUDP_MAX_SESSIONS: usize = 64;
/// Drop mux UDP associations idle longer than this.
const VLESS_XUDP_SESSION_IDLE: Duration = Duration::from_secs(60);
/// How often the association loop sweeps idle sessions.
const VLESS_XUDP_IDLE_SWEEP: Duration = Duration::from_secs(10);

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

struct XudpMuxTable {
    sessions: HashMap<u16, XudpMuxSession>,
    lru: VecDeque<u16>,
    max_sessions: usize,
    /// Parent cancel for the VLESS connection; session tokens are children so
    /// hot-reload / connection abort cancels readers even if the table Drop is
    /// raced with `JoinSet::abort_all`.
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

    /// Inserts a bound socket for `session_id`, spawning a dedicated reader.
    /// Evicts idle sessions first, then the least-recently-used session when at capacity.
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
            self.evict_idle(VLESS_XUDP_SESSION_IDLE);
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
    table.evict_idle(VLESS_XUDP_SESSION_IDLE);
    if let Some(socket) = table.get_socket(session_id) {
        table.touch(session_id);
        return Some(socket);
    }
    let socket = crate::listener::bind_direct_udp_socket(bind_target, config).ok()?;
    Some(table.insert_session(session_id, socket, reply_tx.clone()))
}

#[derive(Clone)]
enum VlessTlsAcceptor {
    Certificate(TlsAcceptor),
    Reality(RealityTlsAcceptor),
}

pub(crate) struct VlessListener {
    listener: TcpListener,
    acceptor: VlessTlsAcceptor,
    users: Arc<HashMap<[u8; 16], VlessUserEntry>>,
    vision_capable: bool,
    inbound_name: String,
    listen: SocketAddr,
    ws_path: Option<String>,
    grpc_service_name: Option<String>,
}

impl VlessListener {
    pub(crate) async fn bind(
        config: &VlessInboundConfig,
        clock: Arc<rewrite_services::AdjustedClock>,
    ) -> Result<Self, RuntimeError> {
        let acceptor = if let Some(reality) = config.reality.as_ref() {
            let options = RealityAcceptOptions {
                private_key: reality.private_key,
                short_ids: reality.short_ids.clone(),
                server_names: reality.server_names.clone(),
                max_time_difference: reality.max_time_difference,
            };
            let acceptor = reality_acceptor(&options).map_err(|error| {
                RuntimeError::Listener(std::io::Error::other(error.to_string()))
            })?;
            VlessTlsAcceptor::Reality(acceptor)
        } else {
            let certificate = config.certificate.clone().ok_or_else(|| {
                RuntimeError::Listener(std::io::Error::other("vless inbound missing certificate"))
            })?;
            let private_key = config.private_key.clone().ok_or_else(|| {
                RuntimeError::Listener(std::io::Error::other("vless inbound missing private-key"))
            })?;
            let mut tls = rewrite_controller::prepare_tls_config(
                &ControllerTls {
                    certificate,
                    private_key,
                    client_auth_type: String::new(),
                    client_auth_cert: String::new(),
                    ech_key: String::new(),
                },
                clock,
            )
            .map_err(RuntimeError::Listener)?;
            // Match Go plain-TCP VLESS: NextProtos only for WS/gRPC.
            rewrite_controller::apply_inbound_alpn(
                &mut tls,
                config.ws_path.is_some(),
                config.grpc_service_name.is_some(),
            );
            VlessTlsAcceptor::Certificate(TlsAcceptor::from(Arc::new(tls)))
        };
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(RuntimeError::Listener)?;
        let vision_capable = config
            .users
            .iter()
            .any(|user| user.flow == Some(rewrite_config::VlessFlow::XtlsRprxVision));
        Ok(Self {
            listener,
            acceptor,
            users: Arc::new(uuid_table(config.users.iter().map(|user| {
                (
                    user.uuid.as_str(),
                    VlessUserEntry {
                        username: user.username.clone(),
                        flow: user.flow.map(|flow| match flow {
                            rewrite_config::VlessFlow::XtlsRprxVision => VlessFlow::XtlsRprxVision,
                        }),
                    },
                )
            }))),
            vision_capable,
            inbound_name: config.name.clone(),
            listen: config.listen,
            ws_path: config.ws_path.clone(),
            grpc_service_name: config.grpc_service_name.clone(),
        })
    }
}

enum VlessInboundBody<S> {
    /// Response header not yet written (Go `serverConn` before first Write).
    Pending(VlessServerStream<S>),
    /// Response written — bare carrier (Go `WriterReplaceable` unwrap).
    Ready(S),
}

struct VlessInboundStream<S> {
    body: Option<VlessInboundBody<S>>,
    local: SocketAddr,
    peer: SocketAddr,
}

impl<S> VlessInboundStream<S> {
    fn from_server(inner: VlessServerStream<S>, local: SocketAddr, peer: SocketAddr) -> Self {
        Self {
            body: Some(VlessInboundBody::Pending(inner)),
            local,
            peer,
        }
    }

    fn from_ready(inner: S, local: SocketAddr, peer: SocketAddr) -> Self {
        Self {
            body: Some(VlessInboundBody::Ready(inner)),
            local,
            peer,
        }
    }

    fn try_peel_response(&mut self) {
        let should_peel = matches!(
            self.body.as_ref(),
            Some(VlessInboundBody::Pending(server)) if server.response_written()
        );
        if !should_peel {
            return;
        }
        if let Some(VlessInboundBody::Pending(server)) = self.body.take() {
            self.body = Some(VlessInboundBody::Ready(server.into_inner()));
        }
    }
}

impl<S> AsyncRead for VlessInboundStream<S>
where
    S: AsyncRead + Unpin + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.body.as_mut() {
            Some(VlessInboundBody::Pending(server)) => Pin::new(server).poll_read(cx, buf),
            Some(VlessInboundBody::Ready(inner)) => Pin::new(inner).poll_read(cx, buf),
            None => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "vless inbound stream peeled",
            ))),
        }
    }
}

impl<S> AsyncWrite for VlessInboundStream<S>
where
    S: AsyncWrite + Unpin + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = match self.body.as_mut() {
            Some(VlessInboundBody::Pending(server)) => Pin::new(server).poll_write(cx, buf),
            Some(VlessInboundBody::Ready(inner)) => Pin::new(inner).poll_write(cx, buf),
            None => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "vless inbound stream peeled",
                )));
            }
        };
        if matches!(result, Poll::Ready(Ok(_))) {
            self.try_peel_response();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.body.as_mut() {
            Some(VlessInboundBody::Pending(server)) => Pin::new(server).poll_flush(cx),
            Some(VlessInboundBody::Ready(inner)) => Pin::new(inner).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.body.as_mut() {
            Some(VlessInboundBody::Pending(server)) => Pin::new(server).poll_shutdown(cx),
            Some(VlessInboundBody::Ready(inner)) => Pin::new(inner).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl<S> rewrite_inbound::InboundStream for VlessInboundStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer)
    }
}

pub(super) async fn run_vless_listener(
    listener: VlessListener,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let VlessListener {
        listener,
        acceptor,
        users,
        vision_capable,
        inbound_name,
        listen,
        ws_path,
        grpc_service_name,
    } = listener;
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((tcp, peer)) = accepted else {
                    state.log("error", "vless inbound accept failed");
                    break;
                };
                // Match Go net.TCPConn default: TCP_NODELAY on.
                let _ = tcp.set_nodelay(true);
                let connection_config = Arc::clone(&*config.borrow());
                if !connection_config.permits_inbound(peer.ip()) {
                    continue;
                }
                if connections.len() >= VLESS_MAX_INBOUND_CONNECTIONS {
                    state.log(
                        "warning",
                        format!(
                            "vless inbound connection limit reached ({VLESS_MAX_INBOUND_CONNECTIONS})"
                        ),
                    );
                    continue;
                }
                let local = tcp.local_addr().unwrap_or(listen);
                let acceptor = acceptor.clone();
                let users = users.clone();
                let connection_vision_capable = vision_capable;
                let connection_state = Arc::clone(&state);
                let connection_dns = Arc::clone(&dns_service);
                let connection_shutdown = shutdown.child_token();
                let connection_inbound_name = inbound_name.clone();
                let connection_ws_path = ws_path.clone();
                let connection_grpc_service = grpc_service_name.clone();
                connections.spawn(async move {
                    Box::pin(handle_vless_inbound(
                        tcp,
                        peer,
                        local,
                        acceptor,
                        users,
                        connection_vision_capable,
                        connection_config,
                        connection_state,
                        connection_dns,
                        connection_shutdown,
                        connection_inbound_name,
                        connection_ws_path,
                        connection_grpc_service,
                    ))
                    .await;
                });
            }
            Some(result) = connections.join_next() => {
                if let Err(error) = result {
                    state.log("error", format!("vless inbound task failed: {error}"));
                }
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_vless_inbound(
    tcp: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    acceptor: VlessTlsAcceptor,
    users: Arc<HashMap<[u8; 16], VlessUserEntry>>,
    vision_capable: bool,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
    inbound_name: String,
    ws_path: Option<String>,
    grpc_service_name: Option<String>,
) {
    let vision_control = vision_capable.then(VisionDirectControl::default);
    let tls: BoxedStream = match acceptor {
        VlessTlsAcceptor::Reality(reality_acceptor) => {
            if vision_capable {
                state.log("error", "vless inbound REALITY does not support Vision yet");
                return;
            }
            match accept_reality(&reality_acceptor, tcp).await {
                Ok(stream) => stream,
                Err(error) => {
                    state.log(
                        "error",
                        format!("vless inbound REALITY handshake failed: {error}"),
                    );
                    return;
                }
            }
        }
        VlessTlsAcceptor::Certificate(acceptor) if vision_capable => {
            let control = vision_control
                .as_ref()
                .expect("vision control is present when vision_capable")
                .clone();
            match tokio::time::timeout(
                Duration::from_secs(10),
                accept_vision_tls(Box::new(tcp), acceptor, control),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    state.log(
                        "error",
                        format!("vless inbound Vision TLS handshake failed: {error}"),
                    );
                    return;
                }
                Err(_) => {
                    state.log("error", "vless inbound Vision TLS handshake timed out");
                    return;
                }
            }
        }
        VlessTlsAcceptor::Certificate(acceptor) => {
            match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                Ok(Ok(stream)) => Box::new(stream),
                Ok(Err(error)) => {
                    state.log(
                        "error",
                        format!("vless inbound TLS handshake failed: {error}"),
                    );
                    return;
                }
                Err(_) => {
                    state.log("error", "vless inbound TLS handshake timed out");
                    return;
                }
            }
        }
    };

    if let Some(service_name) = grpc_service_name {
        serve_vless_grpc_connection(
            tls,
            service_name,
            peer,
            local,
            users,
            None,
            config,
            state,
            dns_service,
            shutdown,
            inbound_name,
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
                        format!("vless inbound WebSocket upgrade failed: {error}"),
                    );
                    return;
                }
                Err(_) => {
                    state.log("error", "vless inbound WebSocket upgrade timed out");
                    return;
                }
            };
        Box::pin(dispatch_vless_session(
            websocket,
            peer,
            local,
            users,
            None,
            config,
            state,
            dns_service,
            shutdown,
            inbound_name,
        ))
        .await;
        return;
    }

    Box::pin(dispatch_vless_session(
        tls,
        peer,
        local,
        users,
        vision_control,
        config,
        state,
        dns_service,
        shutdown,
        inbound_name,
    ))
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn serve_vless_grpc_connection<S>(
    stream: S,
    service_name: String,
    peer: SocketAddr,
    local: SocketAddr,
    users: Arc<HashMap<[u8; 16], VlessUserEntry>>,
    vision_control: Option<VisionDirectControl>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
    inbound_name: String,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = tokio::select! {
        () = shutdown.cancelled() => return,
        result = tokio::time::timeout(
            VLESS_GRPC_HANDSHAKE_TIMEOUT,
            V2rayGrpcServerConnection::handshake(stream, &service_name),
        ) => match result {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                state.log(
                    "error",
                    format!("vless inbound gRPC handshake failed: {error}"),
                );
                return;
            }
            Err(_) => {
                state.log("error", "vless inbound gRPC handshake timed out");
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
                        if streams.len() >= VLESS_MAX_GRPC_STREAMS {
                            state.log(
                                "warning",
                                format!(
                                    "vless inbound gRPC stream limit reached ({VLESS_MAX_GRPC_STREAMS})"
                                ),
                            );
                            continue;
                        }
                        let users = users.clone();
                        let connection_vision_control = vision_control.clone();
                        let config = Arc::clone(&config);
                        let state = Arc::clone(&state);
                        let dns_service = Arc::clone(&dns_service);
                        let shutdown = shutdown.child_token();
                        let inbound_name = inbound_name.clone();
                        streams.spawn(async move {
                            dispatch_vless_session(
                                stream,
                                peer,
                                local,
                                users,
                                connection_vision_control,
                                config,
                                state,
                                dns_service,
                                shutdown,
                                inbound_name,
                            )
                            .await;
                        });
                    }
                    Some(Err(error)) => {
                        state.log(
                            "error",
                            format!("vless inbound gRPC stream accept failed: {error}"),
                        );
                        break;
                    }
                    None => break,
                }
            }
            Some(result) = streams.join_next() => {
                if let Err(error) = result {
                    state.log("error", format!("vless inbound gRPC stream task failed: {error}"));
                }
            }
        }
    }
    streams.abort_all();
    while streams.join_next().await.is_some() {}
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_vless_session<S>(
    stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    users: Arc<HashMap<[u8; 16], VlessUserEntry>>,
    vision_control: Option<VisionDirectControl>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
    inbound_name: String,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream = stream;
    let request = match tokio::time::timeout(
        Duration::from_secs(10),
        accept_vless_request(&mut stream, &users),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(_)) => return,
        Err(_) => {
            state.log("error", "vless inbound authentication timed out");
            return;
        }
    };

    // Go sing_vless.serverConn: coalesce [VERSION,0] with first write.
    let stream = VlessServerStream::new(stream);

    match request.command {
        VlessCommand::Tcp => {
            if request.flow == Some(VlessFlow::XtlsRprxVision) {
                let vision = VisionStream::new(Box::new(stream), request.uuid, vision_control);
                serve_vless_tcp(
                    VlessInboundStream::from_ready(vision, local, peer),
                    request.destination,
                    request.username,
                    inbound_name,
                    &config,
                    &state,
                    &dns_service,
                    &shutdown,
                )
                .await;
            } else {
                serve_vless_tcp(
                    VlessInboundStream::from_server(stream, local, peer),
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
        }
        VlessCommand::Udp => {
            serve_vless_udp(
                stream,
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
        VlessCommand::Mux => {
            serve_vless_xudp(
                stream,
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
async fn serve_vless_tcp<S>(
    client: VlessInboundStream<S>,
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
    let peer = client.peer;
    let local = client.local;
    let mut metadata = Metadata::new(destination, InboundProtocol::Vless);
    metadata.network = Network::Tcp;
    metadata.source_ip = Some(unmap_ip(peer.ip()));
    metadata.source_port = peer.port();
    metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut metadata.inbound_name);
    metadata.inbound_user = username;
    let client: BoxedInboundStream = Box::new(client);
    serve_shadowsocks_connection(client, metadata, config, state, dns_service, shutdown).await;
}

/// Standard-mode VLESS UDP: one fixed destination per association, framed as
/// a 2-byte big-endian length prefix followed by the payload. Mux/XUDP uses
/// [`serve_vless_xudp`] instead.
#[allow(clippy::too_many_arguments)]
async fn serve_vless_udp<S>(
    stream: S,
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
    let mut metadata = Metadata::new(destination, InboundProtocol::Vless);
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
                "vless inbound UDP target {} is unsupported",
                decision.target
            ),
        );
        return;
    };
    state.log(
        "info",
        format!(
            "[UDP] {} --> {} match {} using {} (VLESS)",
            metadata.source_port,
            metadata.destination.authority(),
            decision.matched_kind.as_deref().unwrap_or("none"),
            decision.target
        ),
    );
    match mode {
        UdpSessionMode::Direct => {
            serve_vless_udp_direct(
                stream, metadata, fake_host, decision, config, state, shutdown,
            )
            .await;
        }
        _ => {
            state.log(
                "error",
                format!(
                    "vless inbound UDP target {} is unsupported in IN-D",
                    decision.target
                ),
            );
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_vless_udp_direct<S>(
    stream: S,
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
                format!("vless inbound UDP resolution failed: {error}"),
            );
            return;
        }
    };
    let outbound = match crate::listener::bind_direct_udp_socket(target, config) {
        Ok(socket) => socket,
        Err(error) => {
            state.log("error", format!("vless inbound UDP bind failed: {error}"));
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

    // Complete frames are read on a dedicated task so a select! branch that
    // observes an outbound datagram cannot cancel a half-parsed client frame.
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    let reader_shutdown = shutdown.child_token();
    let reader_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = reader_shutdown.cancelled() => break,
                frame = read_vless_udp_payload(&mut reader) => {
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
                if !write_vless_udp_to_client(
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

/// Writes one standard VLESS UDP frame to the client, aborting on cancel or
/// write timeout.
async fn write_vless_udp_to_client<W, C>(
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
            VLESS_UDP_CLIENT_WRITE_TIMEOUT,
            write_vless_udp_payload(writer, payload),
        ) => matches!(result, Ok(Ok(()))),
    }
}

/// Writes one XUDP KEEP frame to the client, aborting on cancel or write timeout.
async fn write_vless_xudp_to_client<W, C>(
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
    tokio::select! {
        biased;
        () = shutdown.cancelled() => false,
        () = tracker_cancelled => false,
        result = tokio::time::timeout(
            VLESS_UDP_CLIENT_WRITE_TIMEOUT,
            write_xudp_server_packet(writer, session_id, destination, payload),
        ) => matches!(result, Ok(Ok(()))),
    }
}

/// Mux/XUDP VLESS UDP: each mux session_id owns a dedicated UDP association.
/// Subsequent destinations are re-evaluated against the rule engine so an
/// allow→reject switch cannot leak past DIRECT. Replies are tagged with the
/// owning session_id (never demuxed by remote address alone).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_vless_xudp<S>(
    mut stream: S,
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
    let Ok(Ok((first_session_id, first_destination, first_payload))) = tokio::time::timeout(
        Duration::from_secs(10),
        read_xudp_client_packet(&mut stream),
    )
    .await
    else {
        return;
    };

    let mut base_metadata = Metadata::new(first_destination.clone(), InboundProtocol::Vless);
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
            "[UDP] {} --> {} match {} using {} (VLESS XUDP)",
            base_metadata.source_port,
            base_metadata.destination.authority(),
            first_decision.matched_kind.as_deref().unwrap_or("none"),
            first_decision.target
        ),
    );

    let (reply_tx, mut reply_rx) = mpsc::channel::<XudpReply>(32);
    let mut sessions = XudpMuxTable::new(VLESS_XUDP_MAX_SESSIONS, shutdown.child_token());
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
            format!("vless inbound XUDP bind failed for session {first_session_id}"),
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

    let (mut reader, mut writer) = tokio::io::split(stream);
    let (frame_tx, mut frame_rx) = mpsc::channel::<(u16, Destination, Vec<u8>)>(16);
    let reader_shutdown = shutdown.child_token();
    let reader_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = reader_shutdown.cancelled() => break,
                frame = read_xudp_client_packet(&mut reader) => {
                    match frame {
                        Ok(packet) => {
                            if frame_tx.send(packet).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    let mut idle_sweep = tokio::time::interval(VLESS_XUDP_IDLE_SWEEP);
    idle_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Consume the immediate first tick so idle expiry waits a full sweep period.
    idle_sweep.tick().await;

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tracker.cancelled() => break,
            _ = idle_sweep.tick() => {
                sessions.evict_idle(VLESS_XUDP_SESSION_IDLE);
            }
            reply = reply_rx.recv() => {
                let Some((session_id, source, payload)) = reply else { break };
                let destination = Destination {
                    host: Host::Ip(unmap_ip(source.ip())),
                    port: source.port(),
                };
                sessions.touch(session_id);
                if !write_vless_xudp_to_client(
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
                        format!("vless inbound XUDP bind failed for session {session_id}"),
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

/// Routes one XUDP datagram destination. Returns `None` when the packet should
/// be dropped (reject / unsupported outbound).
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
                "[UDP] {} --> {} match {} using {} (VLESS XUDP)",
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
                "vless inbound XUDP target {} is unsupported in IN-D",
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
                format!("vless inbound XUDP resolution failed: {error}"),
            );
            return None;
        }
    };
    Some((decision, target))
}

#[cfg(test)]
mod udp_write_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn client_udp_write_aborts_when_peer_stops_reading() {
        let (client, server) = tokio::io::duplex(8);
        let (_reader, mut writer) = tokio::io::split(server);
        let client = client;
        let shutdown = CancellationToken::new();
        let tracker = CancellationToken::new();
        let payload = vec![0_u8; 4096];
        let write = tokio::spawn({
            let shutdown = shutdown.clone();
            let tracker = tracker.clone();
            async move {
                write_vless_udp_to_client(&mut writer, &payload, &shutdown, tracker.cancelled())
                    .await
            }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        assert!(
            !write.is_finished(),
            "write should still be blocked on a full window"
        );
        tracker.cancel();
        let finished = tokio::time::timeout(Duration::from_secs(1), write)
            .await
            .expect("write must observe cancel")
            .expect("join");
        assert!(!finished, "cancel must abort the client write");
        drop(client);
    }

    #[tokio::test(start_paused = true)]
    async fn client_udp_write_times_out_when_peer_never_reads() {
        let (_client, server) = tokio::io::duplex(8);
        let (_reader, mut writer) = tokio::io::split(server);
        let shutdown = CancellationToken::new();
        let tracker = CancellationToken::new();
        let payload = vec![0_u8; 4096];
        let write = tokio::spawn(async move {
            write_vless_udp_to_client(&mut writer, &payload, &shutdown, tracker.cancelled()).await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(VLESS_UDP_CLIENT_WRITE_TIMEOUT + Duration::from_millis(1)).await;
        let finished = tokio::time::timeout(Duration::from_secs(1), write)
            .await
            .expect("write must observe timeout")
            .expect("join");
        assert!(!finished, "timeout must abort the stalled client write");
    }

    #[tokio::test]
    async fn xudp_table_evicts_lru_when_at_capacity() {
        let (reply_tx, _reply_rx) = mpsc::channel::<XudpReply>(8);
        let mut table = XudpMuxTable::new(2, CancellationToken::new());
        for session_id in [1_u16, 2, 3] {
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            table.insert_session(session_id, socket, reply_tx.clone());
        }
        assert_eq!(table.len(), 2);
        assert!(!table.contains(1), "oldest session must be evicted");
        assert!(table.contains(2));
        assert!(table.contains(3));
        table.shutdown_all();
    }

    #[tokio::test]
    async fn xudp_same_target_replies_stay_on_own_session() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.expect("echo");
        let echo_addr = echo.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buffer = [0_u8; 1500];
            loop {
                let Ok((length, source)) = echo.recv_from(&mut buffer).await else {
                    break;
                };
                let _ = echo.send_to(&buffer[..length], source).await;
            }
        });

        let (reply_tx, mut reply_rx) = mpsc::channel::<XudpReply>(8);
        let mut table = XudpMuxTable::new(8, CancellationToken::new());
        let socket_one = UdpSocket::bind("127.0.0.1:0").await.expect("s1");
        let socket_two = UdpSocket::bind("127.0.0.1:0").await.expect("s2");
        let session_one = table.insert_session(11, socket_one, reply_tx.clone());
        let session_two = table.insert_session(22, socket_two, reply_tx.clone());

        session_one
            .send_to(b"from-session-11", echo_addr)
            .await
            .expect("send1");
        session_two
            .send_to(b"from-session-22", echo_addr)
            .await
            .expect("send2");

        let mut got_one = false;
        let mut got_two = false;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && !(got_one && got_two) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Ok(Some((session_id, _source, payload))) =
                tokio::time::timeout(remaining, reply_rx.recv()).await
            else {
                break;
            };
            match session_id {
                11 => {
                    assert_eq!(payload, b"from-session-11");
                    got_one = true;
                }
                22 => {
                    assert_eq!(payload, b"from-session-22");
                    got_two = true;
                }
                other => panic!("unexpected session id {other}"),
            }
        }
        assert!(got_one && got_two, "each session must receive its own echo");
        table.shutdown_all();
    }

    #[tokio::test(start_paused = true)]
    async fn xudp_table_evicts_idle_sessions() {
        let (reply_tx, _reply_rx) = mpsc::channel::<XudpReply>(4);
        let mut table = XudpMuxTable::new(8, CancellationToken::new());
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        table.insert_session(7, socket, reply_tx);
        assert!(table.contains(7));
        tokio::time::advance(VLESS_XUDP_SESSION_IDLE + Duration::from_secs(1)).await;
        table.evict_idle(VLESS_XUDP_SESSION_IDLE);
        assert!(!table.contains(7), "idle session must expire");
        table.shutdown_all();
    }

    #[tokio::test]
    async fn xudp_table_drop_closes_reader_senders() {
        let (reply_tx, mut reply_rx) = mpsc::channel::<XudpReply>(4);
        {
            let mut table = XudpMuxTable::new(4, CancellationToken::new());
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            table.insert_session(1, socket, reply_tx);
            // Dropping the table must cancel/abort the reader so the only
            // Sender is released and recv completes with None.
        }
        assert!(
            reply_rx.recv().await.is_none(),
            "Drop must recycle session reader tasks"
        );
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
                .is_none(),
            "parent cancel must stop session readers"
        );
        table.shutdown_all();
    }

    #[tokio::test(start_paused = true)]
    async fn xudp_idle_sweep_interval_matches_runtime_cadence() {
        // The association loop sweeps on VLESS_XUDP_IDLE_SWEEP; after idle
        // timeout + one sweep period, sessions must be reclaimable without a
        // new client frame.
        let (reply_tx, _reply_rx) = mpsc::channel::<XudpReply>(4);
        let mut table = XudpMuxTable::new(4, CancellationToken::new());
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        table.insert_session(9, socket, reply_tx);
        let mut sweep = tokio::time::interval(VLESS_XUDP_IDLE_SWEEP);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        sweep.tick().await;
        tokio::time::advance(VLESS_XUDP_SESSION_IDLE + VLESS_XUDP_IDLE_SWEEP).await;
        sweep.tick().await;
        table.evict_idle(VLESS_XUDP_SESSION_IDLE);
        assert!(!table.contains(9));
        table.shutdown_all();
    }
}

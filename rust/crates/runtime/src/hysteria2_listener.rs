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
const HY2_UDP_MTU: usize = 1197;

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
    let auth = tokio::select! {
        () = shutdown.cancelled() => return,
        result = authenticate_incoming(
            connection.clone(),
            &users,
            ServerAuthOptions::default(),
        ) => result,
    };
    let Ok(auth) = auth else {
        return;
    };

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
                        result = accept_tcp_request(send, recv) => result,
                    };
                    let Ok((destination, stream)) = accepted else {
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
    let sessions: Arc<tokio::sync::Mutex<HashMap<u32, mpsc::Sender<UdpMessage>>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let mut defrag_by_session: HashMap<u32, Defragger> = HashMap::new();
    let mut workers = JoinSet::new();

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            datagram = connection.read_datagram() => {
                let Ok(data) = datagram else { break };
                let Some(message) = UdpMessage::parse(&data) else {
                    continue;
                };
                let session_id = message.session_id;
                let reassembled = {
                    let defrag = defrag_by_session.entry(session_id).or_default();
                    defrag.feed(message)
                };
                let Some(message) = reassembled else {
                    continue;
                };
                let mut guard = sessions.lock().await;
                if let Some(tx) = guard.get(&session_id) {
                    let _ = tx.try_send(message);
                    continue;
                }
                if guard.len() >= HY2_MAX_UDP_SESSIONS {
                    continue;
                }
                let (tx, rx) = mpsc::channel(HY2_UDP_SESSION_CHAN);
                let _ = tx.try_send(message);
                guard.insert(session_id, tx);
                drop(guard);

                let session_connection = connection.clone();
                let session_config = Arc::clone(&config);
                let session_state = Arc::clone(&state);
                let session_shutdown = shutdown.child_token();
                let session_inbound_name = inbound_name.clone();
                let session_username = username.clone();
                let session_map = Arc::clone(&sessions);
                workers.spawn(async move {
                    serve_hysteria2_udp_session(
                        session_connection,
                        session_id,
                        rx,
                        peer,
                        local,
                        session_username,
                        session_inbound_name,
                        session_config,
                        session_state,
                        session_shutdown,
                    )
                    .await;
                    session_map.lock().await.remove(&session_id);
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
    mut rx: mpsc::Receiver<UdpMessage>,
    peer: SocketAddr,
    local: SocketAddr,
    username: String,
    inbound_name: String,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
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
    let mut packet_metadata = Metadata::new(destination, InboundProtocol::Hysteria2);
    packet_metadata.network = Network::Udp;
    packet_metadata.source_ip = Some(unmap_ip(peer.ip()));
    packet_metadata.source_port = peer.port();
    packet_metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut packet_metadata.inbound_name);
    packet_metadata.inbound_user = username;

    let fake_host = apply_host_mapping(&mut packet_metadata, &config, &state);
    let decision =
        mode_decision(&config, &state).unwrap_or_else(|| config.rules.evaluate(&packet_metadata));
    let Some((decision, outbound_target, _)) =
        resolve_rematch_target(decision, &mut packet_metadata, &config, &state)
    else {
        return;
    };
    let route = resolved_route(&outbound_target, &config);
    if matches!(route, Route::Reject | Route::RejectDrop) {
        return;
    }
    let Some(mode) = udp_session_mode(&outbound_target, &config) else {
        state.log(
            "error",
            format!(
                "hysteria2 inbound UDP target {} is unsupported",
                decision.target
            ),
        );
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
    match mode {
        UdpSessionMode::Direct => {
            serve_hysteria2_udp_direct(
                connection,
                session_id,
                rx,
                first,
                packet_metadata,
                fake_host,
                decision,
                &config,
                &state,
                &shutdown,
            )
            .await;
        }
        _ => {
            state.log(
                "error",
                format!(
                    "hysteria2 inbound UDP target {} is unsupported in IN-F",
                    decision.target
                ),
            );
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_hysteria2_udp_direct(
    connection: quinn::Connection,
    session_id: u32,
    mut rx: mpsc::Receiver<UdpMessage>,
    first: UdpMessage,
    first_metadata: Metadata,
    first_fake_host: Option<String>,
    decision: rewrite_rules::Decision,
    config: &Config,
    state: &Arc<RuntimeState>,
    shutdown: &CancellationToken,
) {
    let target = match resolve_udp_target(&first_metadata, first_fake_host.as_deref(), config).await
    {
        Ok(target) => target,
        Err(error) => {
            state.log(
                "error",
                format!("hysteria2 inbound UDP resolution failed: {error}"),
            );
            return;
        }
    };
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
            }
            message = rx.recv() => {
                let Some(message) = message else { break };
                let destination = match rewrite_protocol_hysteria2::parse_destination_authority(&message.addr) {
                    Ok(destination) => destination,
                    Err(_) => continue,
                };
                let mut metadata = first_metadata.clone();
                metadata.destination = destination;
                let fake_host = apply_host_mapping(&mut metadata, config, state);
                let Ok(next_target) = resolve_udp_target(&metadata, fake_host.as_deref(), config).await else {
                    continue;
                };
                if outbound.send_to(&message.data, next_target).await.is_ok() {
                    uploaded = uploaded.saturating_add(message.data.len() as u64);
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

//! IN-D named `type: vless` inbound (TLS, optional WSS / gRPC Gun).
//!
//! After the TLS handshake (and optional WebSocket upgrade or Gun stream),
//! `accept_vless_request` authenticates the UUID and decodes the destination;
//! TCP joins the shared `serve_shadowsocks_connection` boundary and UDP uses
//! the standard fixed-destination framing or Mux/XUDP multi-destination
//! frames. Vision / REALITY stay out of scope.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use rewrite_config::{Config, ControllerTls, VlessInboundConfig};
use rewrite_inbound::BoxedInboundStream;
use rewrite_model::{Destination, Host, InboundProtocol, Metadata, Network, unmap_ip};
use rewrite_protocol_vless::{
    VlessCommand, accept_vless_request, read_vless_udp_payload, read_xudp_client_packet,
    uuid_table, write_vless_udp_payload, write_xudp_server_packet,
};
use rewrite_rules::Route;
use rewrite_state::RuntimeState;
use rewrite_transport::{V2rayGrpcServerConnection, accept_websocket_path};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinSet;
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

pub(crate) struct VlessListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    users: HashMap<[u8; 16], String>,
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
            users: uuid_table(
                config
                    .users
                    .iter()
                    .map(|user| (user.uuid.as_str(), user.username.clone())),
            ),
            inbound_name: config.name.clone(),
            listen: config.listen,
            ws_path: config.ws_path.clone(),
            grpc_service_name: config.grpc_service_name.clone(),
        })
    }
}

struct VlessInboundStream<S> {
    inner: S,
    local: SocketAddr,
    peer: SocketAddr,
}

impl<S> VlessInboundStream<S> {
    fn new(inner: S, local: SocketAddr, peer: SocketAddr) -> Self {
        Self { inner, local, peer }
    }
}

impl<S> AsyncRead for VlessInboundStream<S>
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

impl<S> AsyncWrite for VlessInboundStream<S>
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

impl<S> rewrite_inbound::InboundStream for VlessInboundStream<S>
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

#[allow(clippy::too_many_arguments)]
async fn handle_vless_inbound(
    tcp: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    acceptor: TlsAcceptor,
    users: HashMap<[u8; 16], String>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
    inbound_name: String,
    ws_path: Option<String>,
    grpc_service_name: Option<String>,
) {
    let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
        Ok(Ok(stream)) => stream,
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
    };

    if let Some(service_name) = grpc_service_name {
        serve_vless_grpc_connection(
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
    users: HashMap<[u8; 16], String>,
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
    mut stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    users: HashMap<[u8; 16], String>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
    inbound_name: String,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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

    match request.command {
        VlessCommand::Tcp => {
            serve_vless_tcp(
                stream,
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
    stream: S,
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
    let mut metadata = Metadata::new(destination, InboundProtocol::Vless);
    metadata.network = Network::Tcp;
    metadata.source_ip = Some(unmap_ip(peer.ip()));
    metadata.source_port = peer.port();
    metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut metadata.inbound_name);
    metadata.inbound_user = username;
    let client: BoxedInboundStream = Box::new(VlessInboundStream::new(stream, local, peer));
    serve_shadowsocks_connection(client, metadata, config, state, dns_service, shutdown).await;
}

/// Standard-mode VLESS UDP: one fixed destination per association, framed as
/// a 2-byte big-endian length prefix followed by the payload. Mux/XUDP uses
/// [`serve_vless_xudp`] instead.
#[allow(clippy::too_many_arguments)]
async fn serve_vless_udp<S>(
    mut stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    destination: Destination,
    username: String,
    inbound_name: String,
    config: &Config,
    state: &Arc<RuntimeState>,
    shutdown: &CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin,
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
                &mut stream,
                metadata,
                fake_host,
                decision,
                config,
                state,
                shutdown,
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
    stream: &mut S,
    metadata: Metadata,
    fake_host: Option<String>,
    decision: rewrite_rules::Decision,
    config: &Config,
    state: &Arc<RuntimeState>,
    shutdown: &CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin,
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
    let outbound = match UdpSocket::bind(if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })
    .await
    {
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
    loop {
        let mut response = vec![0_u8; 65_536];
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tracker.cancelled() => break,
            received = outbound.recv_from(&mut response) => {
                let Ok((length, _source)) = received else { break };
                if write_vless_udp_payload(stream, &response[..length]).await.is_err() {
                    break;
                }
                downloaded = downloaded.saturating_add(length as u64);
            }
            payload = read_udp_frame(stream, shutdown) => {
                let Some(payload) = payload else { break };
                if outbound.send_to(&payload, target).await.is_ok() {
                    uploaded = uploaded.saturating_add(payload.len() as u64);
                }
            }
        }
    }
    tracker.finish(uploaded, downloaded);
}

async fn read_udp_frame<S>(stream: &mut S, shutdown: &CancellationToken) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    tokio::select! {
        () = shutdown.cancelled() => None,
        result = read_vless_udp_payload(stream) => result.ok(),
    }
}

/// Mux/XUDP VLESS UDP: each frame carries its own destination (product VLESS
/// outbound defaults to this mode).
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
    let Ok(Ok((first_destination, first_payload))) = tokio::time::timeout(
        Duration::from_secs(10),
        read_xudp_client_packet(&mut stream),
    )
    .await
    else {
        return;
    };

    let mut first_metadata = Metadata::new(first_destination.clone(), InboundProtocol::Vless);
    first_metadata.network = Network::Udp;
    first_metadata.source_ip = Some(unmap_ip(peer.ip()));
    first_metadata.source_port = peer.port();
    first_metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut first_metadata.inbound_name);
    first_metadata.inbound_user = username;

    let first_fake_host = apply_host_mapping(&mut first_metadata, config, state);
    let decision =
        mode_decision(config, state).unwrap_or_else(|| config.rules.evaluate(&first_metadata));
    let Some((decision, outbound_target, _)) =
        resolve_rematch_target(decision, &mut first_metadata, config, state)
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
                "vless inbound XUDP target {} is unsupported",
                decision.target
            ),
        );
        return;
    };
    if !matches!(mode, UdpSessionMode::Direct) {
        state.log(
            "error",
            format!(
                "vless inbound XUDP target {} is unsupported in IN-D",
                decision.target
            ),
        );
        return;
    }
    state.log(
        "info",
        format!(
            "[UDP] {} --> {} match {} using {} (VLESS XUDP)",
            first_metadata.source_port,
            first_metadata.destination.authority(),
            decision.matched_kind.as_deref().unwrap_or("none"),
            decision.target
        ),
    );

    let first_target =
        match resolve_udp_target(&first_metadata, first_fake_host.as_deref(), config).await {
            Ok(target) => target,
            Err(error) => {
                state.log(
                    "error",
                    format!("vless inbound XUDP resolution failed: {error}"),
                );
                return;
            }
        };
    let outbound = match crate::listener::bind_direct_udp_socket(first_target, config) {
        Ok(socket) => socket,
        Err(error) => {
            state.log("error", format!("vless inbound XUDP bind failed: {error}"));
            return;
        }
    };
    let tracker = state.register(
        &first_metadata,
        &decision.target,
        decision.matched_kind.as_deref(),
    );
    let mut uploaded = first_payload.len() as u64;
    let mut downloaded = 0_u64;
    if outbound
        .send_to(&first_payload, first_target)
        .await
        .is_err()
    {
        tracker.finish(uploaded, downloaded);
        return;
    }

    let (mut reader, mut writer) = tokio::io::split(stream);
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<(Destination, Vec<u8>)>(16);
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
                if write_xudp_server_packet(&mut writer, &destination, &response[..length])
                    .await
                    .is_err()
                {
                    break;
                }
                downloaded = downloaded.saturating_add(length as u64);
            }
            packet = frame_rx.recv() => {
                let Some((destination, payload)) = packet else { break };
                let mut packet_metadata = first_metadata.clone();
                packet_metadata.destination = destination;
                let fake_host = apply_host_mapping(&mut packet_metadata, config, state);
                let target = match resolve_udp_target(
                    &packet_metadata,
                    fake_host.as_deref(),
                    config,
                )
                .await
                {
                    Ok(target) => target,
                    Err(error) => {
                        state.log(
                            "error",
                            format!("vless inbound XUDP resolution failed: {error}"),
                        );
                        continue;
                    }
                };
                if outbound.send_to(&payload, target).await.is_ok() {
                    uploaded = uploaded.saturating_add(payload.len() as u64);
                }
            }
        }
    }
    reader_task.abort();
    tracker.finish(uploaded, downloaded);
}

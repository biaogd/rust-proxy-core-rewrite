use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use rewrite_config::{Config, ControllerTls, TrojanInboundConfig};
use rewrite_inbound::BoxedInboundStream;
use rewrite_model::{Destination, Host, InboundProtocol, Metadata, Network, unmap_ip};
use rewrite_protocol_trojan::{
    TrojanCommand, accept_trojan_request, password_table, read_trojan_udp_packet,
    write_trojan_udp_packet,
};
use rewrite_rules::Route;
use rewrite_state::RuntimeState;
use rewrite_transport::{
    BoxedStream, RealityAcceptOptions, RealityTlsAcceptor, V2rayGrpcServerConnection,
    accept_reality, accept_websocket_path, reality_acceptor,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::listener::{UdpSessionMode, resolve_udp_target, resolved_route, udp_session_mode};
use crate::tcp::{
    apply_host_mapping, mode_decision, resolve_rematch_target, serve_shadowsocks_connection,
};
use crate::types::RuntimeError;

const TROJAN_MAX_INBOUND_CONNECTIONS: usize = 1024;
const TROJAN_MAX_GRPC_STREAMS: usize = 256;
const TROJAN_GRPC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound client-side UDP writes so a stalled reader cannot pin the select loop
/// past connection cancel / controller close.
const TROJAN_UDP_CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
enum TrojanTlsAcceptor {
    Certificate(TlsAcceptor),
    Reality(RealityTlsAcceptor),
}

pub(crate) struct TrojanListener {
    listener: TcpListener,
    acceptor: TrojanTlsAcceptor,
    passwords: Arc<HashMap<[u8; 56], String>>,
    inbound_name: String,
    listen: SocketAddr,
    ws_path: Option<String>,
    grpc_service_name: Option<String>,
}

impl TrojanListener {
    pub(crate) async fn bind(
        config: &TrojanInboundConfig,
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
            TrojanTlsAcceptor::Reality(acceptor)
        } else {
            let certificate = config.certificate.clone().ok_or_else(|| {
                RuntimeError::Listener(std::io::Error::other("trojan inbound missing certificate"))
            })?;
            let private_key = config.private_key.clone().ok_or_else(|| {
                RuntimeError::Listener(std::io::Error::other("trojan inbound missing private-key"))
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
            // Match Go plain-TCP Trojan: NextProtos only set for WS/gRPC carriers.
            rewrite_controller::apply_inbound_alpn(
                &mut tls,
                config.ws_path.is_some(),
                config.grpc_service_name.is_some(),
            );
            TrojanTlsAcceptor::Certificate(TlsAcceptor::from(Arc::new(tls)))
        };
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(RuntimeError::Listener)?;
        Ok(Self {
            listener,
            acceptor,
            passwords: Arc::new(password_table(
                config
                    .users
                    .iter()
                    .map(|user| (user.password.as_str(), user.username.clone())),
            )),
            inbound_name: config.name.clone(),
            listen: config.listen,
            ws_path: config.ws_path.clone(),
            grpc_service_name: config.grpc_service_name.clone(),
        })
    }
}

struct TrojanInboundStream<S> {
    inner: S,
    local: SocketAddr,
    peer: SocketAddr,
}

impl<S> TrojanInboundStream<S> {
    fn new(inner: S, local: SocketAddr, peer: SocketAddr) -> Self {
        Self { inner, local, peer }
    }
}

impl<S> AsyncRead for TrojanInboundStream<S>
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

impl<S> AsyncWrite for TrojanInboundStream<S>
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

impl<S> rewrite_inbound::InboundStream for TrojanInboundStream<S>
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

pub(super) async fn run_trojan_listener(
    listener: TrojanListener,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let TrojanListener {
        listener,
        acceptor,
        passwords,
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
                    state.log("error", "trojan inbound accept failed");
                    break;
                };
                // Match Go net.TCPConn default: TCP_NODELAY on.
                let _ = tcp.set_nodelay(true);
                let connection_config = Arc::clone(&*config.borrow());
                if !connection_config.permits_inbound(peer.ip()) {
                    continue;
                }
                if connections.len() >= TROJAN_MAX_INBOUND_CONNECTIONS {
                    state.log(
                        "warning",
                        format!(
                            "trojan inbound connection limit reached ({TROJAN_MAX_INBOUND_CONNECTIONS})"
                        ),
                    );
                    continue;
                }
                let local = tcp.local_addr().unwrap_or(listen);
                let acceptor = acceptor.clone();
                let passwords = passwords.clone();
                let connection_state = Arc::clone(&state);
                let connection_dns = Arc::clone(&dns_service);
                let connection_shutdown = shutdown.child_token();
                let connection_inbound_name = inbound_name.clone();
                let connection_ws_path = ws_path.clone();
                let connection_grpc_service = grpc_service_name.clone();
                connections.spawn(async move {
                    Box::pin(handle_trojan_inbound(
                        tcp,
                        peer,
                        local,
                        acceptor,
                        passwords,
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
                    state.log("error", format!("trojan inbound task failed: {error}"));
                }
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

#[allow(clippy::too_many_arguments)]
async fn handle_trojan_inbound(
    tcp: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    acceptor: TrojanTlsAcceptor,
    passwords: Arc<HashMap<[u8; 56], String>>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
    inbound_name: String,
    ws_path: Option<String>,
    grpc_service_name: Option<String>,
) {
    let tls: BoxedStream = match acceptor {
        TrojanTlsAcceptor::Reality(reality_acceptor) => {
            match accept_reality(&reality_acceptor, tcp).await {
                Ok(stream) => stream,
                Err(error) => {
                    state.log(
                        "error",
                        format!("trojan inbound REALITY handshake failed: {error}"),
                    );
                    return;
                }
            }
        }
        TrojanTlsAcceptor::Certificate(acceptor) => {
            match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                Ok(Ok(stream)) => Box::new(stream),
                Ok(Err(error)) => {
                    state.log(
                        "error",
                        format!("trojan inbound TLS handshake failed: {error}"),
                    );
                    return;
                }
                Err(_) => {
                    state.log("error", "trojan inbound TLS handshake timed out");
                    return;
                }
            }
        }
    };

    if let Some(service_name) = grpc_service_name {
        serve_trojan_grpc_connection(
            tls,
            service_name,
            peer,
            local,
            passwords,
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
                        format!("trojan inbound WebSocket upgrade failed: {error}"),
                    );
                    return;
                }
                Err(_) => {
                    state.log("error", "trojan inbound WebSocket upgrade timed out");
                    return;
                }
            };
        Box::pin(dispatch_trojan_session(
            websocket,
            peer,
            local,
            passwords,
            config,
            state,
            dns_service,
            shutdown,
            inbound_name,
        ))
        .await;
        return;
    }

    Box::pin(dispatch_trojan_session(
        tls,
        peer,
        local,
        passwords,
        config,
        state,
        dns_service,
        shutdown,
        inbound_name,
    ))
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn serve_trojan_grpc_connection<S>(
    stream: S,
    service_name: String,
    peer: SocketAddr,
    local: SocketAddr,
    passwords: Arc<HashMap<[u8; 56], String>>,
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
            TROJAN_GRPC_HANDSHAKE_TIMEOUT,
            V2rayGrpcServerConnection::handshake(stream, &service_name),
        ) => match result {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                state.log(
                    "error",
                    format!("trojan inbound gRPC handshake failed: {error}"),
                );
                return;
            }
            Err(_) => {
                state.log("error", "trojan inbound gRPC handshake timed out");
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
                        if streams.len() >= TROJAN_MAX_GRPC_STREAMS {
                            state.log(
                                "warning",
                                format!(
                                    "trojan inbound gRPC stream limit reached ({TROJAN_MAX_GRPC_STREAMS})"
                                ),
                            );
                            continue;
                        }
                        let passwords = passwords.clone();
                        let config = Arc::clone(&config);
                        let state = Arc::clone(&state);
                        let dns_service = Arc::clone(&dns_service);
                        let shutdown = shutdown.child_token();
                        let inbound_name = inbound_name.clone();
                        streams.spawn(async move {
                            dispatch_trojan_session(
                                stream,
                                peer,
                                local,
                                passwords,
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
                            format!("trojan inbound gRPC stream accept failed: {error}"),
                        );
                        break;
                    }
                    None => break,
                }
            }
            Some(result) = streams.join_next() => {
                if let Err(error) = result {
                    state.log("error", format!("trojan inbound gRPC stream task failed: {error}"));
                }
            }
        }
    }
    streams.abort_all();
    while streams.join_next().await.is_some() {}
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_trojan_session<S>(
    mut stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    passwords: Arc<HashMap<[u8; 56], String>>,
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
        accept_trojan_request(&mut stream, &passwords),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(_)) => return,
        Err(_) => {
            state.log("error", "trojan inbound authentication timed out");
            return;
        }
    };

    match request.command {
        TrojanCommand::Tcp => {
            serve_trojan_tcp(
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
        TrojanCommand::Udp => {
            serve_trojan_udp(
                stream,
                peer,
                local,
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
}

#[allow(clippy::too_many_arguments)]
async fn serve_trojan_tcp<S>(
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
    let mut metadata = Metadata::new(destination, InboundProtocol::Trojan);
    metadata.network = Network::Tcp;
    metadata.source_ip = Some(unmap_ip(peer.ip()));
    metadata.source_port = peer.port();
    metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut metadata.inbound_name);
    metadata.inbound_user = username;
    let client: BoxedInboundStream = Box::new(TrojanInboundStream::new(stream, local, peer));
    serve_shadowsocks_connection(client, metadata, config, state, dns_service, shutdown).await;
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_trojan_udp<S>(
    mut stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    username: String,
    inbound_name: String,
    config: &Config,
    state: &Arc<RuntimeState>,
    _dns_service: &Arc<rewrite_dns::DnsService>,
    shutdown: &CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let first_frame = tokio::select! {
        () = shutdown.cancelled() => None,
        result = read_trojan_udp_packet(&mut stream) => result.ok(),
    };
    let Some((first_destination, first_payload)) = first_frame else {
        return;
    };
    let mut packet_metadata = Metadata::new(first_destination, InboundProtocol::Trojan);
    packet_metadata.network = Network::Udp;
    packet_metadata.source_ip = Some(unmap_ip(peer.ip()));
    packet_metadata.source_port = peer.port();
    packet_metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut packet_metadata.inbound_name);
    packet_metadata.inbound_user = username;

    let fake_host = apply_host_mapping(&mut packet_metadata, config, state);
    let decision =
        mode_decision(config, state).unwrap_or_else(|| config.rules.evaluate(&packet_metadata));
    let Some((decision, outbound_target, _)) =
        resolve_rematch_target(decision, &mut packet_metadata, config, state)
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
                "trojan inbound UDP target {} is unsupported",
                decision.target
            ),
        );
        return;
    };
    state.log(
        "info",
        format!(
            "[UDP] {} --> {} match {} using {} (Trojan)",
            packet_metadata.source_port,
            packet_metadata.destination.authority(),
            decision.matched_kind.as_deref().unwrap_or("none"),
            decision.target
        ),
    );
    match mode {
        UdpSessionMode::Direct => {
            serve_trojan_udp_direct(
                stream,
                packet_metadata,
                fake_host,
                first_payload,
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
                    "trojan inbound UDP target {} is unsupported in IN-C",
                    decision.target
                ),
            );
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_trojan_udp_direct<S>(
    stream: S,
    first_metadata: Metadata,
    first_fake_host: Option<String>,
    first_payload: Vec<u8>,
    decision: rewrite_rules::Decision,
    config: &Config,
    state: &Arc<RuntimeState>,
    shutdown: &CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let target = match resolve_udp_target(&first_metadata, first_fake_host.as_deref(), config).await
    {
        Ok(target) => target,
        Err(error) => {
            state.log(
                "error",
                format!("trojan inbound UDP resolution failed: {error}"),
            );
            return;
        }
    };
    let outbound = match crate::listener::bind_direct_udp_socket(target, config) {
        Ok(socket) => socket,
        Err(error) => {
            state.log("error", format!("trojan inbound UDP bind failed: {error}"));
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
    if outbound.send_to(&first_payload, target).await.is_err() {
        tracker.finish(uploaded, downloaded);
        return;
    }

    // Complete frames are read on a dedicated task so a select! branch that
    // observes an outbound datagram cannot cancel a half-parsed client frame.
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<(Destination, Vec<u8>)>(16);
    let reader_shutdown = shutdown.child_token();
    let reader_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = reader_shutdown.cancelled() => break,
                frame = read_trojan_udp_packet(&mut reader) => {
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
                // Race the client write against cancel/timeout: a full TCP
                // window must not trap us inside select! past tracker close.
                if !write_trojan_udp_to_client(
                    &mut writer,
                    &destination,
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
                            format!("trojan inbound UDP resolution failed: {error}"),
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
    let _ = reader_task.await;
    tracker.finish(uploaded, downloaded);
}

/// Writes one Trojan UDP frame to the client, aborting on cancel or write timeout.
///
/// Returns `false` when the write should stop the UDP association (cancel,
/// timeout, or I/O error). A stalled client reader must not pin the association
/// past controller close.
async fn write_trojan_udp_to_client<W, C>(
    writer: &mut W,
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
            TROJAN_UDP_CLIENT_WRITE_TIMEOUT,
            write_trojan_udp_packet(writer, destination, payload),
        ) => matches!(result, Ok(Ok(()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn client_udp_write_aborts_when_peer_stops_reading() {
        // Tiny duplex buffer so a large frame write blocks once the window fills.
        let (client, server) = tokio::io::duplex(8);
        let (_reader, mut writer) = tokio::io::split(server);
        // Hold the client half without reading so the write backs up.
        let client = client;
        let shutdown = CancellationToken::new();
        let tracker = CancellationToken::new();
        let destination = Destination {
            host: Host::Ip("192.0.2.1".parse().expect("ip")),
            port: 53,
        };
        let payload = vec![0_u8; 4096];
        let write = tokio::spawn({
            let shutdown = shutdown.clone();
            let tracker = tracker.clone();
            async move {
                write_trojan_udp_to_client(
                    &mut writer,
                    &destination,
                    &payload,
                    &shutdown,
                    tracker.cancelled(),
                )
                .await
            }
        });
        // Let the write fill the duplex and block.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        assert!(
            !write.is_finished(),
            "write should still be blocked on a full window"
        );
        // Controller close must unblock the association promptly.
        tracker.cancel();
        let finished = tokio::time::timeout(Duration::from_secs(1), write)
            .await
            .expect("write must observe cancel")
            .expect("join");
        assert!(!finished, "cancel must abort the client write");
        // Keep client alive until the write task exits to avoid early EOF races.
        drop(client);
    }

    #[tokio::test(start_paused = true)]
    async fn client_udp_write_times_out_when_peer_never_reads() {
        let (_client, server) = tokio::io::duplex(8);
        let (_reader, mut writer) = tokio::io::split(server);
        let shutdown = CancellationToken::new();
        let tracker = CancellationToken::new();
        let destination = Destination {
            host: Host::Ip("192.0.2.1".parse().expect("ip")),
            port: 53,
        };
        let payload = vec![0_u8; 4096];
        let write = tokio::spawn(async move {
            write_trojan_udp_to_client(
                &mut writer,
                &destination,
                &payload,
                &shutdown,
                tracker.cancelled(),
            )
            .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(TROJAN_UDP_CLIENT_WRITE_TIMEOUT + Duration::from_millis(1)).await;
        let finished = tokio::time::timeout(Duration::from_secs(1), write)
            .await
            .expect("write must observe timeout")
            .expect("join");
        assert!(!finished, "timeout must abort the stalled client write");
    }
}

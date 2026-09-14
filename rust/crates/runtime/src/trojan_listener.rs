use std::collections::HashMap;
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
use rewrite_transport::accept_websocket_path;
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

pub(crate) struct TrojanListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    passwords: HashMap<[u8; 56], String>,
    inbound_name: String,
    listen: SocketAddr,
    ws_path: Option<String>,
}

impl TrojanListener {
    pub(crate) async fn bind(
        config: &TrojanInboundConfig,
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
            passwords: password_table(
                config
                    .users
                    .iter()
                    .map(|user| (user.password.as_str(), user.username.clone())),
            ),
            inbound_name: config.name.clone(),
            listen: config.listen,
            ws_path: config.ws_path.clone(),
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

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
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
                let connection_config = Arc::clone(&*config.borrow());
                if !connection_config.permits_inbound(peer.ip()) {
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
                connections.spawn(async move {
                    handle_trojan_inbound(
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
                    )
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
    acceptor: TlsAcceptor,
    passwords: HashMap<[u8; 56], String>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
    inbound_name: String,
    ws_path: Option<String>,
) {
    let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
        Ok(Ok(stream)) => stream,
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
    };

    if let Some(path) = ws_path {
        let websocket = match tokio::time::timeout(
            Duration::from_secs(10),
            accept_websocket_path(tls, &path),
        )
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
        dispatch_trojan_session(
            websocket,
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

    dispatch_trojan_session(
        tls,
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
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_trojan_session<S>(
    mut stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    passwords: HashMap<[u8; 56], String>,
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
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some((first_destination, first_payload)) =
        read_trojan_udp_frame(&mut stream, shutdown).await
    else {
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
                &mut stream,
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

async fn read_trojan_udp_frame<S>(
    stream: &mut S,
    shutdown: &CancellationToken,
) -> Option<(Destination, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    tokio::select! {
        () = shutdown.cancelled() => None,
        result = read_trojan_udp_packet(stream) => result.ok(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_trojan_udp_direct<S>(
    stream: &mut S,
    first_metadata: Metadata,
    first_fake_host: Option<String>,
    first_payload: Vec<u8>,
    decision: rewrite_rules::Decision,
    config: &Config,
    state: &Arc<RuntimeState>,
    shutdown: &CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin,
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
    let outbound = match UdpSocket::bind(if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })
    .await
    {
        Ok(socket) => socket,
        Err(error) => {
            state.log(
                "error",
                format!("trojan inbound UDP bind failed: {error}"),
            );
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
                if write_trojan_udp_packet(stream, &destination, &response[..length])
                    .await
                    .is_err()
                {
                    break;
                }
                downloaded = downloaded.saturating_add(length as u64);
            }
            packet = read_trojan_udp_frame(stream, shutdown) => {
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
    tracker.finish(uploaded, downloaded);
}

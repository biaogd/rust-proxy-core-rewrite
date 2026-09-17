//! Static tunnel TCP/UDP inbound (`tunnels:` / IN-05).

use std::net::SocketAddr;
use std::sync::Arc;

use rewrite_config::{Config, TunnelInboundConfig, TunnelNetwork};
use rewrite_inbound::BoxedInboundStream;
use rewrite_model::{InboundProtocol, Metadata, Network, unmap_ip};
use rewrite_state::RuntimeState;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::listener::{
    UdpReplySink, UdpSessionContext, UdpSessionPacket, UdpSessions, receive_udp,
};
use crate::tcp::{apply_host_mapping, serve_stream_session};
use crate::types::{LocalTcpListener, RuntimeError};

pub(crate) struct TunnelTcpListener {
    inner: LocalTcpListener,
    target: rewrite_model::Destination,
    proxy: String,
}

impl TunnelTcpListener {
    pub(crate) fn bind(
        config: &TunnelInboundConfig,
        runtime: &Config,
    ) -> Result<Self, RuntimeError> {
        debug_assert_eq!(config.network, TunnelNetwork::Tcp);
        let dual_stack = runtime.allow_lan && runtime.bind_address == "*";
        let listener = rewrite_platform::bind_local_tcp_listener(
            config.listen,
            rewrite_platform::LocalTcpOptions {
                dual_stack,
                multipath: runtime.inbound_mptcp,
                keep_alive_idle: runtime.keep_alive_idle,
                keep_alive_interval: runtime.keep_alive_interval,
                disable_keep_alive: runtime.disable_keep_alive,
            },
        )?;
        let listener = if runtime.inbound_tfo {
            LocalTcpListener::FastOpen(tokio_tfo::TfoListener::from_std(listener)?)
        } else {
            LocalTcpListener::Plain(TcpListener::from_std(listener)?)
        };
        Ok(Self {
            inner: listener,
            target: config.target.clone(),
            proxy: config.proxy.clone(),
        })
    }
}

pub(crate) struct TunnelUdpListener {
    socket: Arc<UdpSocket>,
    target: rewrite_model::Destination,
    proxy: String,
    inbound_port: u16,
}

impl TunnelUdpListener {
    pub(crate) fn bind(
        config: &TunnelInboundConfig,
        runtime: &Config,
    ) -> Result<Self, RuntimeError> {
        debug_assert_eq!(config.network, TunnelNetwork::Udp);
        let dual_stack = runtime.allow_lan && runtime.bind_address == "*";
        let socket = rewrite_platform::bind_local_udp_socket(config.listen, dual_stack)?;
        Ok(Self {
            socket: Arc::new(UdpSocket::from_std(socket)?),
            target: config.target.clone(),
            proxy: config.proxy.clone(),
            inbound_port: config.listen.port(),
        })
    }
}

pub(crate) async fn run_tunnel_tcp_listener(
    listener: TunnelTcpListener,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.inner.accept() => {
                match accepted {
                    Ok((client, _)) => {
                        let connection_config = Arc::clone(&config.borrow());
                        let connection_state = Arc::clone(&state);
                        let connection_dns_service = Arc::clone(&dns_service);
                        let connection_shutdown = shutdown.child_token();
                        let target = listener.target.clone();
                        let proxy = listener.proxy.clone();
                        connections.spawn(async move {
                            serve_tunnel_tcp(
                                client,
                                target,
                                proxy,
                                &connection_config,
                                &connection_state,
                                &connection_dns_service,
                                &connection_shutdown,
                            )
                            .await;
                        });
                    }
                    Err(error) => {
                        state.log("error", format!("tunnel TCP listener failed: {error}"));
                        break;
                    }
                }
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(join_error)) = result {
                    state.log("error", format!("tunnel connection task failed: {join_error}"));
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
                format!("tunnel connection task failed during shutdown: {join_error}"),
            );
        }
    }
}

pub(crate) async fn run_tunnel_udp_listener(
    listener: TunnelUdpListener,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let mut udp_sessions = UdpSessions::default();
    let mut datagram = vec![0_u8; 65_535];
    let socket = Arc::clone(&listener.socket);
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            result = udp_sessions.tasks.join_next(), if !udp_sessions.tasks.is_empty() => {
                udp_sessions.reap(result.as_ref());
            }
            received = receive_udp(Some(&socket), &mut datagram) => {
                if let Ok((length, source)) = received {
                    let connection_config = Arc::clone(&config.borrow());
                    let Some(request) = prepare_tunnel_udp(
                        &datagram[..length],
                        source,
                        &listener,
                        &connection_config,
                        &state,
                    ) else {
                        continue;
                    };
                    udp_sessions.dispatch(
                        source,
                        request,
                        UdpSessionContext::new(
                            UdpReplySink::Raw(Arc::clone(&socket)),
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
    shutdown.cancel();
    udp_sessions.shutdown(&state).await;
}

async fn serve_tunnel_tcp(
    client: BoxedInboundStream,
    target: rewrite_model::Destination,
    proxy: String,
    config: &Config,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    shutdown: &CancellationToken,
) {
    let Ok(peer) = client.peer_addr() else {
        return;
    };
    if !config.permits_inbound(peer.ip()) {
        return;
    }
    let mut metadata = Metadata::new(target, InboundProtocol::Tunnel);
    // Legacy `tunnels:` leave InName empty (Go does not set DEFAULT-TUNNEL).
    metadata.special_proxy = proxy;
    if let Ok(local) = client.local_addr() {
        metadata.inbound_port = local.port();
    }
    serve_stream_session(client, metadata, config, state, dns_service, shutdown).await;
}

fn prepare_tunnel_udp(
    payload: &[u8],
    source: SocketAddr,
    listener: &TunnelUdpListener,
    config: &Config,
    state: &Arc<RuntimeState>,
) -> Option<UdpSessionPacket> {
    if !config.permits_inbound(source.ip()) {
        return None;
    }
    let mut metadata = Metadata::new(listener.target.clone(), InboundProtocol::Tunnel);
    metadata.network = Network::Udp;
    metadata.source_ip = Some(unmap_ip(source.ip()));
    metadata.source_port = source.port();
    metadata.inbound_port = listener.inbound_port;
    metadata.special_proxy.clone_from(&listener.proxy);
    let fake_host = apply_host_mapping(&mut metadata, config, state);
    Some(UdpSessionPacket::from_parts(
        metadata,
        fake_host,
        payload.to_vec(),
    ))
}

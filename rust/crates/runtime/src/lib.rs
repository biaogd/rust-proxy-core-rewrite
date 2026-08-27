use std::collections::BTreeMap;
use std::future::pending;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rand::RngExt;
use rewrite_config::{Config, ConfigError, DnsMode, HostEntry, ListenerKind, Mode, ProxyKind};
use rewrite_inbound::{InboundCommand, ListenerProtocol};
use rewrite_model::{Destination, Host, Metadata, unmap_ip};
use rewrite_rules::{LazyEvaluation, Route};
use rewrite_state::{ConnectionGuard, RuntimeState};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("local listener error: {0}")]
    Listener(#[from] std::io::Error),
}

struct RuntimeTask {
    shutdown: CancellationToken,
    handle: JoinHandle<()>,
}

/// One-shot process lifecycle barriers used by synchronous shell hooks.
pub struct LifecycleSignals {
    ready: oneshot::Sender<()>,
    shutdown_hook_ready: oneshot::Sender<()>,
    continue_shutdown: oneshot::Receiver<()>,
}

impl LifecycleSignals {
    /// Creates lifecycle barriers owned by the runtime.
    #[must_use]
    pub fn new(
        ready: oneshot::Sender<()>,
        shutdown_hook_ready: oneshot::Sender<()>,
        continue_shutdown: oneshot::Receiver<()>,
    ) -> Self {
        Self {
            ready,
            shutdown_hook_ready,
            continue_shutdown,
        }
    }
}

/// Runs a fixed configuration until cancellation.
///
/// # Errors
///
/// Returns [`RuntimeError`] if a declared port/address is invalid or a local
/// listener cannot be bound.
pub async fn run(config: Config, shutdown: CancellationToken) -> Result<(), RuntimeError> {
    let (_reload_sender, reloads) = mpsc::channel(1);
    run_with_reload(config, reloads, shutdown).await
}

/// Runs transactional local listener generations and applies validated reloads.
///
/// A reload binds every newly required socket before publishing its config.
/// Failure leaves the previous generation running.
///
/// # Errors
///
/// Returns [`RuntimeError`] only when the initial generation cannot be created.
/// Later reload errors are logged and leave the current generation unchanged.
pub async fn run_with_reload(
    initial: Config,
    reloads: mpsc::Receiver<Config>,
    shutdown: CancellationToken,
) -> Result<(), RuntimeError> {
    run_with_reload_inner(initial, reloads, shutdown, None).await
}

/// Runs transactional generations with startup and shutdown-hook barriers.
///
/// The readiness notification is sent only after every declared initial socket
/// has been bound and its serving task has been started. After cancellation,
/// profile state is stored and the shutdown-hook notification is sent while
/// runtime services remain live; cleanup resumes when the caller acknowledges
/// that notification.
///
/// # Errors
///
/// Returns [`RuntimeError`] only when the initial generation cannot be created.
/// Later reload errors are logged and leave the current generation unchanged.
pub async fn run_with_reload_lifecycle(
    initial: Config,
    reloads: mpsc::Receiver<Config>,
    shutdown: CancellationToken,
    lifecycle: LifecycleSignals,
) -> Result<(), RuntimeError> {
    run_with_reload_inner(initial, reloads, shutdown, Some(lifecycle)).await
}

async fn run_with_reload_inner(
    initial: Config,
    mut reloads: mpsc::Receiver<Config>,
    shutdown: CancellationToken,
    lifecycle: Option<LifecycleSignals>,
) -> Result<(), RuntimeError> {
    let state = Arc::new(RuntimeState::default());
    let dns_service = Arc::new(rewrite_dns::DnsService::new());
    let (config_sender, config_receiver) = watch::channel(Arc::new(initial.clone()));
    let (controller_update_sender, mut controller_updates) = mpsc::channel(4);
    let mut listeners = BTreeMap::new();
    let mut controller: Option<(SocketAddr, RuntimeTask)> = None;
    let mut dns: Option<(SocketAddr, RuntimeTask)> = None;

    apply_generation(
        initial,
        &config_sender,
        &config_receiver,
        &state,
        &dns_service,
        &controller_update_sender,
        &mut listeners,
        &mut controller,
        &mut dns,
    )
    .await?;
    let shutdown_barrier = lifecycle.map(
        |LifecycleSignals {
             ready,
             shutdown_hook_ready,
             continue_shutdown,
         }| {
            let _ = ready.send(());
            (shutdown_hook_ready, continue_shutdown)
        },
    );

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            next = reloads.recv() => {
                let Some(next) = next else {
                    shutdown.cancelled().await;
                    break;
                };
                if let Err(error) = apply_generation(
                    next,
                    &config_sender,
                    &config_receiver,
                    &state,
                    &dns_service,
                    &controller_update_sender,
                    &mut listeners,
                    &mut controller,
                    &mut dns,
                ).await {
                    state.log("error", format!("configuration reload failed: {error}"));
                    eprintln!("configuration reload failed: {error}");
                } else {
                    state.log("info", "configuration reloaded");
                }
            }
            update = controller_updates.recv() => {
                let Some(update) = update else {
                    continue;
                };
                let result = apply_generation(
                    update.config,
                    &config_sender,
                    &config_receiver,
                    &state,
                    &dns_service,
                    &controller_update_sender,
                    &mut listeners,
                    &mut controller,
                    &mut dns,
                ).await.map_err(|error| error.to_string());
                if let Err(error) = &result {
                    state.log("error", format!("controller configuration update failed: {error}"));
                } else {
                    state.log("info", "controller configuration updated");
                }
                let _ = update.completion.send(result);
            }
        }
    }

    state.store_fake_ip_state();
    if let Some((shutdown_hook_ready, continue_shutdown)) = shutdown_barrier {
        let _ = shutdown_hook_ready.send(());
        let _ = continue_shutdown.await;
    }
    for (_, task) in listeners {
        stop_task(task).await;
    }
    if let Some((_, task)) = controller {
        stop_task(task).await;
    }
    if let Some((_, task)) = dns {
        stop_task(task).await;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn apply_generation(
    next: Config,
    config_sender: &watch::Sender<Arc<Config>>,
    config_receiver: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    controller_updates: &mpsc::Sender<rewrite_controller::ConfigUpdate>,
    listeners: &mut BTreeMap<(ListenerKind, u16), RuntimeTask>,
    controller: &mut Option<(SocketAddr, RuntimeTask)>,
    dns: &mut Option<(SocketAddr, RuntimeTask)>,
) -> Result<(), RuntimeError> {
    let desired_listeners = next.listener_ports()?;
    let desired_controller = next.controller_addr()?;
    let desired_dns = next.dns.as_ref().map(|config| config.listen);

    let mut prepared_listeners = Vec::new();
    for &(kind, port) in &desired_listeners {
        if listeners.contains_key(&(kind, port)) {
            continue;
        }
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let listener = TcpListener::bind(address).await?;
        let udp = if matches!(kind, ListenerKind::Socks | ListenerKind::Mixed) {
            Some(Arc::new(UdpSocket::bind(address).await?))
        } else {
            None
        };
        prepared_listeners.push((kind, port, listener, udp));
    }
    let prepared_controller = if desired_controller.is_some_and(|address| {
        controller
            .as_ref()
            .is_none_or(|(current, _)| *current != address)
    }) {
        let address = desired_controller.expect("checked as present");
        Some((address, TcpListener::bind(address).await?))
    } else {
        None
    };
    let prepared_dns = if desired_dns
        .is_some_and(|address| dns.as_ref().is_none_or(|(current, _)| *current != address))
    {
        let address = desired_dns.expect("checked as present");
        Some((
            address,
            TcpListener::bind(address).await?,
            UdpSocket::bind(address).await?,
        ))
    } else {
        None
    };

    state.sync_selectors(next.proxy_groups.iter().map(|group| {
        (
            group.name.as_str(),
            group.proxies.as_slice(),
            group.default_selected.as_deref(),
        )
    }));
    config_sender.send_replace(Arc::new(next));
    dns_service.clear_cache().await;
    dns_service.reset_connections().await;

    for (kind, port, listener, udp) in prepared_listeners {
        let task_shutdown = CancellationToken::new();
        let child_shutdown = task_shutdown.clone();
        let task_config = config_receiver.clone();
        let task_state = Arc::clone(state);
        let handle = tokio::spawn(async move {
            run_listener(kind, listener, udp, task_config, task_state, child_shutdown).await;
        });
        listeners.insert(
            (kind, port),
            RuntimeTask {
                shutdown: task_shutdown,
                handle,
            },
        );
    }

    apply_controller_task(
        prepared_controller,
        desired_controller,
        config_receiver,
        state,
        dns_service,
        controller_updates,
        controller,
    )
    .await;

    apply_dns_task(
        prepared_dns,
        desired_dns,
        config_receiver,
        state,
        dns_service,
        dns,
    )
    .await;

    let desired: Vec<_> = desired_listeners.into_iter().collect();
    let obsolete: Vec<_> = listeners
        .keys()
        .filter(|key| !desired.contains(key))
        .copied()
        .collect();
    for key in obsolete {
        if let Some(task) = listeners.remove(&key) {
            stop_task(task).await;
        }
    }
    Ok(())
}

async fn apply_controller_task(
    prepared: Option<(SocketAddr, TcpListener)>,
    desired: Option<SocketAddr>,
    config: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    config_updates: &mpsc::Sender<rewrite_controller::ConfigUpdate>,
    current: &mut Option<(SocketAddr, RuntimeTask)>,
) {
    if let Some((address, listener)) = prepared {
        if let Some((_, previous)) = current.take() {
            stop_task(previous).await;
        }
        let task_shutdown = CancellationToken::new();
        let child_shutdown = task_shutdown.clone();
        let task_config = config.clone();
        let task_state = Arc::clone(state);
        let task_dns_service = Arc::clone(dns_service);
        let task_config_updates = config_updates.clone();
        let handle = tokio::spawn(async move {
            rewrite_controller::serve(
                listener,
                task_dns_service,
                task_config,
                task_state,
                task_config_updates,
                child_shutdown,
            )
            .await;
        });
        *current = Some((
            address,
            RuntimeTask {
                shutdown: task_shutdown,
                handle,
            },
        ));
    } else if desired.is_none()
        && let Some((_, previous)) = current.take()
    {
        stop_task(previous).await;
    }
}

async fn apply_dns_task(
    prepared: Option<(SocketAddr, TcpListener, UdpSocket)>,
    desired: Option<SocketAddr>,
    config: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    current: &mut Option<(SocketAddr, RuntimeTask)>,
) {
    if let Some((address, tcp, udp)) = prepared {
        if let Some((_, previous)) = current.take() {
            stop_task(previous).await;
        }
        let task_shutdown = CancellationToken::new();
        let child_shutdown = task_shutdown.clone();
        let task_config = config.clone();
        let task_state = Arc::clone(state);
        let task_dns_service = Arc::clone(dns_service);
        let handle = tokio::spawn(async move {
            rewrite_dns::serve(
                tcp,
                udp,
                task_dns_service,
                task_config,
                task_state,
                child_shutdown,
            )
            .await;
        });
        *current = Some((
            address,
            RuntimeTask {
                shutdown: task_shutdown,
                handle,
            },
        ));
    } else if desired.is_none()
        && let Some((_, previous)) = current.take()
    {
        stop_task(previous).await;
    }
}

async fn stop_task(task: RuntimeTask) {
    task.shutdown.cancel();
    if tokio::time::timeout(Duration::from_secs(3), task.handle)
        .await
        .is_err()
    {
        eprintln!("runtime generation shutdown deadline exceeded");
    }
}

async fn run_listener(
    kind: ListenerKind,
    listener: TcpListener,
    udp: Option<Arc<UdpSocket>>,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    let mut connections = JoinSet::new();
    let mut datagram = vec![0_u8; 65_535];
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((client, _)) => {
                        let connection_config = Arc::clone(&config.borrow());
                        let connection_state = Arc::clone(&state);
                        let connection_shutdown = shutdown.child_token();
                        connections.spawn(async move {
                            serve_connection(
                                client,
                                kind,
                                &connection_config,
                                &connection_state,
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
            received = receive_udp(udp.as_ref(), &mut datagram) => {
                if let Ok((length, source)) = received
                    && let Some(socket) = &udp
                {
                    let packet = datagram[..length].to_vec();
                    let socket = Arc::clone(socket);
                    let connection_config = Arc::clone(&config.borrow());
                    let connection_state = Arc::clone(&state);
                    connections.spawn(async move {
                        handle_udp(
                            socket,
                            packet,
                            source,
                            connection_config,
                            connection_state,
                        ).await;
                    });
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
}

async fn receive_udp(
    socket: Option<&Arc<UdpSocket>>,
    buffer: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match socket {
        Some(socket) => socket.recv_from(buffer).await,
        None => pending().await,
    }
}

async fn handle_udp(
    listener: Arc<UdpSocket>,
    packet: Vec<u8>,
    source: SocketAddr,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
) {
    let inbound_port = listener.local_addr().map_or(0, |address| address.port());
    let accepted = match rewrite_inbound::decode_socks5_udp(&packet, source, inbound_port) {
        Ok(accepted) => accepted,
        Err(error) => {
            state.log("error", format!("SOCKS5 UDP packet rejected: {error}"));
            return;
        }
    };
    let mut metadata = accepted.metadata.clone();
    // Both pinned default SOCKS and mixed UDP listeners are backed by the Go
    // SOCKS UDP listener and therefore expose DEFAULT-SOCKS, not DEFAULT-MIXED.
    "DEFAULT-SOCKS".clone_into(&mut metadata.inbound_name);
    let fake_host = apply_host_mapping(&mut metadata, &config, &state);
    let decision =
        mode_decision(&config, &state).unwrap_or_else(|| config.rules.evaluate(&metadata));
    if decision.route() != Route::Direct {
        return;
    }
    let tracker = state.register(
        &metadata,
        &decision.target,
        decision.matched_kind.as_deref(),
    );
    let target = match resolve_udp_target(&metadata, fake_host.as_deref(), &config).await {
        Ok(target) => target,
        Err(error) => {
            state.log("error", format!("DIRECT UDP resolution failed: {error}"));
            return;
        }
    };
    let family = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let outbound = match UdpSocket::bind(family).await {
        Ok(socket) => socket,
        Err(error) => {
            state.log("error", format!("DIRECT UDP bind failed: {error}"));
            return;
        }
    };
    if outbound.send_to(accepted.payload, target).await.is_err() {
        return;
    }
    let mut response = vec![0_u8; 65_535];
    let received = tokio::time::timeout(Duration::from_secs(5), outbound.recv_from(&mut response));
    let Ok(Ok((length, remote))) = received.await else {
        return;
    };
    let response = rewrite_inbound::encode_socks5_udp(remote, &response[..length]);
    if listener.send_to(&response, source).await.is_ok() {
        tracker.finish(accepted.payload.len() as u64, length as u64);
    }
}

async fn resolve_udp_target(
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

async fn serve_connection(
    client: TcpStream,
    kind: ListenerKind,
    config: &Config,
    state: &Arc<RuntimeState>,
    shutdown: &CancellationToken,
) {
    let protocol = match kind {
        ListenerKind::Http => ListenerProtocol::Http,
        ListenerKind::Socks => ListenerProtocol::Socks,
        ListenerKind::Mixed => ListenerProtocol::Mixed,
    };
    let accepted = tokio::select! {
        () = shutdown.cancelled() => return,
        result = tokio::time::timeout(
            Duration::from_secs(10),
            rewrite_inbound::accept(client, protocol, &config.authentication),
        ) => {
            match result {
                Ok(Ok(accepted)) => accepted,
                Ok(Err(error)) => {
                    state.log("error", format!("local inbound rejected: {error}"));
                    return;
                }
                Err(_) => {
                    state.log("error", "local inbound handshake timed out");
                    return;
                }
            }
        }
    };

    if accepted.command == InboundCommand::UdpAssociate {
        let mut client = accepted.client;
        let mut discard = [0_u8; 1024];
        tokio::select! {
            () = shutdown.cancelled() => {}
            _ = tokio::io::AsyncReadExt::read(&mut client, &mut discard) => {}
        }
        return;
    }

    let mut metadata = accepted.metadata.clone();
    match kind {
        ListenerKind::Http => "DEFAULT-HTTP",
        ListenerKind::Socks => "DEFAULT-SOCKS",
        ListenerKind::Mixed => "DEFAULT-MIXED",
    }
    .clone_into(&mut metadata.inbound_name);
    let fake_host = apply_host_mapping(&mut metadata, config, state);
    let decision = evaluate_tcp_rules(&mut metadata, config, state).await;
    let route = decision.route();
    state.log(
        "info",
        format!(
            "[TCP] {} --> {} match {} using {}",
            metadata.source_port,
            metadata.destination.authority(),
            decision.matched_kind.as_deref().unwrap_or("none"),
            decision.target
        ),
    );
    let tracker = state.register(
        &metadata,
        &decision.target,
        decision.matched_kind.as_deref(),
    );
    if matches!(route, Route::Reject | Route::RejectDrop) {
        return;
    }
    let Some(mut remote) = connect_tcp_outbound(
        &metadata,
        fake_host.as_deref(),
        &decision.target,
        route,
        config,
        state,
        shutdown,
    )
    .await
    else {
        return;
    };
    let client = accepted.client;
    if !accepted.preface.is_empty() && remote.write_all(&accepted.preface).await.is_err() {
        return;
    }

    relay_tracked_tcp(client, remote, tracker, state, shutdown).await;
}

async fn connect_tcp_outbound(
    metadata: &Metadata,
    fake_host: Option<&str>,
    target: &str,
    route: Route,
    config: &Config,
    state: &RuntimeState,
    shutdown: &CancellationToken,
) -> Option<rewrite_outbound::BoxedOutboundStream> {
    let outbound_target = resolve_selector_target(target, config, state)?;
    if matches!(outbound_target.as_str(), "REJECT" | "REJECT-DROP") {
        return None;
    }
    if route == Route::Direct || outbound_target == "DIRECT" {
        let destination =
            match resolve_direct_destination(&metadata.destination, fake_host, config).await {
                Ok(destination) => destination,
                Err(error) => {
                    state.log("error", format!("DIRECT DNS resolution failed: {error}"));
                    return None;
                }
            };
        return tokio::select! {
            () = shutdown.cancelled() => None,
            result = rewrite_outbound::connect(&destination, config.ipv6) => match result {
                Ok(remote) => Some(Box::new(remote)),
                Err(error) => {
                    state.log("error", format!("DIRECT connection failed: {error}"));
                    None
                }
            }
        };
    }
    let proxy = config
        .proxies
        .iter()
        .chain(
            config
                .proxy_providers
                .iter()
                .flat_map(|provider| provider.proxies.iter()),
        )
        .find(|proxy| proxy.name == outbound_target)?;
    let server = Destination {
        host: proxy
            .server
            .parse()
            .map_or_else(|_| Host::Domain(proxy.server.clone()), Host::Ip),
        port: proxy.port,
    };
    let credentials = proxy.username.as_deref().zip(proxy.password.as_deref());
    match proxy.kind {
        ProxyKind::Http => tokio::select! {
            () = shutdown.cancelled() => None,
            result = rewrite_outbound::connect_http(
                &server,
                &metadata.destination,
                config.ipv6,
                credentials,
            ) => match result {
                Ok(remote) => Some(remote),
                Err(error) => {
                    state.log("error", format!("HTTP proxy connection failed: {error}"));
                    None
                }
            }
        },
        ProxyKind::Socks5 => tokio::select! {
            () = shutdown.cancelled() => None,
            result = rewrite_outbound::connect_socks5(
                &server,
                &metadata.destination,
                config.ipv6,
                credentials,
            ) => match result {
                Ok(remote) => Some(remote),
                Err(error) => {
                    state.log("error", format!("SOCKS5 proxy connection failed: {error}"));
                    None
                }
            }
        },
    }
}

fn resolve_selector_target(target: &str, config: &Config, state: &RuntimeState) -> Option<String> {
    let mut current = target.to_owned();
    let mut visited = std::collections::BTreeSet::new();
    while let Some(group) = config
        .proxy_groups
        .iter()
        .find(|group| group.name == current)
    {
        if !visited.insert(current.clone()) {
            return None;
        }
        current = state
            .selector_proxy(&group.name)
            .or_else(|| group.proxies.first().cloned())?;
    }
    Some(current)
}

async fn relay_tracked_tcp(
    mut client: TcpStream,
    mut remote: rewrite_outbound::BoxedOutboundStream,
    tracker: ConnectionGuard,
    state: &RuntimeState,
    shutdown: &CancellationToken,
) {
    tokio::select! {
        () = shutdown.cancelled() => {}
        () = tracker.cancelled() => {}
        result = rewrite_net::relay(&mut client, &mut remote) => match result {
            Ok((uploaded, downloaded)) => tracker.finish(uploaded, downloaded),
            Err(error) => state.log("error", format!("TCP relay failed: {error}")),
        }
    }
}

async fn evaluate_tcp_rules(
    metadata: &mut Metadata,
    config: &Config,
    state: &RuntimeState,
) -> rewrite_rules::Decision {
    if let Some(decision) = mode_decision(config, state) {
        return decision;
    }
    match config.rules.evaluate_lazy(metadata) {
        LazyEvaluation::Decision(decision) => decision,
        LazyEvaluation::ResolveDestinationIp => {
            match resolve_rule_destination(metadata, config).await {
                Ok(address) => metadata.destination_ip = Some(unmap_ip(address)),
                Err(error) => state.log("error", format!("rule DNS resolution failed: {error}")),
            }
            config.rules.evaluate(metadata)
        }
    }
}

fn mode_decision(config: &Config, state: &RuntimeState) -> Option<rewrite_rules::Decision> {
    let target = match config.mode {
        Mode::Rule => return None,
        Mode::Direct => "DIRECT".to_owned(),
        Mode::Global => state.global_proxy(),
    };
    Some(rewrite_rules::Decision {
        target,
        matched_kind: None,
        rematch_cycle: false,
        rematch_name: String::new(),
        special_rules: String::new(),
    })
}

async fn resolve_direct_destination(
    destination: &Destination,
    fake_host: Option<&str>,
    config: &Config,
) -> Result<Destination, rewrite_dns::DnsError> {
    let host = fake_host.or(match &destination.host {
        Host::Domain(host) => Some(host.as_str()),
        Host::Ip(_) => None,
    });
    let Some(host) = host else {
        return Ok(destination.clone());
    };
    let Some(dns) = config.dns.as_ref() else {
        if fake_host.is_some() {
            return Err(rewrite_dns::DnsError::Inactive);
        }
        return Ok(destination.clone());
    };
    let address = rewrite_dns::resolve_direct_domain(dns, host, config.ipv6).await?;
    Ok(Destination {
        host: Host::Ip(address),
        port: destination.port,
    })
}

async fn resolve_rule_destination(
    metadata: &Metadata,
    config: &Config,
) -> Result<std::net::IpAddr, String> {
    if metadata.host.is_empty() {
        return Err("destination has no domain".to_owned());
    }
    if let Some(dns) = config.dns.as_ref() {
        return rewrite_dns::resolve_domain(dns, &metadata.host, config.ipv6)
            .await
            .map_err(|error| error.to_string());
    }
    let mut addresses =
        tokio::net::lookup_host((metadata.host.as_str(), metadata.destination.port))
            .await
            .map_err(|error| error.to_string())?;
    addresses
        .find(|address| config.ipv6 || address.is_ipv4())
        .map(|address| address.ip())
        .ok_or_else(|| "system resolver returned no permitted address".to_owned())
}

fn apply_host_mapping(
    metadata: &mut Metadata,
    config: &Config,
    state: &RuntimeState,
) -> Option<String> {
    match metadata.destination.host.clone() {
        Host::Ip(address) => {
            if let Some(dns) = config.dns.as_ref()
                && dns.mode == DnsMode::FakeIp
                && let Some(fake) = dns.fake_ip.as_ref()
            {
                let network = if address.is_ipv4() {
                    fake.ipv4_range
                } else {
                    fake.ipv6_range
                };
                if let Some(network) = network
                    && let Some(host) = state.lookup_fake_ip(network, address, config.store_fake_ip)
                {
                    metadata.host.clone_from(&host);
                    metadata.destination.host = Host::Domain(host.clone());
                    return Some(host);
                }
            }
            if let Some(host) = state.lookup_dns_mapping(address) {
                metadata.host = host;
            }
        }
        Host::Domain(domain) => {
            let first_target = match config.hosts.search(&domain) {
                Some(HostEntry::Domain(target)) => Some(target.clone()),
                _ => None,
            };
            if let Some(target) = &first_target {
                metadata.host.clone_from(target);
                metadata.destination.host = Host::Domain(target.clone());
            }
            let lookup_name = first_target.as_deref().unwrap_or(&domain);
            let configured = config.hosts.resolve(lookup_name);
            let system = (configured.is_none()
                && config.dns.as_ref().is_some_and(|dns| dns.use_system_hosts))
            .then(|| rewrite_dns::system_host_addresses(lookup_name))
            .flatten()
            .map(HostEntry::Addresses);
            if let Some(HostEntry::Addresses(addresses)) = configured.or(system)
                && !addresses.is_empty()
            {
                let address = addresses[rand::rng().random_range(0..addresses.len())];
                metadata.destination.host = Host::Ip(address);
                metadata.destination_ip = Some(address);
            }
        }
    }
    None
}

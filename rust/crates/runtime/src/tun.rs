use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use ipnet::IpNet;
use rewrite_config::{Config, DnsClassicEndpoint, DnsResolverClient, TunConfig};
use rewrite_inbound::{BoxedInboundStream, InboundStream};
#[cfg(target_os = "macos")]
use rewrite_platform::apply_tun_system_dns;
#[cfg(target_os = "windows")]
use rewrite_platform::apply_windows_tun_interface_dns;
use rewrite_platform::{
    DefaultInterfaceSnapshot, DnsOwner, NETWORK_CHANGE_POLL, OwnedRoute, RouteOwner,
    clear_outbound_bypass, current_default_interface, current_route_platform,
    default_auto_route_destinations, install_bypass_host_route, install_device_route,
    install_outbound_bypass, plan_auto_route_prefixes, plan_network_change,
    planned_bypass_host_route, reject_existing_windows_tun_device, set_auto_detect_bind_interface,
    update_outbound_bypass, validate_tun_device_name,
};
use rewrite_state::RuntimeState;
use rewrite_tun::{
    TunDeviceConfig, TunInboundStream, build_smoltcp_stack, open_tun_device, spawn_session_hub,
};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::listener::{UdpReplySink, UdpSessionContext, UdpSessionPacket, UdpSessions};
use crate::tcp::{apply_host_mapping, relay_dns_tcp, serve_stream_session};
use crate::types::RuntimeError;

/// Soft cap on concurrent TUN TCP tasks (Phase 8F resource bound).
const TUN_MAX_TCP_TASKS: usize = 4096;
/// Soft cap on concurrent TUN UDP sessions (Phase 8F resource bound).
const TUN_MAX_UDP_SESSIONS: usize = 4096;

struct TunClientStream(TunInboundStream);

impl InboundStream for TunClientStream {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.0.local_addr())
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.0.peer_addr())
    }
}

impl tokio::io::AsyncRead for TunClientStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.0), cx, buf)
    }
}

impl tokio::io::AsyncWrite for TunClientStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.0), cx)
    }
}

/// Runs the Linux/macOS/Windows TUN data path until cancelled, then restores DNS and routes.
pub(super) async fn run_tun_listener(
    tun_config: TunConfig,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
    ready: Option<oneshot::Sender<Result<(), RuntimeError>>>,
) -> Result<(), RuntimeError> {
    if let Err(error) = tun_runtime_supported() {
        if let Some(ready) = ready {
            let _ = ready.send(Err(RuntimeError::Tun(error.to_string())));
        }
        return Err(error);
    }

    let prepared = match prepare_tun(&tun_config, &config.borrow()) {
        Ok(prepared) => prepared,
        Err(error) => {
            if let Some(ready) = ready {
                let _ = ready.send(Err(RuntimeError::Tun(error.to_string())));
            }
            return Err(error);
        }
    };
    if let Some(ready) = ready {
        let _ = ready.send(Ok(()));
    }
    run_prepared_tun(prepared, tun_config, config, state, dns_service, shutdown).await
}

fn tun_runtime_supported() -> Result<(), RuntimeError> {
    if cfg!(all(target_os = "macos", not(target_arch = "aarch64"))) {
        return Err(RuntimeError::Tun(
            "Phase 8B TUN runtime is Darwin arm64 only; other Darwin arches are not in this gate"
                .to_owned(),
        ));
    }
    if cfg!(all(target_os = "windows", not(target_arch = "x86_64"))) {
        return Err(RuntimeError::Tun(
            "Phase 8C is Windows x86_64 only; other Windows arches are not in this gate".to_owned(),
        ));
    }
    if cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows") {
        return Ok(());
    }
    Err(RuntimeError::Tun(
        "Phase 8A/8B/8C TUN runtime is Linux, Darwin arm64, and Windows x86_64 only".to_owned(),
    ))
}

struct PreparedTun {
    device: rewrite_tun::TunDevice,
    dns: DnsOwner,
    routes: RouteOwner,
    mtu: u16,
    device_name: String,
}

fn prepare_tun(tun_config: &TunConfig, config: &Config) -> Result<PreparedTun, RuntimeError> {
    validate_tun_device_name(&tun_config.device, current_route_platform())
        .map_err(|error| RuntimeError::Tun(error.to_string()))?;
    reject_existing_windows_tun_device(&tun_config.device)
        .map_err(|error| RuntimeError::Tun(error.to_string()))?;
    let device_config = TunDeviceConfig::from_tun_config(tun_config);
    let device =
        open_tun_device(&device_config).map_err(|error| RuntimeError::Tun(error.to_string()))?;
    let device_name = device.name().to_owned();
    let physical = current_default_interface(Some(&device_name))
        .unwrap_or_else(|_| DefaultInterfaceSnapshot::lost());
    let mut routes = RouteOwner::new();
    if tun_config.auto_route {
        if let Err(error) =
            protect_loop_avoidance(tun_config, config, &physical, &device_name, &mut routes)
        {
            let _ = routes.revert_all();
            return Err(RuntimeError::Tun(error.to_string()));
        }
        if let Err(error) = install_auto_routes(tun_config, &device_name, &physical, &mut routes) {
            let _ = routes.revert_all();
            return Err(RuntimeError::Tun(error.to_string()));
        }
        let destinations = auto_route_destinations(tun_config);
        install_outbound_bypass(
            &device_name,
            &physical,
            bypass_skip_prefixes(tun_config, config),
            destinations.iter().any(|prefix| prefix.addr().is_ipv4()),
            destinations.iter().any(|prefix| prefix.addr().is_ipv6()),
        );
    }
    let dns = match apply_system_dns(tun_config, &device_name) {
        Ok(owner) => owner,
        Err(error) => {
            clear_outbound_bypass();
            let _ = routes.revert_all();
            return Err(error);
        }
    };
    Ok(PreparedTun {
        device,
        dns,
        routes,
        mtu: device_config.mtu,
        device_name,
    })
}

#[allow(clippy::unnecessary_wraps)] // Darwin/Windows apply can fail; Linux is a no-op.
fn apply_system_dns(tun_config: &TunConfig, device_name: &str) -> Result<DnsOwner, RuntimeError> {
    #[cfg(target_os = "macos")]
    {
        let _ = device_name;
        let address = tun_config.tun_dns_server().ok_or_else(|| {
            RuntimeError::Tun("Darwin TUN system DNS requires inet4-address".to_owned())
        })?;
        apply_tun_system_dns(address).map_err(|error| RuntimeError::Tun(error.to_string()))
    }
    #[cfg(target_os = "windows")]
    {
        let address = tun_config.tun_dns_server().ok_or_else(|| {
            RuntimeError::Tun("Windows TUN adapter DNS requires inet4-address".to_owned())
        })?;
        apply_windows_tun_interface_dns(device_name, address)
            .map_err(|error| RuntimeError::Tun(error.to_string()))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = tun_config;
        let _ = device_name;
        Ok(DnsOwner::noop())
    }
}

#[allow(clippy::too_many_lines)]
async fn run_prepared_tun(
    prepared: PreparedTun,
    tun_config: TunConfig,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) -> Result<(), RuntimeError> {
    let PreparedTun {
        device,
        mut dns,
        mut routes,
        mtu,
        device_name,
    } = prepared;
    let mut default_interface = current_default_interface(Some(&device_name))
        .unwrap_or_else(|_| DefaultInterfaceSnapshot::lost());
    let bind_physical = tun_config.auto_detect_interface || tun_config.auto_route;
    if bind_physical {
        set_auto_detect_bind_interface(Some(&default_interface));
    }
    let watch_network = tun_config.auto_route || tun_config.auto_detect_interface;
    let handles = build_smoltcp_stack(usize::from(mtu))
        .map_err(|error| RuntimeError::Tun(error.to_string()))?;
    if let Some(runner) = handles.runner {
        tokio::spawn(runner);
    }
    let hub = spawn_session_hub(handles.tcp, handles.udp, shutdown.child_token());
    let (mut tcp_rx, mut udp_rx, reply_tx) = hub.into_parts();
    let (mut stack_sink, mut stack_stream) = handles.stack.split();
    let device = device.into_device();

    let pump_shutdown = shutdown.child_token();
    let device_task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            tokio::select! {
                () = pump_shutdown.cancelled() => break,
                received = device.recv(&mut buffer) => {
                    let Ok(length) = received else { break };
                    if stack_sink.send(buffer[..length].to_vec()).await.is_err() {
                        break;
                    }
                }
                frame = stack_stream.next() => {
                    let Some(frame) = frame else { break };
                    let Ok(packet) = frame else { break };
                    if device.send(&packet).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let tun_config = Arc::new(tun_config);
    let mut connections = JoinSet::new();
    let mut udp_sessions = UdpSessions::default();
    let mut network_tick = tokio::time::interval(NETWORK_CHANGE_POLL);
    network_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            _ = network_tick.tick(), if watch_network => {
                let current_config = Arc::clone(&config.borrow());
                apply_network_change(
                    &tun_config,
                    &current_config,
                    &state,
                    &dns_service,
                    &device_name,
                    &mut default_interface,
                    &mut routes,
                    &mut dns,
                )
                .await;
            }
            session = tcp_rx.recv() => {
                let Some(session) = session else { break };
                if !accept_tun_flow(connections.len(), TUN_MAX_TCP_TASKS) {
                    state.log(
                        "error",
                        "TUN TCP session cap reached; refusing unbounded growth",
                    );
                    continue;
                }
                let connection_config = Arc::clone(&config.borrow());
                let connection_state = Arc::clone(&state);
                let connection_dns = Arc::clone(&dns_service);
                let connection_shutdown = shutdown.child_token();
                let destination = session.stream.local_addr();
                let tun_config = Arc::clone(&tun_config);
                connections.spawn(async move {
                    let client: BoxedInboundStream = Box::new(TunClientStream(session.stream));
                    if tun_config.hijacks_dns(destination) {
                        if connection_config.dns.is_none() {
                            connection_state.log(
                                "error",
                                "TUN DNS hijack ignored because dns: is not configured",
                            );
                            return;
                        }
                        let tracker = connection_state.register(
                            &session.metadata,
                            "DNS",
                            Some("TUN-DNS"),
                        );
                        relay_dns_tcp(
                            client,
                            &[],
                            &connection_config,
                            &connection_state,
                            &connection_dns,
                            tracker,
                            &connection_shutdown,
                        )
                        .await;
                        return;
                    }
                    serve_stream_session(
                        client,
                        session.metadata,
                        &connection_config,
                        &connection_state,
                        &connection_dns,
                        &connection_shutdown,
                    )
                    .await;
                });
            }
            datagram = udp_rx.recv() => {
                let Some(datagram) = datagram else { break };
                if !udp_sessions.contains(&datagram.session_peer)
                    && !accept_tun_flow(udp_sessions.len(), TUN_MAX_UDP_SESSIONS)
                {
                    state.log(
                        "error",
                        "TUN UDP session cap reached; refusing unbounded growth",
                    );
                    continue;
                }
                let connection_config = Arc::clone(&config.borrow());
                let mut metadata = datagram.metadata;
                let fake_host = apply_host_mapping(&mut metadata, &connection_config, &state);
                let hijacked = tun_config.hijacks_dns(datagram.remote);
                if hijacked && connection_config.dns.is_none() {
                    state.log(
                        "error",
                        "TUN DNS hijack ignored because dns: is not configured",
                    );
                    continue;
                }
                let request = if hijacked {
                    UdpSessionPacket::dns_hijack(metadata, fake_host, datagram.payload)
                } else {
                    UdpSessionPacket::from_parts(metadata, fake_host, datagram.payload)
                };
                udp_sessions.dispatch(
                    datagram.session_peer,
                    request,
                    UdpSessionContext::new(
                        UdpReplySink::Tun {
                            tx: reply_tx.clone(),
                        },
                        connection_config,
                        Arc::clone(&state),
                        Arc::clone(&dns_service),
                        shutdown.child_token(),
                    ),
                );
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(join_error)) = result {
                    state.log("error", format!("TUN TCP task failed: {join_error}"));
                }
            }
            result = udp_sessions.tasks.join_next(), if !udp_sessions.tasks.is_empty() => {
                udp_sessions.reap(result.as_ref());
            }
        }
    }

    shutdown.cancel();
    if tun_config.auto_detect_interface || tun_config.auto_route {
        set_auto_detect_bind_interface(None);
    }
    clear_outbound_bypass();
    let _ = device_task.await;
    while let Some(result) = connections.join_next().await {
        if let Err(join_error) = result {
            state.log(
                "error",
                format!("TUN TCP task failed during shutdown: {join_error}"),
            );
        }
    }
    udp_sessions.shutdown(&state).await;
    if let Err(error) = dns.restore() {
        state.log("error", format!("TUN DNS restore failed: {error}"));
    }
    if let Err(error) = routes.revert_all() {
        state.log("error", format!("TUN route cleanup failed: {error}"));
    }
    Ok(())
}

fn accept_tun_flow(active: usize, cap: usize) -> bool {
    active < cap
}

#[allow(clippy::too_many_arguments)]
async fn apply_network_change(
    tun_config: &TunConfig,
    config: &Config,
    state: &RuntimeState,
    dns_service: &rewrite_dns::DnsService,
    device_name: &str,
    previous: &mut DefaultInterfaceSnapshot,
    routes: &mut RouteOwner,
    dns: &mut DnsOwner,
) {
    let after = current_default_interface(Some(device_name))
        .unwrap_or_else(|_| DefaultInterfaceSnapshot::lost());
    let Some(plan) = plan_network_change(
        previous,
        &after,
        device_name,
        tun_config.auto_detect_interface,
        cfg!(target_os = "macos"),
    ) else {
        return;
    };

    let level = if after.is_lost() { "error" } else { "warning" };
    eprintln!("{}", plan.log);
    state.log(level, plan.log);

    if plan.update_detected_interface || tun_config.auto_route {
        set_auto_detect_bind_interface(Some(&after));
        // Endpoints stay bound to the NIC they were created on. Drop cached
        // TUIC/Hysteria2 clients and bump the DIRECT UDP generation so the
        // next dial / next datagram rebinds the new uplink.
        state.clear_tuic_clients().await;
        state.clear_hysteria2_clients().await;
        state.bump_network_generation();
        let rebound = format!("[TUN] rebound QUIC endpoints onto {}", after.display_name());
        eprintln!("{rebound}");
        state.log("warning", rebound);
    }

    if plan.reprotect_hosts {
        if let Err(error) = routes.revert_not_on_device(device_name) {
            state.log(
                "warning",
                format!("[TUN] failed to drop stale bypass routes: {error}"),
            );
        }
        if let Err(error) = protect_loop_avoidance(tun_config, config, &after, device_name, routes)
        {
            state.log(
                "warning",
                format!("[TUN] failed to re-protect loop-avoidance routes: {error}"),
            );
        }
        if let Err(error) = install_physical_exceptions(tun_config, device_name, &after, routes) {
            state.log(
                "warning",
                format!("[TUN] failed to re-install route-exclude exceptions: {error}"),
            );
        }
    }
    update_outbound_bypass(&after);

    if plan.reapply_system_dns {
        if let Err(error) = dns.restore() {
            state.log(
                "warning",
                format!("[TUN] failed to restore system DNS before re-apply: {error}"),
            );
        }
        match apply_system_dns(tun_config, device_name) {
            Ok(applied) => *dns = applied,
            Err(error) => {
                state.log(
                    "warning",
                    format!("[TUN] failed to re-apply system DNS after network change: {error}"),
                );
            }
        }
    }

    if plan.reset_resolver {
        dns_service.reset_connections().await;
    }

    *previous = after;
}

fn install_auto_routes(
    tun: &TunConfig,
    device: &str,
    physical: &DefaultInterfaceSnapshot,
    owner: &mut RouteOwner,
) -> Result<(), rewrite_platform::PlatformError> {
    let destinations = auto_route_destinations(tun);
    let excludes = auto_route_excludes(tun);
    let plan = plan_auto_route_prefixes(&destinations, &excludes);
    for destination in plan.tun {
        let route = OwnedRoute {
            destination,
            device: device.to_owned(),
            gateway: None,
            table: None,
        };
        install_device_route(&route)?;
        owner.record(route);
    }
    install_physical_exceptions_plan(
        &plan.physical_exceptions,
        device,
        physical,
        &destinations,
        owner,
    )
}

fn install_physical_exceptions(
    tun: &TunConfig,
    tun_device: &str,
    physical: &DefaultInterfaceSnapshot,
    owner: &mut RouteOwner,
) -> Result<(), rewrite_platform::PlatformError> {
    let destinations = auto_route_destinations(tun);
    let excludes = auto_route_excludes(tun);
    let plan = plan_auto_route_prefixes(&destinations, &excludes);
    install_physical_exceptions_plan(
        &plan.physical_exceptions,
        tun_device,
        physical,
        &destinations,
        owner,
    )
}

fn install_physical_exceptions_plan(
    exceptions: &[IpNet],
    tun_device: &str,
    physical: &DefaultInterfaceSnapshot,
    destinations: &[IpNet],
    owner: &mut RouteOwner,
) -> Result<(), rewrite_platform::PlatformError> {
    let capture_ipv4 = destinations.iter().any(|prefix| prefix.addr().is_ipv4());
    let capture_ipv6 = destinations.iter().any(|prefix| prefix.addr().is_ipv6());
    for destination in exceptions {
        let Some(route) = planned_bypass_host_route(
            destination.addr(),
            physical,
            tun_device,
            capture_ipv4,
            capture_ipv6,
        )?
        else {
            continue;
        };
        let mut route = route;
        route.destination = *destination;
        install_bypass_host_route(&route, tun_device, owner)?;
    }
    Ok(())
}

fn auto_route_destinations(tun: &TunConfig) -> Vec<IpNet> {
    let mut destinations = Vec::new();
    destinations.extend(tun.route_address.iter().copied());
    destinations.extend(tun.inet4_route_address.iter().copied());
    destinations.extend(tun.inet6_route_address.iter().copied());
    if destinations.is_empty() {
        destinations.extend(default_auto_route_destinations(current_route_platform()));
    }
    destinations
}

fn auto_route_excludes(tun: &TunConfig) -> Vec<IpNet> {
    tun.route_exclude_address
        .iter()
        .chain(tun.inet4_route_exclude_address.iter())
        .chain(tun.inet6_route_exclude_address.iter())
        .copied()
        .collect()
}

fn bypass_skip_prefixes(tun: &TunConfig, config: &Config) -> Vec<IpNet> {
    let mut prefixes = Vec::new();
    prefixes.extend(tun.inet4_address.iter().copied());
    prefixes.extend(tun.inet6_address.iter().copied());
    if let Some(dns) = &config.dns
        && let Some(fake_ip) = &dns.fake_ip
    {
        prefixes.extend(fake_ip.ipv4_range);
        prefixes.extend(fake_ip.ipv6_range);
    }
    prefixes
}

fn protect_loop_avoidance(
    tun: &TunConfig,
    config: &Config,
    physical: &DefaultInterfaceSnapshot,
    tun_device: &str,
    owner: &mut RouteOwner,
) -> Result<(), rewrite_platform::PlatformError> {
    let mut hosts = Vec::new();
    if let Some(dns) = &config.dns {
        collect_resolver_hosts(&dns.classic_upstreams, &mut hosts);
        collect_resolver_clients(&dns.main_resolvers, &mut hosts);
        collect_resolver_clients(&dns.default_resolvers, &mut hosts);
        collect_resolver_clients(&dns.proxy_resolvers, &mut hosts);
        if let Some(fallback) = &dns.fallback {
            collect_resolver_clients(&fallback.resolvers, &mut hosts);
        }
    }
    for proxy in &config.proxies {
        if let Ok(address) = proxy.server.parse::<IpAddr>() {
            hosts.push(address);
        }
    }
    hosts.sort_unstable();
    hosts.dedup();
    let destinations = auto_route_destinations(tun);
    let capture_ipv4 = destinations.iter().any(|prefix| prefix.addr().is_ipv4());
    let capture_ipv6 = destinations.iter().any(|prefix| prefix.addr().is_ipv6());
    for host in hosts {
        if let Some(route) =
            planned_bypass_host_route(host, physical, tun_device, capture_ipv4, capture_ipv6)?
        {
            install_bypass_host_route(&route, tun_device, owner)?;
        }
    }
    Ok(())
}

fn collect_resolver_clients(resolvers: &[DnsResolverClient], hosts: &mut Vec<IpAddr>) {
    for resolver in resolvers {
        match resolver {
            DnsResolverClient::Classic(upstream) => collect_classic(upstream, hosts),
            DnsResolverClient::Network { upstream, .. } => hosts.push(upstream.address.ip()),
            DnsResolverClient::System
            | DnsResolverClient::Dhcp(_)
            | DnsResolverClient::Rcode(_)
            | DnsResolverClient::Tailscale(_) => {}
        }
    }
}

fn collect_resolver_hosts(
    upstreams: &[rewrite_config::DnsClassicUpstream],
    hosts: &mut Vec<IpAddr>,
) {
    for upstream in upstreams {
        collect_classic(upstream, hosts);
    }
}

fn collect_classic(upstream: &rewrite_config::DnsClassicUpstream, hosts: &mut Vec<IpAddr>) {
    match &upstream.endpoint {
        DnsClassicEndpoint::Socket(address) => hosts.push(address.ip()),
        DnsClassicEndpoint::Domain { bootstrap, .. } => hosts.push(bootstrap.address.ip()),
    }
}

#[cfg(test)]
mod tests {
    use super::{TUN_MAX_TCP_TASKS, TUN_MAX_UDP_SESSIONS, accept_tun_flow};

    #[test]
    fn tun_flow_caps_match_the_8f_budget() {
        assert_eq!(TUN_MAX_TCP_TASKS, 4096);
        assert_eq!(TUN_MAX_UDP_SESSIONS, 4096);
        assert!(accept_tun_flow(0, TUN_MAX_TCP_TASKS));
        assert!(accept_tun_flow(4095, TUN_MAX_TCP_TASKS));
        assert!(!accept_tun_flow(4096, TUN_MAX_TCP_TASKS));
        assert!(!accept_tun_flow(4096, TUN_MAX_UDP_SESSIONS));
    }
}

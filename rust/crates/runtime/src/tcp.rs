use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rand::RngExt;
use rewrite_config::{
    Config, DnsMode, HostEntry, ListenerKind, LoadBalanceStrategy, Mode, ProxyGroupKind, ProxyKind,
};
use rewrite_inbound::{BoxedInboundStream, InboundCommand, ListenerProtocol};
use rewrite_model::{Destination, Host, Metadata, unmap_ip};
use rewrite_rules::{LazyEvaluation, Route};
use rewrite_state::{ConnectionGuard, RuntimeState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::listener::resolved_route;

#[allow(clippy::too_many_lines)]
pub(super) async fn serve_connection(
    client: BoxedInboundStream,
    kind: ListenerKind,
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
    let protocol = match kind {
        ListenerKind::Http => ListenerProtocol::Http,
        ListenerKind::Socks => ListenerProtocol::Socks,
        ListenerKind::Mixed => ListenerProtocol::Mixed,
    };
    let authentication = if config.skips_inbound_auth(peer.ip()) {
        &[]
    } else {
        config.authentication.as_slice()
    };
    let accepted = tokio::select! {
        () = shutdown.cancelled() => return,
        result = tokio::time::timeout(
            Duration::from_secs(10),
            rewrite_inbound::accept(client, protocol, authentication),
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
    let Some((decision, outbound_target, traversed_groups)) =
        resolve_rematch_target(decision, &mut metadata, config, state)
    else {
        return;
    };
    let route = resolved_route(&outbound_target, config);
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
    if route == Route::Reject {
        return;
    }
    if route == Route::RejectDrop {
        let _client = accepted.client;
        tokio::select! {
            () = shutdown.cancelled() => {}
            () = tokio::time::sleep(Duration::from_mins(1)) => {}
        }
        return;
    }
    let Some(remote) = connect_tcp_outbound(
        &metadata,
        fake_host.as_deref(),
        &decision.target,
        (outbound_target, traversed_groups),
        config,
        state,
        shutdown,
    )
    .await
    else {
        return;
    };
    let client = accepted.client;
    if matches!(remote, TcpOutbound::Dns) {
        relay_dns_tcp(
            client,
            &accepted.preface,
            config,
            state,
            dns_service,
            tracker,
            shutdown,
        )
        .await;
        return;
    }
    let TcpOutbound::Stream(mut remote) = remote else {
        unreachable!("DNS outbound was handled")
    };
    if !accepted.preface.is_empty() && remote.write_all(&accepted.preface).await.is_err() {
        return;
    }

    relay_tracked_tcp(client, remote, tracker, state, shutdown).await;
}

pub(super) enum TcpOutbound {
    Stream(rewrite_outbound::BoxedOutboundStream),
    Dns,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn relay_dns_tcp(
    mut client: BoxedInboundStream,
    preface: &[u8],
    config: &Config,
    state: &RuntimeState,
    dns_service: &rewrite_dns::DnsService,
    tracker: ConnectionGuard,
    shutdown: &CancellationToken,
) {
    let mut pending = preface.to_vec();
    let mut uploaded = 0_u64;
    let mut downloaded = 0_u64;
    loop {
        let mut length = [0_u8; 2];
        let read = read_prefixed_exact(&mut client, &mut pending, &mut length);
        if !tokio::select! {
            () = shutdown.cancelled() => false,
            () = tracker.cancelled() => false,
            result = read => result.is_ok(),
        } {
            break;
        }
        let length = usize::from(u16::from_be_bytes(length));
        if length == 0 {
            break;
        }
        let mut query = vec![0_u8; length];
        if read_prefixed_exact(&mut client, &mut pending, &mut query)
            .await
            .is_err()
        {
            break;
        }
        uploaded = uploaded.saturating_add((length + 2) as u64);
        let response = match dns_service.relay_query(config, state, &query).await {
            Ok(response) => response,
            Err(error) => {
                state.log("error", format!("DNS adapter TCP relay failed: {error}"));
                break;
            }
        };
        let Ok(response_length) = u16::try_from(response.len()) else {
            break;
        };
        if client
            .write_all(&response_length.to_be_bytes())
            .await
            .is_err()
            || client.write_all(&response).await.is_err()
        {
            break;
        }
        downloaded = downloaded.saturating_add((response.len() + 2) as u64);
    }
    tracker.finish(uploaded, downloaded);
}

pub(super) async fn read_prefixed_exact(
    client: &mut BoxedInboundStream,
    pending: &mut Vec<u8>,
    output: &mut [u8],
) -> std::io::Result<()> {
    let copied = pending.len().min(output.len());
    output[..copied].copy_from_slice(&pending[..copied]);
    pending.drain(..copied);
    client.read_exact(&mut output[copied..]).await.map(|_| ())
}

pub(super) async fn connect_tcp_outbound(
    metadata: &Metadata,
    fake_host: Option<&str>,
    target: &str,
    resolved: (String, Vec<String>),
    config: &Config,
    state: &RuntimeState,
    shutdown: &CancellationToken,
) -> Option<TcpOutbound> {
    let (outbound_target, traversed_groups) = resolved;
    let route = resolved_route(&outbound_target, config);
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
            result = rewrite_outbound::connect_with_options(
                &destination,
                config.ipv6,
                direct_tcp_options(config),
            ) => match result {
                Ok(remote) => Some(TcpOutbound::Stream(Box::new(remote))),
                Err(error) => {
                    state.log("error", format!("DIRECT connection failed: {error}"));
                    None
                }
            }
        };
    }
    let attempts = configured_tcp_attempts(config, &outbound_target, &traversed_groups);
    let mut initial_resolution = Some((outbound_target, traversed_groups));
    for attempt in 0..attempts {
        let (outbound_target, traversed_groups) = initial_resolution
            .take()
            .or_else(|| resolve_selector_target(target, metadata, config, state))?;
        if matches!(outbound_target.as_str(), "REJECT" | "REJECT-DROP") {
            return None;
        }
        if outbound_target == "DIRECT" {
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
                result = rewrite_outbound::connect_with_options(
                    &destination,
                    config.ipv6,
                    direct_tcp_options(config),
                ) => match result {
                    Ok(remote) => Some(TcpOutbound::Stream(Box::new(remote))),
                    Err(error) => {
                        state.log("error", format!("DIRECT connection failed: {error}"));
                        None
                    }
                }
            };
        }
        let proxy = configured_proxy(config, &outbound_target)?;
        if proxy.kind == ProxyKind::Reject {
            return None;
        }
        if proxy.kind == ProxyKind::Dns {
            return Some(TcpOutbound::Dns);
        }
        let result = tokio::select! {
            () = shutdown.cancelled() => return None,
            result = connect_configured_proxy(
                proxy,
                &metadata.destination,
                config.ipv6,
                state.clock(),
                &config.trust_certificates,
                config.dns.as_ref(),
                direct_tcp_options(config),
            ) => result,
        };
        match result {
            Ok(remote) => return Some(TcpOutbound::Stream(remote)),
            Err(error) => {
                record_group_proxy_failure(&traversed_groups, config, state, &error);
                state.log("error", error);
            }
        }
        if attempt + 1 < attempts {
            let delay = group_retry_delay(attempt);
            tokio::select! {
                () = shutdown.cancelled() => return None,
                () = tokio::time::sleep(delay) => {}
            }
        }
    }
    None
}

pub(super) fn direct_tcp_options(config: &Config) -> rewrite_outbound::DirectTcpOptions<'_> {
    rewrite_outbound::DirectTcpOptions {
        interface: &config.interface_name,
        routing_mark: config.routing_mark,
        keep_alive_idle: config.keep_alive_idle,
        keep_alive_interval: config.keep_alive_interval,
        disable_keep_alive: config.disable_keep_alive,
        tcp_concurrent: config.tcp_concurrent,
    }
}

pub(super) async fn connect_configured_proxy(
    proxy: &rewrite_config::ProxyConfig,
    destination: &Destination,
    allow_ipv6: bool,
    clock: Arc<rewrite_services::AdjustedClock>,
    custom_roots: &[String],
    dns: Option<&rewrite_config::DnsConfig>,
    socket_options: rewrite_outbound::DirectTcpOptions<'_>,
) -> Result<rewrite_outbound::BoxedOutboundStream, String> {
    let server = Destination {
        host: proxy
            .server
            .parse()
            .map_or_else(|_| Host::Domain(proxy.server.clone()), Host::Ip),
        port: proxy.port,
    };
    match proxy.kind {
        ProxyKind::Direct => {
            rewrite_outbound::connect_with_options(destination, allow_ipv6, socket_options)
                .await
                .map(|stream| Box::new(stream) as rewrite_outbound::BoxedOutboundStream)
                .map_err(|error| format!("DIRECT connection failed: {error}"))
        }
        ProxyKind::Http => {
            let credentials = proxy.http_credentials();
            let tls = proxy.tls.then_some(rewrite_outbound::HttpProxyTls {
                server_name: proxy.sni.as_deref().unwrap_or(&proxy.server),
                verification_name: proxy.name_cert_verify.as_deref(),
                skip_certificate_verification: proxy.skip_cert_verify,
                fingerprint: proxy.fingerprint.as_deref(),
                certificate: proxy.certificate.as_deref(),
                private_key: proxy.private_key.as_deref(),
                custom_roots,
                ech_config: None,
                alpn_protocols: &[],
            });
            rewrite_outbound::connect_http_with_options(
                &server,
                destination,
                allow_ipv6,
                credentials,
                &proxy.headers,
                tls,
                Some(clock),
                socket_options,
            )
            .await
            .map_err(|error| format!("HTTP proxy connection failed: {error}"))
        }
        ProxyKind::Socks5 => {
            let tls = proxy.tls.then_some(rewrite_outbound::HttpProxyTls {
                server_name: &proxy.server,
                verification_name: proxy.name_cert_verify.as_deref(),
                skip_certificate_verification: proxy.skip_cert_verify,
                fingerprint: proxy.fingerprint.as_deref(),
                certificate: proxy.certificate.as_deref(),
                private_key: proxy.private_key.as_deref(),
                custom_roots,
                ech_config: None,
                alpn_protocols: &[],
            });
            rewrite_outbound::connect_socks5_with_options(
                &server,
                destination,
                allow_ipv6,
                proxy.socks5_credentials(),
                tls,
                Some(clock),
                socket_options,
            )
            .await
            .map_err(|error| format!("SOCKS5 proxy connection failed: {error}"))
        }
        ProxyKind::Shadowsocks => {
            connect_shadowsocks_proxy(
                proxy,
                destination,
                allow_ipv6,
                clock,
                custom_roots,
                dns,
                socket_options,
            )
            .await
        }
        ProxyKind::Reject | ProxyKind::Dns | ProxyKind::Rematch => {
            Err("configured proxy is not a TCP dialer".to_owned())
        }
    }
}

async fn connect_shadowsocks_proxy(
    proxy: &rewrite_config::ProxyConfig,
    destination: &Destination,
    allow_ipv6: bool,
    clock: Arc<rewrite_services::AdjustedClock>,
    custom_roots: &[String],
    dns: Option<&rewrite_config::DnsConfig>,
    socket_options: rewrite_outbound::DirectTcpOptions<'_>,
) -> Result<rewrite_outbound::BoxedOutboundStream, String> {
    let server = Destination {
        host: proxy
            .server
            .parse()
            .map_or_else(|_| Host::Domain(proxy.server.clone()), Host::Ip),
        port: proxy.port,
    };
    let resolved_ech = match proxy.shadowsocks_plugin.as_ref() {
        Some(rewrite_model::ShadowsocksPluginConfig::V2rayWebSocket {
            ech: Some(rewrite_model::V2rayEchConfig::Dns { query_server_name }),
            host,
            ..
        }) => {
            let dns = dns.ok_or_else(|| {
                "Shadowsocks v2ray-plugin ECH requires DNS configuration".to_owned()
            })?;
            let query = query_server_name.as_deref().unwrap_or(host);
            Some(
                rewrite_dns::resolve_proxy_ech(dns, query)
                    .await
                    .map_err(|error| format!("v2ray-plugin ECH lookup failed: {error}"))?,
            )
        }
        _ => None,
    };
    let inline_ech = match proxy.shadowsocks_plugin.as_ref() {
        Some(rewrite_model::ShadowsocksPluginConfig::V2rayWebSocket {
            ech: Some(rewrite_model::V2rayEchConfig::Inline(bytes)),
            ..
        }) => Some(bytes.as_slice()),
        _ => None,
    };
    rewrite_outbound::connect_shadowsocks_with_plugin_options(
        &server,
        destination,
        allow_ipv6,
        proxy.password.as_deref().unwrap_or_default(),
        proxy.cipher.as_deref().unwrap_or_default(),
        rewrite_outbound::ShadowsocksTcpOptions {
            socket: socket_options,
            plugin: proxy.shadowsocks_plugin.as_ref(),
            clock: Some(clock),
            custom_roots,
            ech_config: resolved_ech.as_deref().or(inline_ech),
        },
    )
    .await
    .map_err(|error| format!("Shadowsocks proxy connection failed: {error}"))
}

pub(super) fn group_retry_delay(attempt: usize) -> Duration {
    let multiplier = 1_u64 << u32::try_from(attempt.min(7)).unwrap_or(7);
    Duration::from_millis(10_u64.saturating_mul(multiplier).min(1000))
}

pub(super) fn configured_tcp_attempts(
    config: &Config,
    target: &str,
    traversed_groups: &[String],
) -> usize {
    if !traversed_groups.is_empty()
        || configured_proxy(config, target).is_some_and(|proxy| proxy.kind == ProxyKind::Socks5)
    {
        10
    } else {
        1
    }
}

pub(super) fn configured_proxy<'a>(
    config: &'a Config,
    name: &str,
) -> Option<&'a rewrite_config::ProxyConfig> {
    config
        .proxies
        .iter()
        .chain(
            config
                .proxy_providers
                .iter()
                .flat_map(|provider| provider.proxies.iter()),
        )
        .find(|proxy| proxy.name == name)
}

pub(super) fn resolve_rematch_target(
    mut decision: rewrite_rules::Decision,
    metadata: &mut Metadata,
    config: &Config,
    state: &RuntimeState,
) -> Option<(rewrite_rules::Decision, String, Vec<String>)> {
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let (target, traversed_groups) =
            resolve_selector_target(&decision.target, metadata, config, state)?;
        if configured_proxy(config, &target).is_none_or(|proxy| proxy.kind != ProxyKind::Rematch) {
            return Some((decision, target, traversed_groups));
        }
        let rematch = config.rematch(&target)?;
        let key = (
            target,
            metadata.rematch_name.clone(),
            metadata.special_rules.clone(),
        );
        if !seen.insert(key) {
            return None;
        }
        if let Some(name) = &rematch.target_rematch_name {
            name.clone_into(&mut metadata.rematch_name);
        }
        if let Some(sub_rule) = &rematch.target_sub_rule {
            sub_rule.clone_into(&mut metadata.special_rules);
        }
        decision = config.rules.evaluate(metadata);
    }
}

pub(super) fn resolve_selector_target(
    target: &str,
    metadata: &Metadata,
    config: &Config,
    state: &RuntimeState,
) -> Option<(String, Vec<String>)> {
    let mut current = target.to_owned();
    let mut visited = std::collections::BTreeSet::new();
    let mut traversed = Vec::new();
    while let Some(group) = config
        .proxy_groups
        .iter()
        .find(|group| group.name == current)
    {
        if !visited.insert(current.clone()) {
            return None;
        }
        traversed.push(group.name.clone());
        state.touch_proxy_group(&group.name);
        current = match group.kind {
            ProxyGroupKind::Select => state
                .selector_proxy(&group.name)
                .or_else(|| group.proxies.first().cloned())?,
            ProxyGroupKind::Fallback => {
                state.fallback_proxy(&group.name, &group.proxies, &group.test_url)?
            }
            ProxyGroupKind::UrlTest => state.url_test_proxy(
                &group.name,
                &group.proxies,
                &group.test_url,
                group.tolerance,
            )?,
            ProxyGroupKind::LoadBalance => match group
                .load_balance_strategy
                .unwrap_or(LoadBalanceStrategy::ConsistentHashing)
            {
                LoadBalanceStrategy::ConsistentHashing => state.consistent_hash_proxy(
                    &group.proxies,
                    &group.test_url,
                    &load_balance_key(metadata, false),
                )?,
                LoadBalanceStrategy::RoundRobin => {
                    state.round_robin_proxy(&group.name, &group.proxies, &group.test_url)?
                }
                LoadBalanceStrategy::StickySessions => state.sticky_session_proxy(
                    &group.name,
                    &group.proxies,
                    &group.test_url,
                    &load_balance_key(metadata, true),
                )?,
            },
        };
    }
    if let Some(provider) = config
        .proxy_providers
        .iter()
        .find(|provider| provider.proxies.iter().any(|proxy| proxy.name == current))
    {
        state.touch_proxy_group(&format!("provider:{}", provider.name));
    }
    Some((current, traversed))
}

pub(super) fn record_group_proxy_failure(
    groups: &[String],
    config: &Config,
    state: &RuntimeState,
    error: &str,
) {
    let connection_refused = error.to_ascii_lowercase().contains("connection refused");
    for name in groups {
        let Some(group) = config.proxy_groups.iter().find(|group| group.name == *name) else {
            continue;
        };
        state.record_group_dial_failure(
            name,
            Duration::from_millis(group.health.timeout),
            group.health.max_failed_times,
            connection_refused,
        );
    }
}

pub(super) fn load_balance_key(metadata: &Metadata, include_source: bool) -> String {
    let destination = if metadata.host.is_empty() {
        metadata.destination_ip.map(|address| address.to_string())
    } else if metadata.host.parse::<IpAddr>().is_ok() {
        Some(metadata.host.clone())
    } else {
        psl::domain(metadata.host.as_bytes())
            .map(|domain| String::from_utf8_lossy(domain.as_bytes()).into_owned())
    }
    .unwrap_or_default();
    if include_source {
        format!(
            "{}{}",
            metadata
                .source_ip
                .map_or_else(String::new, |address| address.to_string()),
            destination
        )
    } else {
        destination
    }
}

pub(super) async fn relay_tracked_tcp(
    mut client: BoxedInboundStream,
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

pub(super) async fn evaluate_tcp_rules(
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

pub(super) fn mode_decision(
    config: &Config,
    state: &RuntimeState,
) -> Option<rewrite_rules::Decision> {
    let target = match config.mode {
        Mode::Rule => return None,
        Mode::Direct => "DIRECT".to_owned(),
        Mode::Global if config.has_custom_global_group() => "GLOBAL".to_owned(),
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

pub(super) async fn resolve_direct_destination(
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

pub(super) async fn resolve_rule_destination(
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

pub(super) fn apply_host_mapping(
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
                    && let Some(host) =
                        state.lookup_fake_ip(network, address, config.profile.store_fake_ip)
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

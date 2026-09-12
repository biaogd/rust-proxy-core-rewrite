use std::collections::BTreeMap;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use rewrite_config::{Config, ConfigError, ListenerKind, ProxyGroupKind, ShadowsocksInboundConfig};
use rewrite_state::RuntimeState;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::listener::run_listener;
use crate::services::hydrate_http_proxy_providers;
use crate::shadowsocks_listener::{ShadowsocksListener, run_shadowsocks_listener};
use crate::tun::run_tun_listener;
use crate::types::{
    ControllerKey, ListenerKey, LocalTcpListener, PreparedController, RuntimeError, RuntimeTask,
};

#[derive(Default)]
struct PreparedGeneration {
    listeners: Vec<(ListenerKey, LocalTcpListener, Option<Arc<UdpSocket>>)>,
    shadowsocks: Vec<(ListenerKey, ShadowsocksListener)>,
    controllers: Vec<PreparedController>,
    dns: Option<(SocketAddr, TcpListener, UdpSocket)>,
    retired_listeners: Vec<ListenerKey>,
    retired_controllers: Vec<ControllerKey>,
    previous_published: Option<Arc<Config>>,
    published: bool,
}

impl PreparedGeneration {
    fn release_uncommitted(&mut self) {
        self.listeners.clear();
        self.shadowsocks.clear();
        self.controllers.clear();
        self.dns = None;
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub(super) async fn apply_generation(
    next: Config,
    config_sender: &watch::Sender<Arc<Config>>,
    config_receiver: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    controller_updates: &mpsc::Sender<rewrite_controller::ConfigUpdate>,
    listeners: &mut BTreeMap<ListenerKey, RuntimeTask>,
    controllers: &mut BTreeMap<ControllerKey, RuntimeTask>,
    dns: &mut Option<(SocketAddr, RuntimeTask)>,
    tun: &mut Option<(rewrite_config::TunConfig, RuntimeTask)>,
) -> Result<(), RuntimeError> {
    let mut prepared = PreparedGeneration {
        previous_published: Some(Arc::clone(&*config_sender.borrow())),
        ..PreparedGeneration::default()
    };
    let result = apply_generation_inner(
        next,
        config_sender,
        config_receiver,
        state,
        dns_service,
        controller_updates,
        listeners,
        controllers,
        dns,
        tun,
        &mut prepared,
    )
    .await;
    if let Err(error) = &result
        && let Err(restore_error) = rollback_uncommitted_generation(
            config_sender,
            config_receiver,
            state,
            dns_service,
            controller_updates,
            listeners,
            controllers,
            &mut prepared,
        )
        .await
    {
        return Err(RuntimeError::Tun(format!(
            "{error}; failed to restore previous listeners ({restore_error})"
        )));
    }
    result
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn apply_generation_inner(
    mut next: Config,
    config_sender: &watch::Sender<Arc<Config>>,
    config_receiver: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    controller_updates: &mpsc::Sender<rewrite_controller::ConfigUpdate>,
    listeners: &mut BTreeMap<ListenerKey, RuntimeTask>,
    controllers: &mut BTreeMap<ControllerKey, RuntimeTask>,
    dns: &mut Option<(SocketAddr, RuntimeTask)>,
    tun: &mut Option<(rewrite_config::TunConfig, RuntimeTask)>,
    prepared: &mut PreparedGeneration,
) -> Result<(), RuntimeError> {
    hydrate_http_proxy_providers(&mut next, state).await;
    let desired_listeners = next.listener_ports()?;
    let desired_controllers = controller_keys(&next)?;
    let desired_dns = next.dns.as_ref().map(|config| config.listen);

    let desired_listener_keys = desired_listeners
        .iter()
        .map(|&(kind, port)| {
            if kind == ListenerKind::Shadowsocks {
                let address = next.shadowsocks_listen_address(port)?;
                let identity = next
                    .shadowsocks_listener_for_port(port)
                    .map_or_else(String::new, ShadowsocksInboundConfig::reload_identity);
                Ok((kind, port, address, identity))
            } else {
                next.listener_address(port)
                    .map(|address| (kind, port, address, String::new()))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (kind, port, address, identity) in &desired_listener_keys {
        let kind = *kind;
        let port = *port;
        let address = *address;
        let key = (kind, port, address, identity.clone());
        if listeners.contains_key(&key) {
            continue;
        }

        // A wildcard/specific-address change on the same port cannot be
        // prepared while the old socket owns that port. Go closes this fixed
        // listener before recreating it, so mirror that boundary here.
        // Shadowsocks also rebinds when cipher/password/plugin identity changes.
        let conflicting = listeners
            .keys()
            .find(|(current_kind, current_port, _, _)| {
                *current_kind == kind && *current_port == port
            })
            .cloned();
        if let Some(conflicting) = conflicting
            && let Some(task) = listeners.remove(&conflicting)
        {
            stop_task(task).await;
            prepared.retired_listeners.push(conflicting);
        }

        if kind == ListenerKind::Shadowsocks {
            let Some(shadowsocks) = next.shadowsocks_listener_for_port(port) else {
                continue;
            };
            let listener = ShadowsocksListener::bind(shadowsocks).await?;
            prepared.shadowsocks.push((key, listener));
            continue;
        }

        let (listener, udp) = bind_fixed_listener(&next, kind, address)?;
        prepared.listeners.push((key, listener, udp));
    }
    for key in &desired_controllers {
        if controllers.contains_key(key) {
            continue;
        }
        let replaced = controllers
            .keys()
            .find(|current| {
                same_controller_kind(current, key) && same_controller_bind_target(current, key)
            })
            .cloned();
        if let Some(replaced) = replaced
            && let Some(task) = controllers.remove(&replaced)
        {
            stop_task(task).await;
            cleanup_controller_key(&replaced);
            prepared.retired_controllers.push(replaced);
        }
        match prepare_controller(key.clone(), state.clock()) {
            Ok(controller) => prepared.controllers.push(controller),
            Err(error) => {
                state.log("error", format!("controller listen failed: {error}"));
                eprintln!("controller listen failed: {error}");
            }
        }
    }
    if desired_dns
        .is_some_and(|address| dns.as_ref().is_none_or(|(current, _)| *current != address))
    {
        let address = desired_dns.expect("checked as present");
        prepared.dns = Some((
            address,
            TcpListener::bind(address).await?,
            UdpSocket::bind(address).await?,
        ));
    }

    sync_selector_state(state, &next);
    state.clear_grpc_clients().await;
    state.clear_xhttp_clients().await;
    state.clear_anytls_clients().await;
    state.clear_ssr_clients();
    state.clear_hysteria2_clients().await;
    state.clear_tuic_clients().await;
    state.clear_wireguard_clients().await;
    let previous_published = prepared
        .previous_published
        .clone()
        .unwrap_or_else(|| Arc::clone(&*config_sender.borrow()));
    let desired_tun = next.tun.clone();
    config_sender.send_replace(Arc::new(next));
    prepared.published = true;
    dns_service.clear_cache().await;
    dns_service.reset_connections().await;

    apply_tun_task(
        desired_tun,
        previous_published,
        config_sender,
        config_receiver,
        state,
        dns_service,
        tun,
    )
    .await?;

    for (key, listener, udp) in std::mem::take(&mut prepared.listeners) {
        spawn_fixed_listener(
            key,
            listener,
            udp,
            config_receiver,
            state,
            dns_service,
            listeners,
        );
    }

    for (key, listener) in std::mem::take(&mut prepared.shadowsocks) {
        spawn_shadowsocks_listener(
            key,
            listener,
            config_receiver,
            state,
            dns_service,
            listeners,
        );
    }

    apply_controller_tasks(
        std::mem::take(&mut prepared.controllers),
        &desired_controllers,
        config_receiver,
        state,
        dns_service,
        controller_updates,
        controllers,
    )
    .await;

    apply_dns_task(
        prepared.dns.take(),
        desired_dns,
        config_receiver,
        state,
        dns_service,
        dns,
    )
    .await;

    let desired = desired_listener_keys;
    let obsolete: Vec<_> = listeners
        .keys()
        .filter(|key| !desired.contains(key))
        .cloned()
        .collect();
    for key in obsolete {
        if let Some(task) = listeners.remove(&key) {
            stop_task(task).await;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn rollback_uncommitted_generation(
    config_sender: &watch::Sender<Arc<Config>>,
    config_receiver: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    controller_updates: &mpsc::Sender<rewrite_controller::ConfigUpdate>,
    listeners: &mut BTreeMap<ListenerKey, RuntimeTask>,
    controllers: &mut BTreeMap<ControllerKey, RuntimeTask>,
    prepared: &mut PreparedGeneration,
) -> Result<(), RuntimeError> {
    // Drop replacement sockets first. Same-port rebinds (address or SS
    // identity) still hold the port until these values are released.
    prepared.release_uncommitted();
    let Some(previous) = prepared.previous_published.clone() else {
        return Ok(());
    };
    if prepared.published {
        config_sender.send_replace(Arc::clone(&previous));
        sync_selector_state(state, previous.as_ref());
    }
    restore_retired_sockets(
        std::mem::take(&mut prepared.retired_listeners),
        std::mem::take(&mut prepared.retired_controllers),
        previous.as_ref(),
        config_receiver,
        state,
        dns_service,
        controller_updates,
        listeners,
        controllers,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn restore_retired_sockets(
    retired_listeners: Vec<ListenerKey>,
    retired_controllers: Vec<ControllerKey>,
    previous: &Config,
    config_receiver: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    controller_updates: &mpsc::Sender<rewrite_controller::ConfigUpdate>,
    listeners: &mut BTreeMap<ListenerKey, RuntimeTask>,
    controllers: &mut BTreeMap<ControllerKey, RuntimeTask>,
) -> Result<(), RuntimeError> {
    for key in retired_listeners {
        if listeners.contains_key(&key) {
            continue;
        }
        let (kind, port, address, _identity) = key.clone();
        if kind == ListenerKind::Shadowsocks {
            let Some(shadowsocks) = previous.shadowsocks_listener_for_port(port) else {
                continue;
            };
            let listener = ShadowsocksListener::bind(shadowsocks).await?;
            spawn_shadowsocks_listener(
                key,
                listener,
                config_receiver,
                state,
                dns_service,
                listeners,
            );
            continue;
        }
        let (listener, udp) = bind_fixed_listener(previous, kind, address)?;
        spawn_fixed_listener(
            key,
            listener,
            udp,
            config_receiver,
            state,
            dns_service,
            listeners,
        );
    }
    let mut prepared_controllers = Vec::new();
    let mut desired: Vec<_> = controllers.keys().cloned().collect();
    for key in retired_controllers {
        if controllers.contains_key(&key) || desired.contains(&key) {
            continue;
        }
        desired.push(key.clone());
        prepared_controllers.push(prepare_controller(key, state.clock())?);
    }
    apply_controller_tasks(
        prepared_controllers,
        &desired,
        config_receiver,
        state,
        dns_service,
        controller_updates,
        controllers,
    )
    .await;
    Ok(())
}

fn bind_fixed_listener(
    config: &Config,
    kind: ListenerKind,
    address: SocketAddr,
) -> Result<(LocalTcpListener, Option<Arc<UdpSocket>>), RuntimeError> {
    let dual_stack = config.allow_lan && config.bind_address == "*";
    let listener = rewrite_platform::bind_local_tcp_listener(
        address,
        rewrite_platform::LocalTcpOptions {
            dual_stack,
            multipath: config.inbound_mptcp,
            keep_alive_idle: config.keep_alive_idle,
            keep_alive_interval: config.keep_alive_interval,
            disable_keep_alive: config.disable_keep_alive,
        },
    )?;
    let listener = if config.inbound_tfo {
        LocalTcpListener::FastOpen(tokio_tfo::TfoListener::from_std(listener)?)
    } else {
        LocalTcpListener::Plain(TcpListener::from_std(listener)?)
    };
    let udp = if matches!(kind, ListenerKind::Socks | ListenerKind::Mixed) {
        let udp = rewrite_platform::bind_local_udp_socket(address, dual_stack)?;
        Some(Arc::new(UdpSocket::from_std(udp)?))
    } else {
        None
    };
    Ok((listener, udp))
}

fn spawn_fixed_listener(
    key: ListenerKey,
    listener: LocalTcpListener,
    udp: Option<Arc<UdpSocket>>,
    config_receiver: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    listeners: &mut BTreeMap<ListenerKey, RuntimeTask>,
) {
    let task_shutdown = CancellationToken::new();
    let child_shutdown = task_shutdown.clone();
    let task_config = config_receiver.clone();
    let task_state = Arc::clone(state);
    let task_dns_service = Arc::clone(dns_service);
    let kind = key.0;
    let handle = tokio::spawn(async move {
        run_listener(
            kind,
            listener,
            udp,
            task_config,
            task_state,
            task_dns_service,
            child_shutdown,
        )
        .await;
    });
    listeners.insert(
        key,
        RuntimeTask {
            shutdown: task_shutdown,
            handle,
        },
    );
}

fn spawn_shadowsocks_listener(
    key: ListenerKey,
    listener: ShadowsocksListener,
    config_receiver: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    listeners: &mut BTreeMap<ListenerKey, RuntimeTask>,
) {
    let task_shutdown = CancellationToken::new();
    let child_shutdown = task_shutdown.clone();
    let task_config = config_receiver.clone();
    let task_state = Arc::clone(state);
    let task_dns_service = Arc::clone(dns_service);
    let handle = tokio::spawn(async move {
        run_shadowsocks_listener(
            listener,
            task_config,
            task_state,
            task_dns_service,
            child_shutdown,
        )
        .await;
    });
    listeners.insert(
        key,
        RuntimeTask {
            shutdown: task_shutdown,
            handle,
        },
    );
}

async fn apply_tun_task(
    desired: Option<rewrite_config::TunConfig>,
    previous_published: Arc<Config>,
    config_sender: &watch::Sender<Arc<Config>>,
    config_receiver: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    tun: &mut Option<(rewrite_config::TunConfig, RuntimeTask)>,
) -> Result<(), RuntimeError> {
    let enable = desired.as_ref().is_some_and(|config| config.enable);
    let previous = tun.take();
    let rollback_config = previous.as_ref().map(|(config, _)| config.clone());
    if let Some((_, task)) = previous {
        stop_task(task).await;
    }
    if !enable {
        return Ok(());
    }
    let Some(tun_config) = desired else {
        return Ok(());
    };
    match start_tun_task(tun_config.clone(), config_receiver, state, dns_service).await {
        Ok(task) => {
            *tun = Some((tun_config, task));
            Ok(())
        }
        Err(error) => {
            config_sender.send_replace(previous_published);
            if let Some(previous_config) = rollback_config {
                match start_tun_task(previous_config.clone(), config_receiver, state, dns_service)
                    .await
                {
                    Ok(task) => {
                        *tun = Some((previous_config, task));
                        Err(RuntimeError::Tun(format!(
                            "failed to reload TUN ({error}); restored previous instance"
                        )))
                    }
                    Err(restore_error) => Err(RuntimeError::Tun(format!(
                        "failed to reload TUN ({error}); failed to restore previous instance ({restore_error})"
                    ))),
                }
            } else {
                Err(error)
            }
        }
    }
}

async fn start_tun_task(
    tun_config: rewrite_config::TunConfig,
    config_receiver: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
) -> Result<RuntimeTask, RuntimeError> {
    let task_config = config_receiver.clone();
    let task_state = Arc::clone(state);
    let task_dns = Arc::clone(dns_service);
    let task_shutdown = CancellationToken::new();
    let child_shutdown = task_shutdown.child_token();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        if let Err(error) = run_tun_listener(
            tun_config,
            task_config,
            task_state.clone(),
            task_dns,
            child_shutdown,
            Some(ready_tx),
        )
        .await
        {
            task_state.log("error", format!("TUN listener failed: {error}"));
        }
    });
    match ready_rx.await {
        Ok(Ok(())) => Ok(RuntimeTask {
            shutdown: task_shutdown,
            handle,
        }),
        Ok(Err(error)) => {
            task_shutdown.cancel();
            let _ = handle.await;
            Err(error)
        }
        Err(_) => {
            task_shutdown.cancel();
            let _ = handle.await;
            Err(RuntimeError::Tun(
                "TUN startup cancelled before becoming ready".to_owned(),
            ))
        }
    }
}

pub(super) fn controller_keys(config: &Config) -> Result<Vec<ControllerKey>, ConfigError> {
    let mut keys = Vec::new();
    let ui_path = config.external_ui_path();
    if let Some(address) = config.controller_tcp_addr()? {
        keys.push(ControllerKey::Tcp(
            address,
            config.external_controller_routing_mark,
            ui_path.clone(),
        ));
    }
    if let Some(address) = config.controller_tls_addr()? {
        keys.push(ControllerKey::Tls(
            address,
            config.external_controller_routing_mark,
            config.controller_tls.clone(),
            ui_path.clone(),
        ));
    }
    #[cfg(unix)]
    if let Some(path) = config.controller_unix_path() {
        keys.push(ControllerKey::Unix(path, ui_path.clone()));
    }
    #[cfg(windows)]
    if !config.external_controller_pipe.is_empty() {
        keys.push(ControllerKey::Pipe(
            config.external_controller_pipe.clone(),
            ui_path,
        ));
    }
    Ok(keys)
}

pub(super) fn same_controller_kind(left: &ControllerKey, right: &ControllerKey) -> bool {
    match (left, right) {
        (ControllerKey::Tcp(..), ControllerKey::Tcp(..))
        | (ControllerKey::Tls(..), ControllerKey::Tls(..)) => true,
        #[cfg(unix)]
        (ControllerKey::Unix(..), ControllerKey::Unix(..)) => true,
        #[cfg(windows)]
        (ControllerKey::Pipe(..), ControllerKey::Pipe(..)) => true,
        _ => false,
    }
}

fn same_controller_bind_target(left: &ControllerKey, right: &ControllerKey) -> bool {
    match (left, right) {
        (ControllerKey::Tcp(left, ..), ControllerKey::Tcp(right, ..))
        | (ControllerKey::Tls(left, ..), ControllerKey::Tls(right, ..)) => left == right,
        #[cfg(unix)]
        (ControllerKey::Unix(left, ..), ControllerKey::Unix(right, ..)) => left == right,
        #[cfg(windows)]
        (ControllerKey::Pipe(left, ..), ControllerKey::Pipe(right, ..)) => left == right,
        _ => false,
    }
}

pub(super) fn prepare_controller(
    key: ControllerKey,
    clock: Arc<rewrite_services::AdjustedClock>,
) -> Result<PreparedController, RuntimeError> {
    match key {
        ControllerKey::Tcp(address, mark, ui_path) => {
            let key = ControllerKey::Tcp(address, mark, ui_path);
            let listener = rewrite_platform::bind_marked_tcp_listener(address, mark)?;
            Ok(PreparedController::Tcp(
                key,
                TcpListener::from_std(listener)?,
            ))
        }
        ControllerKey::Tls(address, mark, tls, ui_path) => {
            let prepared_tls = rewrite_controller::prepare_tls_config(&tls, clock)?;
            let listener =
                TcpListener::from_std(rewrite_platform::bind_marked_tcp_listener(address, mark)?)?;
            Ok(PreparedController::Tls(
                ControllerKey::Tls(address, mark, tls, ui_path),
                listener,
                Box::new(prepared_tls),
            ))
        }
        #[cfg(unix)]
        ControllerKey::Unix(path, ui_path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            let listener = tokio::net::UnixListener::bind(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
            Ok(PreparedController::Unix(
                ControllerKey::Unix(path, ui_path),
                listener,
            ))
        }
        #[cfg(windows)]
        ControllerKey::Pipe(name, ui_path) => {
            let listener = rewrite_controller::prepare_named_pipe(&name)?;
            Ok(PreparedController::Pipe(
                ControllerKey::Pipe(name, ui_path),
                listener,
            ))
        }
    }
}

pub(super) fn sync_selector_state(state: &RuntimeState, config: &Config) {
    if !config.has_custom_global_group() {
        state.sync_global_proxy(&config.default_global_proxies());
    }
    state.retain_proxy_groups(config.proxy_groups.iter().map(|group| group.name.as_str()));
    state.sync_group_choices(
        config
            .proxy_groups
            .iter()
            .filter(|group| group.kind != ProxyGroupKind::LoadBalance)
            .map(|group| {
                (
                    group.name.as_str(),
                    group.proxies.as_slice(),
                    group.default_selected.as_deref(),
                    group.kind != ProxyGroupKind::Select,
                )
            }),
        config.profile.store_selected,
    );
    let mut health_names = vec!["DIRECT", "REJECT"];
    health_names.extend(config.proxies.iter().map(|proxy| proxy.name.as_str()));
    health_names.extend(
        config
            .proxy_providers
            .iter()
            .flat_map(|provider| provider.proxies.iter().map(|proxy| proxy.name.as_str())),
    );
    health_names.extend(config.proxy_groups.iter().map(|group| group.name.as_str()));
    state.retain_proxy_health(health_names);
}

pub(super) async fn apply_controller_tasks(
    prepared: Vec<PreparedController>,
    desired: &[ControllerKey],
    config: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    config_updates: &mpsc::Sender<rewrite_controller::ConfigUpdate>,
    current: &mut BTreeMap<ControllerKey, RuntimeTask>,
) {
    for prepared in prepared {
        let task_shutdown = CancellationToken::new();
        let child_shutdown = task_shutdown.clone();
        let task_config = config.clone();
        let task_state = Arc::clone(state);
        let task_dns_service = Arc::clone(dns_service);
        let task_config_updates = config_updates.clone();
        let (key, handle) = match prepared {
            PreparedController::Tcp(key, listener) => {
                let handle = tokio::spawn(rewrite_controller::serve_tcp(
                    listener,
                    task_dns_service,
                    task_config,
                    task_state,
                    task_config_updates,
                    child_shutdown,
                    true,
                ));
                (key, handle)
            }
            PreparedController::Tls(key, listener, tls) => {
                let handle = tokio::spawn(rewrite_controller::serve_tls(
                    listener,
                    task_dns_service,
                    task_config,
                    task_state,
                    task_config_updates,
                    child_shutdown,
                    *tls,
                ));
                (key, handle)
            }
            #[cfg(unix)]
            PreparedController::Unix(key, listener) => {
                let handle = tokio::spawn(rewrite_controller::serve_unix(
                    listener,
                    task_dns_service,
                    task_config,
                    task_state,
                    task_config_updates,
                    child_shutdown,
                ));
                (key, handle)
            }
            #[cfg(windows)]
            PreparedController::Pipe(key, listener) => {
                let ControllerKey::Pipe(name, ..) = &key else {
                    unreachable!("pipe preparation has a pipe key")
                };
                let handle = tokio::spawn(rewrite_controller::serve_named_pipe(
                    listener,
                    name.clone(),
                    task_dns_service,
                    task_config,
                    task_state,
                    task_config_updates,
                    child_shutdown,
                ));
                (key, handle)
            }
        };
        current.insert(
            key,
            RuntimeTask {
                shutdown: task_shutdown,
                handle,
            },
        );
    }
    let obsolete = current
        .keys()
        .filter(|key| !desired.contains(key))
        .cloned()
        .collect::<Vec<_>>();
    for key in obsolete {
        if let Some(previous) = current.remove(&key) {
            stop_task(previous).await;
            cleanup_controller_key(&key);
        }
    }
}

pub(super) fn cleanup_controller_key(key: &ControllerKey) {
    #[cfg(unix)]
    if let ControllerKey::Unix(path, ..) = key {
        let _ = std::fs::remove_file(path);
    }
    #[cfg(not(unix))]
    let _ = key;
}

pub(super) async fn apply_dns_task(
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

pub(super) async fn stop_task(task: RuntimeTask) {
    task.shutdown.cancel();
    let mut handle = task.handle;
    if tokio::time::timeout(Duration::from_secs(3), &mut handle)
        .await
        .is_err()
    {
        eprintln!("runtime generation shutdown deadline exceeded");
        handle.abort();
        let _ = handle.await;
    }
}

#[cfg(unix)]
use super::PermissionsExt;
use super::{
    Arc, BTreeMap, CancellationToken, Config, ConfigError, ControllerKey, Duration, ListenerKey,
    ListenerKind, LocalTcpListener, PreparedController, ProxyGroupKind, RuntimeError, RuntimeState,
    RuntimeTask, SocketAddr, TcpListener, UdpSocket, hydrate_http_proxy_providers, mpsc,
    run_listener, watch,
};

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub(super) async fn apply_generation(
    mut next: Config,
    config_sender: &watch::Sender<Arc<Config>>,
    config_receiver: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    controller_updates: &mpsc::Sender<rewrite_controller::ConfigUpdate>,
    listeners: &mut BTreeMap<ListenerKey, RuntimeTask>,
    controllers: &mut BTreeMap<ControllerKey, RuntimeTask>,
    dns: &mut Option<(SocketAddr, RuntimeTask)>,
) -> Result<(), RuntimeError> {
    hydrate_http_proxy_providers(&mut next, state).await;
    let desired_listeners = next.listener_ports()?;
    let desired_controllers = controller_keys(&next)?;
    let desired_dns = next.dns.as_ref().map(|config| config.listen);

    let mut prepared_listeners = Vec::new();
    let desired_listener_keys = desired_listeners
        .iter()
        .map(|&(kind, port)| {
            next.listener_address(port)
                .map(|address| (kind, port, address))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for &(kind, port, address) in &desired_listener_keys {
        let key = (kind, port, address);
        if listeners.contains_key(&key) {
            continue;
        }

        // A wildcard/specific-address change on the same port cannot be
        // prepared while the old socket owns that port. Go closes this fixed
        // listener before recreating it, so mirror that boundary here.
        let conflicting = listeners
            .keys()
            .find(|(current_kind, current_port, _)| *current_kind == kind && *current_port == port)
            .copied();
        if let Some(conflicting) = conflicting
            && let Some(task) = listeners.remove(&conflicting)
        {
            stop_task(task).await;
        }

        let dual_stack = next.allow_lan && next.bind_address == "*";
        let listener = rewrite_platform::bind_local_tcp_listener(
            address,
            rewrite_platform::LocalTcpOptions {
                dual_stack,
                multipath: next.inbound_mptcp,
                keep_alive_idle: next.keep_alive_idle,
                keep_alive_interval: next.keep_alive_interval,
                disable_keep_alive: next.disable_keep_alive,
            },
        )?;
        let listener = if next.inbound_tfo {
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
        prepared_listeners.push((key, listener, udp));
    }
    let mut prepared_controllers = Vec::new();
    for key in &desired_controllers {
        if controllers.contains_key(key) {
            continue;
        }
        let replaced = controllers
            .keys()
            .find(|current| same_controller_kind(current, key))
            .cloned();
        if let Some(replaced) = replaced
            && let Some(task) = controllers.remove(&replaced)
        {
            stop_task(task).await;
            cleanup_controller_key(&replaced);
        }
        match prepare_controller(key.clone(), state.clock()) {
            Ok(prepared) => prepared_controllers.push(prepared),
            Err(error) => {
                state.log("error", format!("controller listen failed: {error}"));
                eprintln!("controller listen failed: {error}");
            }
        }
    }
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

    sync_selector_state(state, &next);
    config_sender.send_replace(Arc::new(next));
    dns_service.clear_cache().await;
    dns_service.reset_connections().await;

    for ((kind, port, address), listener, udp) in prepared_listeners {
        let task_shutdown = CancellationToken::new();
        let child_shutdown = task_shutdown.clone();
        let task_config = config_receiver.clone();
        let task_state = Arc::clone(state);
        let task_dns_service = Arc::clone(dns_service);
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
            (kind, port, address),
            RuntimeTask {
                shutdown: task_shutdown,
                handle,
            },
        );
    }

    apply_controller_tasks(
        prepared_controllers,
        &desired_controllers,
        config_receiver,
        state,
        dns_service,
        controller_updates,
        controllers,
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

    let desired = desired_listener_keys;
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

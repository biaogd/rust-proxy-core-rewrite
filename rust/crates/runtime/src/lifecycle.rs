use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use rewrite_config::{Config, ProxyProviderVehicle};
use rewrite_state::RuntimeState;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::generation::{apply_generation, cleanup_controller_key, stop_task};
use crate::services::{
    refresh_http_proxy_provider, refresh_rule_provider, start_file_provider_watcher,
    start_geo_updater, start_group_health_scheduler, start_http_provider_scheduler,
    start_ntp_service, start_provider_health_scheduler, start_ui_updater,
};
use crate::types::{ControllerKey, LifecycleSignals, ListenerKey, RuntimeError, RuntimeTask};

/// Runs a fixed configuration until cancellation.
///
/// # Errors
///
/// Returns [`RuntimeError`] if a declared port/address is invalid or a local
/// listener cannot be bound.
pub async fn run(config: Config, shutdown: CancellationToken) -> Result<(), RuntimeError> {
    let (_reload_sender, reloads) = mpsc::channel(1);
    Box::pin(run_with_reload(config, reloads, shutdown)).await
}

/// Runs transactional local listener generations and applies validated reloads.
///
/// A reload binds every non-conflicting socket before publishing its config.
/// A same-port bind-address change must retire the old socket first, matching
/// the Go fixed-listener recreation boundary. Other bind failures leave the
/// previous generation running.
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

#[allow(clippy::too_many_lines)]
pub(super) async fn run_with_reload_inner(
    initial: Config,
    mut reloads: mpsc::Receiver<Config>,
    shutdown: CancellationToken,
    lifecycle: Option<LifecycleSignals>,
) -> Result<(), RuntimeError> {
    let state = Arc::new(RuntimeState::default());
    state.enable_storage_persistence();
    let dns_service = Arc::new(rewrite_dns::DnsService::new());
    let (config_sender, config_receiver) = watch::channel(Arc::new(initial.clone()));
    let (controller_update_sender, mut controller_updates) = mpsc::channel(4);
    let mut listeners = BTreeMap::new();
    let mut controllers = BTreeMap::new();
    let mut dns: Option<(SocketAddr, RuntimeTask)> = None;

    apply_generation(
        initial,
        &config_sender,
        &config_receiver,
        &state,
        &dns_service,
        &controller_update_sender,
        &mut listeners,
        &mut controllers,
        &mut dns,
    )
    .await?;
    let health = start_group_health_scheduler(config_receiver.clone(), Arc::clone(&state));
    let provider_health =
        start_provider_health_scheduler(config_receiver.clone(), Arc::clone(&state));
    let providers =
        start_http_provider_scheduler(config_receiver.clone(), controller_update_sender.clone());
    let provider_files =
        start_file_provider_watcher(config_receiver.clone(), controller_update_sender.clone())
            .await;
    let ntp = start_ntp_service(config_receiver.clone(), Arc::clone(&state));
    let ui_updater = start_ui_updater(config_receiver.clone(), Arc::clone(&state));
    let geo_updater = start_geo_updater(config_receiver.clone(), Arc::clone(&state));
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
    let mut restart_requested = false;

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
                    &mut controllers,
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
                if apply_controller_update(
                    update,
                    &config_sender,
                    &config_receiver,
                    &state,
                    &dns_service,
                    &controller_update_sender,
                    &mut listeners,
                    &mut controllers,
                    &mut dns,
                ).await {
                    restart_requested = true;
                    break;
                }
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
    for (key, task) in controllers {
        stop_task(task).await;
        cleanup_controller_key(&key);
    }
    if let Some((_, task)) = dns {
        stop_task(task).await;
    }
    stop_task(health).await;
    stop_task(provider_health).await;
    stop_task(providers).await;
    stop_task(provider_files).await;
    stop_task(ntp).await;
    stop_task(ui_updater).await;
    stop_task(geo_updater).await;
    if restart_requested {
        restart_current_process();
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_controller_update(
    update: rewrite_controller::ConfigUpdate,
    config_sender: &watch::Sender<Arc<Config>>,
    config_receiver: &watch::Receiver<Arc<Config>>,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    controller_update_sender: &mpsc::Sender<rewrite_controller::ConfigUpdate>,
    listeners: &mut BTreeMap<ListenerKey, RuntimeTask>,
    controllers: &mut BTreeMap<ControllerKey, RuntimeTask>,
    dns: &mut Option<(SocketAddr, RuntimeTask)>,
) -> bool {
    if matches!(&update.kind, rewrite_controller::ConfigUpdateKind::Restart) {
        let _ = update.completion.send(Ok(()));
        return true;
    }
    let next = match update.kind {
        rewrite_controller::ConfigUpdateKind::Replace(config) => Ok(*config),
        rewrite_controller::ConfigUpdateKind::RefreshProxyProvider(name) => {
            let mut config = config_receiver.borrow().as_ref().clone();
            let provider = config
                .proxy_providers
                .iter()
                .find(|provider| provider.name == name);
            if provider.is_some_and(|provider| provider.vehicle == ProxyProviderVehicle::Http) {
                refresh_http_proxy_provider(&mut config, &name)
                    .await
                    .map(|()| config)
            } else {
                config
                    .reload_proxy_provider(&name)
                    .map_err(|error| error.to_string())
            }
        }
        rewrite_controller::ConfigUpdateKind::RefreshRuleProvider(name) => {
            let mut config = config_receiver.borrow().as_ref().clone();
            refresh_rule_provider(&mut config, &name)
                .await
                .map(|()| config)
        }
        rewrite_controller::ConfigUpdateKind::Restart => unreachable!("handled above"),
    };
    let result = match next {
        Ok(next) => apply_generation(
            next,
            config_sender,
            config_receiver,
            state,
            dns_service,
            controller_update_sender,
            listeners,
            controllers,
            dns,
        )
        .await
        .map_err(|error| error.to_string()),
        Err(error) => Err(error),
    };
    if let Err(error) = &result {
        state.log(
            "error",
            format!("controller configuration update failed: {error}"),
        );
    } else {
        state.log("info", "controller configuration updated");
    }
    let _ = update.completion.send(result);
    false
}

#[cfg(unix)]
pub(super) fn restart_current_process() {
    use std::os::unix::process::CommandExt;
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let error = std::process::Command::new(executable)
        .args(std::env::args_os().skip(1))
        .exec();
    eprintln!("restarting: {error}");
}

#[cfg(windows)]
pub(super) fn restart_current_process() {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    if let Err(error) = std::process::Command::new(executable)
        .args(std::env::args_os().skip(1))
        .spawn()
    {
        eprintln!("restarting: {error}");
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn restart_current_process() {}

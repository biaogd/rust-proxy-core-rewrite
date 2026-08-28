use std::collections::BTreeMap;
use std::future::pending;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures_util::StreamExt;
use notify::{RecursiveMode, Watcher};
use rand::RngExt;
use rewrite_config::{
    Config, ConfigError, ControllerTls, DnsMode, HostEntry, ListenerKind, LoadBalanceStrategy,
    Mode, ProxyGroupKind, ProxyKind, ProxyProviderVehicle,
};
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

type ListenerKey = (ListenerKind, u16, SocketAddr);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ControllerKey {
    Tcp(SocketAddr, i64, Option<PathBuf>),
    Tls(SocketAddr, i64, ControllerTls, Option<PathBuf>),
    #[cfg(unix)]
    Unix(PathBuf, Option<PathBuf>),
    #[cfg(windows)]
    Pipe(String, Option<PathBuf>),
}

enum PreparedController {
    Tcp(ControllerKey, TcpListener),
    Tls(
        ControllerKey,
        TcpListener,
        Box<tokio_rustls::rustls::ServerConfig>,
    ),
    #[cfg(unix)]
    Unix(ControllerKey, tokio::net::UnixListener),
    #[cfg(windows)]
    Pipe(
        ControllerKey,
        tokio::net::windows::named_pipe::NamedPipeServer,
    ),
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
async fn run_with_reload_inner(
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
async fn apply_controller_update(
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
fn restart_current_process() {
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
fn restart_current_process() {
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
fn restart_current_process() {}

fn start_group_health_scheduler(
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
) -> RuntimeTask {
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let handle = tokio::spawn(run_group_health_scheduler(config, state, child_shutdown));
    RuntimeTask { shutdown, handle }
}

fn start_provider_health_scheduler(
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
) -> RuntimeTask {
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let handle = tokio::spawn(run_provider_health_scheduler(config, state, child_shutdown));
    RuntimeTask { shutdown, handle }
}

fn start_ntp_service(
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
) -> RuntimeTask {
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let handle = tokio::spawn(run_ntp_service(config, state, child_shutdown));
    RuntimeTask { shutdown, handle }
}

fn start_ui_updater(config: watch::Receiver<Arc<Config>>, state: Arc<RuntimeState>) -> RuntimeTask {
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let handle = tokio::spawn(run_ui_updater(config, state, child_shutdown));
    RuntimeTask { shutdown, handle }
}

async fn run_ui_updater(
    mut config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    loop {
        let current = Arc::clone(&config.borrow_and_update());
        match rewrite_services::auto_update_ui(&current).await {
            Ok(true) => state.log("info", "external UI downloaded"),
            Ok(false) => {}
            Err(error) => state.log("error", format!("external UI download failed: {error}")),
        }
        tokio::select! {
            () = shutdown.cancelled() => return,
            changed = config.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

fn start_geo_updater(
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
) -> RuntimeTask {
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let handle = tokio::spawn(run_geo_updater(config, state, child_shutdown));
    RuntimeTask { shutdown, handle }
}

async fn run_geo_updater(
    mut config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    loop {
        let current = Arc::clone(&config.borrow_and_update());
        if current.geo_auto_update {
            match rewrite_services::geodata_update_due(&current) {
                Ok(true) => match rewrite_services::update_geodata(&current).await {
                    Ok(()) => state.log("info", "geodata updated"),
                    Err(error) => state.log("error", format!("geodata update failed: {error}")),
                },
                Ok(false) => {}
                Err(error) => state.log("error", format!("geodata schedule failed: {error}")),
            }
        }
        let hours = u64::try_from(current.geo_update_interval.max(1)).unwrap_or(1);
        tokio::select! {
            () = shutdown.cancelled() => return,
            changed = config.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            () = tokio::time::sleep(Duration::from_secs(hours.saturating_mul(60 * 60))), if current.geo_auto_update => {}
        }
    }
}

async fn run_ntp_service(
    mut config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    'configuration: loop {
        state.clock().set_offset_micros(0);
        let ntp = config.borrow_and_update().ntp.clone();
        if !ntp.enable {
            tokio::select! {
                () = shutdown.cancelled() => break,
                changed = config.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
            continue;
        }
        if ntp.write_to_system {
            state.log(
                "warning",
                "NTP write-to-system is unavailable in the safe Rust platform boundary",
            );
        }
        for attempt in 0..3 {
            let clock = state.clock();
            let exchange = rewrite_services::update_ntp(&ntp, &clock);
            tokio::select! {
                () = shutdown.cancelled() => break 'configuration,
                changed = config.changed() => {
                    if changed.is_err() {
                        break 'configuration;
                    }
                    continue 'configuration;
                }
                result = exchange => match result {
                    Ok(offset) => {
                        state.log("info", format!("NTP clock offset updated: {offset}us"));
                        break;
                    }
                    Err(error) if attempt < 2 => {
                        state.log("warning", format!("NTP update attempt failed: {error}"));
                    }
                    Err(error) => {
                        state.log("error", format!("NTP update failed: {error}"));
                    }
                }
            }
        }
        let interval = u64::try_from(ntp.interval.max(1)).unwrap_or(1);
        tokio::select! {
            () = shutdown.cancelled() => break,
            changed = config.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            () = tokio::time::sleep(Duration::from_secs(interval.saturating_mul(60))) => {}
        }
    }
    state.clock().set_offset_micros(0);
}

fn start_http_provider_scheduler(
    config: watch::Receiver<Arc<Config>>,
    updates: mpsc::Sender<rewrite_controller::ConfigUpdate>,
) -> RuntimeTask {
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let handle = tokio::spawn(run_http_provider_scheduler(config, updates, child_shutdown));
    RuntimeTask { shutdown, handle }
}

async fn start_file_provider_watcher(
    config: watch::Receiver<Arc<Config>>,
    updates: mpsc::Sender<rewrite_controller::ConfigUpdate>,
) -> RuntimeTask {
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let (ready_sender, ready) = oneshot::channel();
    let handle = tokio::spawn(run_file_provider_watcher(
        config,
        updates,
        child_shutdown,
        ready_sender,
    ));
    let _ = ready.await;
    RuntimeTask { shutdown, handle }
}

async fn run_file_provider_watcher(
    mut config: watch::Receiver<Arc<Config>>,
    updates: mpsc::Sender<rewrite_controller::ConfigUpdate>,
    shutdown: CancellationToken,
    ready: oneshot::Sender<()>,
) {
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let mut watcher = match notify::recommended_watcher(move |event| {
        let _ = event_sender.send(event);
    }) {
        Ok(watcher) => watcher,
        Err(error) => {
            eprintln!("provider file watcher initialization failed: {error}");
            let _ = ready.send(());
            return;
        }
    };
    let mut watched_directories = Vec::new();
    let mut files = BTreeMap::new();
    if let Err(error) = reset_provider_file_watches(
        &mut watcher,
        &config.borrow_and_update(),
        &mut watched_directories,
        &mut files,
    ) {
        eprintln!("provider file watcher configuration failed: {error}");
    }
    let _ = ready.send(());

    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            changed = config.changed() => {
                if changed.is_err() {
                    return;
                }
                if let Err(error) = reset_provider_file_watches(
                    &mut watcher,
                    &config.borrow_and_update(),
                    &mut watched_directories,
                    &mut files,
                ) {
                    eprintln!("provider file watcher configuration failed: {error}");
                }
            }
            event = events.recv() => {
                let Some(event) = event else {
                    return;
                };
                let mut changed_paths = event.map(|event| event.paths).unwrap_or_default();
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
                while let Ok(event) = events.try_recv() {
                    if let Ok(event) = event {
                        changed_paths.extend(event.paths);
                    }
                }
                let mut due = std::collections::BTreeSet::new();
                for path in changed_paths {
                    let path = normalize_provider_watch_path(&path);
                    if let Some(providers) = files.get(&path) {
                        for provider in providers {
                            due.insert(provider.clone());
                        }
                    }
                }
                for provider in due {
                    let (completion, result) = oneshot::channel();
                    let kind = match provider.kind {
                        ScheduledProviderKind::Proxy => {
                            rewrite_controller::ConfigUpdateKind::RefreshProxyProvider(provider.name)
                        }
                        ScheduledProviderKind::Rule => {
                            rewrite_controller::ConfigUpdateKind::RefreshRuleProvider(provider.name)
                        }
                    };
                    if updates
                        .send(rewrite_controller::ConfigUpdate { kind, completion })
                        .await
                        .is_err()
                    {
                        return;
                    }
                    tokio::select! {
                        () = shutdown.cancelled() => return,
                        _ = result => {}
                    }
                }
            }
        }
    }
}

fn reset_provider_file_watches(
    watcher: &mut notify::RecommendedWatcher,
    config: &Config,
    watched_directories: &mut Vec<PathBuf>,
    files: &mut BTreeMap<PathBuf, Vec<ScheduledProvider>>,
) -> notify::Result<()> {
    for directory in watched_directories.drain(..) {
        let _ = watcher.unwatch(&directory);
    }
    files.clear();
    for provider in &config.proxy_providers {
        if provider.vehicle == ProxyProviderVehicle::File {
            files
                .entry(normalize_provider_watch_path(&provider.path))
                .or_default()
                .push(ScheduledProvider {
                    kind: ScheduledProviderKind::Proxy,
                    name: provider.name.clone(),
                });
        }
    }
    for provider in config.rule_providers.values() {
        if provider.vehicle == rewrite_config::RuleProviderVehicle::File {
            files
                .entry(normalize_provider_watch_path(&provider.path))
                .or_default()
                .push(ScheduledProvider {
                    kind: ScheduledProviderKind::Rule,
                    name: provider.name.clone(),
                });
        }
    }
    let mut directories: Vec<_> = files
        .keys()
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect();
    directories.sort();
    directories.dedup();
    for directory in directories {
        watcher.watch(&directory, RecursiveMode::NonRecursive)?;
        watched_directories.push(directory);
    }
    Ok(())
}

fn normalize_provider_watch_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[allow(clippy::too_many_lines)]
async fn run_http_provider_scheduler(
    mut config: watch::Receiver<Arc<Config>>,
    updates: mpsc::Sender<rewrite_controller::ConfigUpdate>,
    shutdown: CancellationToken,
) {
    let mut deadlines =
        BTreeMap::<ScheduledProvider, (HttpProviderSchedule, tokio::time::Instant)>::new();
    loop {
        let current = Arc::clone(&config.borrow_and_update());
        let scheduled: BTreeMap<_, _> = current
            .proxy_providers
            .iter()
            .filter(|provider| {
                provider.vehicle == ProxyProviderVehicle::Http && provider.interval > 0
            })
            .map(|provider| {
                (
                    ScheduledProvider {
                        kind: ScheduledProviderKind::Proxy,
                        name: provider.name.clone(),
                    },
                    HttpProviderSchedule {
                        interval: provider.interval,
                        url: provider.url.clone(),
                        path: provider.path.clone(),
                        cache_modified: provider.cache_modified,
                    },
                )
            })
            .chain(
                current
                    .rule_providers
                    .values()
                    .filter(|provider| {
                        provider.vehicle == rewrite_config::RuleProviderVehicle::Http
                            && provider.interval > 0
                    })
                    .map(|provider| {
                        (
                            ScheduledProvider {
                                kind: ScheduledProviderKind::Rule,
                                name: provider.name.clone(),
                            },
                            HttpProviderSchedule {
                                interval: provider.interval,
                                url: provider.url.clone(),
                                path: provider.path.clone(),
                                cache_modified: provider.cache_modified,
                            },
                        )
                    }),
            )
            .collect();
        deadlines.retain(|provider, _| scheduled.contains_key(provider));
        let now = tokio::time::Instant::now();
        for (provider, schedule) in &scheduled {
            if deadlines
                .get(provider)
                .is_none_or(|(current, _)| current != schedule)
            {
                deadlines.insert(
                    provider.clone(),
                    (
                        schedule.clone(),
                        now + http_provider_initial_delay(
                            schedule.interval,
                            schedule.cache_modified,
                        ),
                    ),
                );
            }
        }
        let wake_at = deadlines
            .values()
            .map(|(_, deadline)| *deadline)
            .min()
            .unwrap_or_else(|| now + Duration::from_hours(1));
        tokio::select! {
            () = shutdown.cancelled() => return,
            changed = config.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            () = tokio::time::sleep_until(wake_at) => {
                let now = tokio::time::Instant::now();
                let due: Vec<_> = deadlines
                    .iter()
                    .filter(|(_, (_, deadline))| *deadline <= now)
                    .map(|(name, _)| name.clone())
                    .collect();
                for provider in due {
                    let schedule = scheduled
                        .get(&provider)
                        .expect("due HTTP provider remains scheduled")
                        .clone();
                    deadlines.insert(
                        provider.clone(),
                        (
                            schedule.clone(),
                            now + Duration::from_secs(schedule.interval.max(1)),
                        ),
                    );
                    let (completion, result) = oneshot::channel();
                    let kind = match provider.kind {
                        ScheduledProviderKind::Proxy => {
                            rewrite_controller::ConfigUpdateKind::RefreshProxyProvider(
                                provider.name,
                            )
                        }
                        ScheduledProviderKind::Rule => {
                            rewrite_controller::ConfigUpdateKind::RefreshRuleProvider(
                                provider.name,
                            )
                        }
                    };
                    let update = rewrite_controller::ConfigUpdate {
                        kind,
                        completion,
                    };
                    if updates.send(update).await.is_err() {
                        return;
                    }
                    tokio::select! {
                        () = shutdown.cancelled() => return,
                        _ = result => {}
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ScheduledProvider {
    kind: ScheduledProviderKind,
    name: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ScheduledProviderKind {
    Proxy,
    Rule,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HttpProviderSchedule {
    interval: u64,
    url: Option<String>,
    path: PathBuf,
    cache_modified: Option<SystemTime>,
}

fn http_provider_initial_delay(interval: u64, cache_modified: Option<SystemTime>) -> Duration {
    let interval = Duration::from_secs(interval);
    let age = cache_modified
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .unwrap_or_default();
    interval.saturating_sub(age)
}

async fn run_group_health_scheduler(
    mut config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    let mut deadlines = BTreeMap::<String, tokio::time::Instant>::new();
    loop {
        let current = Arc::clone(&config.borrow_and_update());
        let automatic: Vec<_> = current
            .proxy_groups
            .iter()
            .filter(|group| group.kind != ProxyGroupKind::Select && group.health.interval != 0)
            .cloned()
            .collect();
        deadlines.retain(|name, _| automatic.iter().any(|group| group.name == *name));
        let now = tokio::time::Instant::now();
        for group in &automatic {
            let initial = !deadlines.contains_key(&group.name);
            let due = initial || deadlines[&group.name] <= now;
            if !due {
                continue;
            }
            let interval = Duration::from_secs(group.health.interval);
            if (initial
                || !group.health.lazy
                || state.proxy_group_touched_within(&group.name, interval))
                && state.begin_group_health_check(&group.name)
            {
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = rewrite_controller::healthcheck_proxy_group(group, &current, &state) => {}
                }
                state.finish_group_health_check(&group.name);
            }
            deadlines.insert(group.name.clone(), tokio::time::Instant::now() + interval);
        }
        let wake_at = deadlines
            .values()
            .min()
            .copied()
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_hours(1));
        tokio::select! {
            () = shutdown.cancelled() => return,
            changed = config.changed() => {
                if changed.is_err() {
                    return;
                }
                deadlines.clear();
            }
            name = state.next_group_health_trigger() => {
                let current = Arc::clone(&config.borrow());
                if let Some(group) = current.proxy_groups.iter().find(|group| group.name == name) {
                    tokio::select! {
                        () = shutdown.cancelled() => return,
                        () = rewrite_controller::healthcheck_proxy_group(group, &current, &state) => {}
                    }
                }
                state.finish_group_health_check(&name);
            }
            () = tokio::time::sleep_until(wake_at) => {}
        }
    }
}

async fn run_provider_health_scheduler(
    mut config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    let mut deadlines = BTreeMap::<String, tokio::time::Instant>::new();
    loop {
        let current = Arc::clone(&config.borrow_and_update());
        let automatic: Vec<_> = current
            .proxy_providers
            .iter()
            .filter(|provider| provider.health_check.enabled)
            .cloned()
            .collect();
        deadlines.retain(|name, _| automatic.iter().any(|provider| provider.name == *name));
        let now = tokio::time::Instant::now();
        for provider in &automatic {
            let initial = !deadlines.contains_key(&provider.name);
            let due = initial || deadlines[&provider.name] <= now;
            if !due {
                continue;
            }
            let interval = Duration::from_secs(provider.health_check.interval.max(1));
            let touch_name = format!("provider:{}", provider.name);
            if initial
                || !provider.health_check.lazy
                || state.proxy_group_touched_within(&touch_name, interval)
            {
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = rewrite_controller::healthcheck_proxy_provider_config(
                        provider,
                        &current,
                        &state,
                    ) => {}
                }
            }
            deadlines.insert(
                provider.name.clone(),
                tokio::time::Instant::now() + interval,
            );
        }
        let wake_at = deadlines
            .values()
            .min()
            .copied()
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_hours(1));
        tokio::select! {
            () = shutdown.cancelled() => return,
            changed = config.changed() => {
                if changed.is_err() {
                    return;
                }
                deadlines.clear();
            }
            () = tokio::time::sleep_until(wake_at) => {}
        }
    }
}

const HTTP_PROVIDER_LIMIT: usize = 4 * 1024 * 1024;
const HTTP_PROVIDER_TIMEOUT: Duration = Duration::from_secs(30);

enum HttpProviderFetch {
    Modified {
        payload: Vec<u8>,
        etag: Option<String>,
    },
    NotModified,
}

async fn hydrate_http_proxy_providers(config: &mut Config, state: &RuntimeState) {
    let pending: Vec<_> = config
        .proxy_providers
        .iter()
        .filter(|provider| {
            provider.vehicle == ProxyProviderVehicle::Http && provider.proxies.is_empty()
        })
        .map(|provider| provider.name.clone())
        .collect();
    for name in pending {
        match refresh_http_proxy_provider(config, &name).await {
            Ok(()) => {
                state.log("info", format!("initial proxy provider {name} loaded"));
            }
            Err(error) => {
                state.log(
                    "error",
                    format!("initial proxy provider {name} error: {error}"),
                );
                eprintln!("initial proxy provider {name} error: {error}");
            }
        }
    }
    let pending_rules: Vec<_> = config
        .rule_providers
        .values()
        .filter(|provider| {
            provider.vehicle == rewrite_config::RuleProviderVehicle::Http
                && provider.payload.is_empty()
        })
        .map(|provider| provider.name.clone())
        .collect();
    for name in pending_rules {
        match refresh_rule_provider(config, &name).await {
            Ok(()) => state.log("info", format!("initial rule provider {name} loaded")),
            Err(error) => {
                state.log(
                    "error",
                    format!("initial rule provider {name} error: {error}"),
                );
                eprintln!("initial rule provider {name} error: {error}");
            }
        }
    }
}

async fn refresh_http_proxy_provider(config: &mut Config, name: &str) -> Result<(), String> {
    let provider = config
        .proxy_providers
        .iter()
        .find(|provider| provider.name == name)
        .ok_or_else(|| format!("proxy provider {name} not found"))?;
    if provider.vehicle != ProxyProviderVehicle::Http {
        return Err(format!("proxy provider {name} is not an HTTP provider"));
    }
    let url = provider
        .url
        .clone()
        .ok_or_else(|| format!("proxy provider {name} has no URL"))?;
    let path = provider.path.clone();
    let headers = provider.headers.clone();
    let size_limit = provider.size_limit;
    let etag = config.etag_support.then(|| provider.etag.clone()).flatten();
    let trust_certificates = config.trust_certificates.clone();
    let hosts = config.hosts.clone();
    let fetched = tokio::time::timeout(
        HTTP_PROVIDER_TIMEOUT,
        fetch_http_proxy_provider(
            &url,
            &headers,
            etag.as_deref(),
            size_limit,
            &trust_certificates,
            &hosts,
        ),
    )
    .await
    .map_err(|_| "provider HTTP request timed out".to_owned())??;
    let HttpProviderFetch::Modified { payload, etag } = fetched else {
        if let Ok(payload) = std::fs::read(&path) {
            let _ = persist_http_proxy_provider(&path, &payload);
        }
        let provider = config
            .proxy_providers
            .iter_mut()
            .find(|provider| provider.name == name)
            .expect("looked up proxy provider remains present");
        provider.cache_modified = Some(SystemTime::now());
        return Ok(());
    };
    let source = std::str::from_utf8(&payload)
        .map_err(|error| format!("provider payload is not UTF-8: {error}"))?;
    let mut next = config
        .replace_proxy_provider_source(name, source)
        .map_err(|error| error.to_string())?;
    let refreshed = next
        .proxy_providers
        .iter_mut()
        .find(|provider| provider.name == name)
        .expect("replaced proxy provider remains present");
    refreshed.etag = etag;
    persist_http_proxy_provider(&path, &payload).map_err(|error| error.to_string())?;
    rewrite_config::persist_provider_etag(&path, &url, &payload, refreshed.etag.as_deref())
        .map_err(|error| error.to_string())?;
    refreshed.cache_modified = std::fs::metadata(&path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .or_else(|| Some(SystemTime::now()));
    *config = next;
    Ok(())
}

async fn refresh_rule_provider(config: &mut Config, name: &str) -> Result<(), String> {
    let provider = config
        .rule_providers
        .get(name)
        .ok_or_else(|| format!("rule provider {name} not found"))?;
    if provider.vehicle != rewrite_config::RuleProviderVehicle::Http {
        *config = config
            .reload_rule_provider(name)
            .map_err(|error| error.to_string())?;
        return Ok(());
    }
    let url = provider
        .url
        .clone()
        .ok_or_else(|| format!("rule provider {name} has no URL"))?;
    let path = provider.path.clone();
    let headers = provider.headers.clone();
    let size_limit = provider.size_limit;
    let etag = config.etag_support.then(|| provider.etag.clone()).flatten();
    let trust_certificates = config.trust_certificates.clone();
    let hosts = config.hosts.clone();
    let fetched = tokio::time::timeout(
        HTTP_PROVIDER_TIMEOUT,
        fetch_http_proxy_provider(
            &url,
            &headers,
            etag.as_deref(),
            size_limit,
            &trust_certificates,
            &hosts,
        ),
    )
    .await
    .map_err(|_| "rule provider HTTP request timed out".to_owned())??;
    let HttpProviderFetch::Modified { payload, etag } = fetched else {
        return Ok(());
    };
    let mut next = config
        .replace_rule_provider_source(name, &payload)
        .map_err(|error| error.to_string())?;
    persist_http_proxy_provider(&path, &payload).map_err(|error| error.to_string())?;
    rewrite_config::persist_provider_etag(&path, &url, &payload, etag.as_deref())
        .map_err(|error| error.to_string())?;
    next.rule_providers
        .get_mut(name)
        .expect("replaced rule provider remains present")
        .etag = etag;
    *config = next;
    Ok(())
}

async fn fetch_http_proxy_provider(
    raw_url: &str,
    configured_headers: &BTreeMap<String, Vec<String>>,
    etag: Option<&str>,
    size_limit: usize,
    trust_certificates: &[String],
    hosts: &rewrite_config::HostTable,
) -> Result<HttpProviderFetch, String> {
    // reqwest deliberately uses rustls-no-provider so the workspace does not
    // pull AWS-LC beside the ring-backed DNS/QUIC stack. Install ring before
    // constructing its client; repeated installation is harmless.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let url = url::Url::parse(raw_url).map_err(|error| error.to_string())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("provider URL must use HTTP or HTTPS and include a host".to_owned());
    }
    let mut client = reqwest::Client::builder();
    let mut roots = Vec::new();
    for certificate in trust_certificates {
        let certificate = reqwest::tls::Certificate::from_pem(certificate.as_bytes())
            .map_err(|error| format!("invalid provider root certificate: {error}"))?;
        roots.push(certificate);
    }
    if !roots.is_empty() {
        client = client.tls_certs_only(roots);
    }
    if let Some(host) = url.host_str()
        && host.parse::<IpAddr>().is_err()
        && let Some(HostEntry::Addresses(addresses)) = hosts.resolve(host)
        && let Some(address) = addresses.first()
    {
        let port = url
            .port_or_known_default()
            .ok_or_else(|| "provider URL has no port".to_owned())?;
        client = client.resolve(host, SocketAddr::new(*address, port));
    }
    let client = client.build().map_err(|error| error.to_string())?;
    let mut request = client.get(url);
    for (name, values) in configured_headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| format!("invalid provider header name: {error}"))?;
        for value in values {
            let value = reqwest::header::HeaderValue::from_str(value)
                .map_err(|error| format!("invalid provider header value: {error}"))?;
            request = request.header(name.clone(), value);
        }
    }
    if let Some(etag) = etag {
        let value = reqwest::header::HeaderValue::from_str(etag)
            .map_err(|error| format!("invalid provider ETag: {error}"))?;
        request = request.header(reqwest::header::IF_NONE_MATCH, value);
    }
    let response = request.send().await.map_err(|error| format!("{error:?}"))?;
    if etag.is_some() && response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(HttpProviderFetch::NotModified);
    }
    if !response.status().is_success() {
        return Err(format!("provider HTTP status {}", response.status()));
    }
    let response_etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let limit = if size_limit == 0 {
        HTTP_PROVIDER_LIMIT
    } else {
        size_limit.min(HTTP_PROVIDER_LIMIT)
    };
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(format!("provider payload exceeds {limit} bytes"));
    }
    let mut body = response.bytes_stream();
    let mut payload = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|error| error.to_string())?;
        if payload.len().saturating_add(chunk.len()) > limit {
            return Err(format!("provider payload exceeds {limit} bytes"));
        }
        payload.extend_from_slice(&chunk);
    }
    Ok(HttpProviderFetch::Modified {
        payload,
        etag: response_etag,
    })
}

fn persist_http_proxy_provider(path: &Path, payload: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, payload)?;
    std::fs::rename(temporary, path)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn apply_generation(
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
        let listener = rewrite_platform::bind_local_tcp_listener(address, dual_stack)?;
        let listener = TcpListener::from_std(listener)?;
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
        let handle = tokio::spawn(async move {
            run_listener(kind, listener, udp, task_config, task_state, child_shutdown).await;
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

fn controller_keys(config: &Config) -> Result<Vec<ControllerKey>, ConfigError> {
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

fn same_controller_kind(left: &ControllerKey, right: &ControllerKey) -> bool {
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

fn prepare_controller(
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

fn sync_selector_state(state: &RuntimeState, config: &Config) {
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

async fn apply_controller_tasks(
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

fn cleanup_controller_key(key: &ControllerKey) {
    #[cfg(unix)]
    if let ControllerKey::Unix(path, ..) = key {
        let _ = std::fs::remove_file(path);
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

async fn run_listener(
    kind: ListenerKind,
    listener: TcpListener,
    udp: Option<Arc<UdpSocket>>,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    let mut connections = JoinSet::new();
    let mut udp_sessions = UdpSessions::default();
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
            result = udp_sessions.tasks.join_next(), if !udp_sessions.tasks.is_empty() => {
                udp_sessions.reap(result.as_ref());
            }
            received = receive_udp(udp.as_ref(), &mut datagram) => {
                if let Ok((length, source)) = received
                    && let Some(socket) = &udp
                {
                    let connection_config = Arc::clone(&config.borrow());
                    let Some(request) = prepare_udp_request(
                        &datagram[..length],
                        source,
                        socket.local_addr().map_or(0, |address| address.port()),
                        &connection_config,
                        &state,
                    ) else {
                        continue;
                    };
                    udp_sessions.dispatch(
                        Arc::clone(socket),
                        source,
                        request,
                        connection_config,
                        Arc::clone(&state),
                        shutdown.child_token(),
                    );
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
    udp_sessions.shutdown(&state).await;
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

struct UdpSessionPacket {
    metadata: Metadata,
    fake_host: Option<String>,
    payload: Vec<u8>,
}

#[derive(Default)]
struct UdpSessions {
    tasks: JoinSet<(SocketAddr, u64)>,
    entries: BTreeMap<SocketAddr, (u64, mpsc::Sender<UdpSessionPacket>)>,
    next_id: u64,
}

impl UdpSessions {
    fn reap(&mut self, result: Option<&Result<(SocketAddr, u64), tokio::task::JoinError>>) {
        if let Some(Ok((source, session_id))) = result
            && self
                .entries
                .get(source)
                .is_some_and(|(current_id, _)| current_id == session_id)
        {
            self.entries.remove(source);
        }
    }

    fn dispatch(
        &mut self,
        listener: Arc<UdpSocket>,
        source: SocketAddr,
        request: UdpSessionPacket,
        config: Arc<Config>,
        state: Arc<RuntimeState>,
        shutdown: CancellationToken,
    ) {
        if let Some((_, sender)) = self.entries.get(&source) {
            match sender.try_send(request) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    state.log("error", "SOCKS5 UDP session queue is full");
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(request)) => {
                    self.entries.remove(&source);
                    self.start(listener, source, request, config, state, shutdown);
                    return;
                }
            }
        }
        self.start(listener, source, request, config, state, shutdown);
    }

    fn start(
        &mut self,
        listener: Arc<UdpSocket>,
        source: SocketAddr,
        request: UdpSessionPacket,
        config: Arc<Config>,
        state: Arc<RuntimeState>,
        shutdown: CancellationToken,
    ) {
        let decision = mode_decision(&config, &state)
            .unwrap_or_else(|| config.rules.evaluate(&request.metadata));
        if decision.route() != Route::Direct {
            return;
        }
        let session_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let (sender, receiver) = mpsc::channel(64);
        self.entries.insert(source, (session_id, sender));
        self.tasks.spawn(async move {
            run_udp_session(
                listener, source, request, receiver, config, state, decision, shutdown,
            )
            .await;
            (source, session_id)
        });
    }

    async fn shutdown(mut self, state: &RuntimeState) {
        self.entries.clear();
        while let Some(result) = self.tasks.join_next().await {
            if let Err(join_error) = result {
                state.log(
                    "error",
                    format!("UDP session task failed during listener shutdown: {join_error}"),
                );
            }
        }
    }
}

fn prepare_udp_request(
    packet: &[u8],
    source: SocketAddr,
    inbound_port: u16,
    config: &Config,
    state: &Arc<RuntimeState>,
) -> Option<UdpSessionPacket> {
    let accepted = match rewrite_inbound::decode_socks5_udp(packet, source, inbound_port) {
        Ok(accepted) => accepted,
        Err(error) => {
            state.log("error", format!("SOCKS5 UDP packet rejected: {error}"));
            return None;
        }
    };
    let mut metadata = accepted.metadata.clone();
    // Both pinned default SOCKS and mixed UDP listeners are backed by the Go
    // SOCKS UDP listener and therefore expose DEFAULT-SOCKS, not DEFAULT-MIXED.
    "DEFAULT-SOCKS".clone_into(&mut metadata.inbound_name);
    let fake_host = apply_host_mapping(&mut metadata, config, state);
    Some(UdpSessionPacket {
        metadata,
        fake_host,
        payload: accepted.payload.to_vec(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_session(
    listener: Arc<UdpSocket>,
    source: SocketAddr,
    first: UdpSessionPacket,
    mut requests: mpsc::Receiver<UdpSessionPacket>,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    decision: rewrite_rules::Decision,
    shutdown: CancellationToken,
) {
    const UDP_SESSION_TIMEOUT: Duration = Duration::from_mins(1);

    let target =
        match resolve_udp_target(&first.metadata, first.fake_host.as_deref(), &config).await {
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
    let tracker = state.register(
        &first.metadata,
        &decision.target,
        decision.matched_kind.as_deref(),
    );
    let mut uploaded = 0_u64;
    let mut downloaded = 0_u64;
    if outbound.send_to(&first.payload, target).await.is_err() {
        return;
    }
    uploaded = uploaded.saturating_add(first.payload.len() as u64);
    let idle = tokio::time::sleep(UDP_SESSION_TIMEOUT);
    tokio::pin!(idle);
    let mut response = vec![0_u8; 65_535];
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tracker.cancelled() => break,
            request = requests.recv() => {
                let Some(request) = request else { break };
                let target = match resolve_udp_target(
                    &request.metadata,
                    request.fake_host.as_deref(),
                    &config,
                ).await {
                    Ok(target) => target,
                    Err(error) => {
                        state.log("error", format!("DIRECT UDP resolution failed: {error}"));
                        continue;
                    }
                };
                if outbound.send_to(&request.payload, target).await.is_ok() {
                    uploaded = uploaded.saturating_add(request.payload.len() as u64);
                    idle.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_TIMEOUT);
                }
            }
            received = outbound.recv_from(&mut response) => {
                let Ok((length, remote)) = received else { break };
                let packet = rewrite_inbound::encode_socks5_udp(remote, &response[..length]);
                if listener.send_to(&packet, source).await.is_err() {
                    break;
                }
                downloaded = downloaded.saturating_add(length as u64);
                idle.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_TIMEOUT);
            }
            () = &mut idle => break,
        }
    }
    tracker.finish(uploaded, downloaded);
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
    let (outbound_target, traversed_groups) =
        resolve_selector_target(target, metadata, config, state)?;
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
    let attempts = if traversed_groups.is_empty() { 1 } else { 10 };
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
        let result = tokio::select! {
            () = shutdown.cancelled() => return None,
            result = connect_configured_proxy(
                proxy,
                &metadata.destination,
                config.ipv6,
                state.clock(),
            ) => result,
        };
        match result {
            Ok(remote) => return Some(remote),
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

async fn connect_configured_proxy(
    proxy: &rewrite_config::ProxyConfig,
    destination: &Destination,
    allow_ipv6: bool,
    clock: Arc<rewrite_services::AdjustedClock>,
) -> Result<rewrite_outbound::BoxedOutboundStream, String> {
    let server = Destination {
        host: proxy
            .server
            .parse()
            .map_or_else(|_| Host::Domain(proxy.server.clone()), Host::Ip),
        port: proxy.port,
    };
    let credentials = proxy.username.as_deref().zip(proxy.password.as_deref());
    match proxy.kind {
        ProxyKind::Http => {
            let tls = proxy.tls.then_some(rewrite_outbound::HttpProxyTls {
                server_name: proxy.sni.as_deref().unwrap_or(&proxy.server),
                skip_certificate_verification: proxy.skip_cert_verify,
            });
            rewrite_outbound::connect_http(
                &server,
                destination,
                allow_ipv6,
                credentials,
                &proxy.headers,
                tls,
                Some(clock),
            )
            .await
            .map_err(|error| format!("HTTP proxy connection failed: {error}"))
        }
        ProxyKind::Socks5 => {
            rewrite_outbound::connect_socks5(&server, destination, allow_ipv6, credentials)
                .await
                .map_err(|error| format!("SOCKS5 proxy connection failed: {error}"))
        }
    }
}

fn group_retry_delay(attempt: usize) -> Duration {
    let multiplier = 1_u64 << u32::try_from(attempt.min(7)).unwrap_or(7);
    Duration::from_millis(10_u64.saturating_mul(multiplier).min(1000))
}

fn resolve_selector_target(
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

fn record_group_proxy_failure(
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

fn load_balance_key(metadata: &Metadata, include_source: bool) -> String {
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

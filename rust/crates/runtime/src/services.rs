use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures_util::StreamExt;
use notify::{RecursiveMode, Watcher};
use rewrite_config::{Config, HostEntry, ProxyGroupKind, ProxyProviderVehicle};
use rewrite_state::RuntimeState;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use crate::types::RuntimeTask;

pub(super) fn start_group_health_scheduler(
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
) -> RuntimeTask {
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let handle = tokio::spawn(run_group_health_scheduler(config, state, child_shutdown));
    RuntimeTask { shutdown, handle }
}

pub(super) fn start_provider_health_scheduler(
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
) -> RuntimeTask {
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let handle = tokio::spawn(run_provider_health_scheduler(config, state, child_shutdown));
    RuntimeTask { shutdown, handle }
}

pub(super) fn start_ntp_service(
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
) -> RuntimeTask {
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let handle = tokio::spawn(run_ntp_service(config, state, child_shutdown));
    RuntimeTask { shutdown, handle }
}

pub(super) fn start_ui_updater(
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
) -> RuntimeTask {
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let handle = tokio::spawn(run_ui_updater(config, state, child_shutdown));
    RuntimeTask { shutdown, handle }
}

pub(super) async fn run_ui_updater(
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

pub(super) fn start_geo_updater(
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
) -> RuntimeTask {
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let handle = tokio::spawn(run_geo_updater(config, state, child_shutdown));
    RuntimeTask { shutdown, handle }
}

pub(super) async fn run_geo_updater(
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

pub(super) async fn run_ntp_service(
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

pub(super) fn start_http_provider_scheduler(
    config: watch::Receiver<Arc<Config>>,
    updates: mpsc::Sender<rewrite_controller::ConfigUpdate>,
) -> RuntimeTask {
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let handle = tokio::spawn(run_http_provider_scheduler(config, updates, child_shutdown));
    RuntimeTask { shutdown, handle }
}

pub(super) async fn start_file_provider_watcher(
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

pub(super) async fn run_file_provider_watcher(
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

pub(super) fn reset_provider_file_watches(
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

pub(super) fn normalize_provider_watch_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[allow(clippy::too_many_lines)]
pub(super) async fn run_http_provider_scheduler(
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
pub(super) struct ScheduledProvider {
    kind: ScheduledProviderKind,
    name: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum ScheduledProviderKind {
    Proxy,
    Rule,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HttpProviderSchedule {
    interval: u64,
    url: Option<String>,
    path: PathBuf,
    cache_modified: Option<SystemTime>,
}

pub(super) fn http_provider_initial_delay(
    interval: u64,
    cache_modified: Option<SystemTime>,
) -> Duration {
    let interval = Duration::from_secs(interval);
    let age = cache_modified
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .unwrap_or_default();
    interval.saturating_sub(age)
}

pub(super) async fn run_group_health_scheduler(
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

pub(super) async fn run_provider_health_scheduler(
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

pub(super) const HTTP_PROVIDER_LIMIT: usize = 4 * 1024 * 1024;
pub(super) const HTTP_PROVIDER_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) enum HttpProviderFetch {
    Modified {
        payload: Vec<u8>,
        etag: Option<String>,
    },
    NotModified,
}

pub(super) async fn hydrate_http_proxy_providers(config: &mut Config, state: &RuntimeState) {
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

pub(super) async fn refresh_http_proxy_provider(
    config: &mut Config,
    name: &str,
) -> Result<(), String> {
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

pub(super) async fn refresh_rule_provider(config: &mut Config, name: &str) -> Result<(), String> {
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

pub(super) async fn fetch_http_proxy_provider(
    raw_url: &str,
    configured_headers: &BTreeMap<String, Vec<String>>,
    etag: Option<&str>,
    size_limit: usize,
    trust_certificates: &[String],
    hosts: &rewrite_config::HostTable,
) -> Result<HttpProviderFetch, String> {
    // Reqwest deliberately uses rustls-no-provider so enabling AWS-LC for ECH
    // does not make its provider selection ambiguous. Install ring before
    // constructing the client; repeated installation is harmless.
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

pub(super) fn persist_http_proxy_provider(path: &Path, payload: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, payload)?;
    std::fs::rename(temporary, path)
}

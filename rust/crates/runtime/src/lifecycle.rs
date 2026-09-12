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
/// A same-port bind-address or Shadowsocks-identity change must retire the old
/// socket first, matching the Go fixed-listener recreation boundary. Any later
/// failure — including a bind/`?` error during prepare, not just TUN start —
/// drops uncommitted sockets and restores those retired listeners before the
/// error is returned.
///
/// # Errors
///
/// Returns [`RuntimeError`] only when the initial generation cannot be created.
/// Later reload errors are logged and leave the current generation unchanged,
/// including restoring previous listeners, controllers, DNS and TUN.
pub async fn run_with_reload(
    initial: Config,
    reloads: mpsc::Receiver<Config>,
    shutdown: CancellationToken,
) -> Result<(), RuntimeError> {
    Box::pin(run_with_reload_inner(initial, reloads, shutdown, None)).await
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
/// Later reload errors are logged and leave the current generation unchanged,
/// including restoring previous listeners, controllers, DNS and TUN.
pub async fn run_with_reload_lifecycle(
    initial: Config,
    reloads: mpsc::Receiver<Config>,
    shutdown: CancellationToken,
    lifecycle: LifecycleSignals,
) -> Result<(), RuntimeError> {
    Box::pin(run_with_reload_inner(
        initial,
        reloads,
        shutdown,
        Some(lifecycle),
    ))
    .await
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
    let mut tun: Option<(rewrite_config::TunConfig, RuntimeTask)> = None;

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
        &mut tun,
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
    let mut reloads_open = true;

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            next = reloads.recv(), if reloads_open => {
                match next {
                    Some(next) => {
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
                            &mut tun,
                        ).await {
                            state.log("error", format!("configuration reload failed: {error}"));
                            eprintln!("configuration reload failed: {error}");
                        } else {
                            state.log("info", "configuration reloaded");
                        }
                    }
                    None => reloads_open = false,
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
                    &mut tun,
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
    if let Some((_, task)) = tun {
        stop_task(task).await;
    }
    stop_task(health).await;
    stop_task(provider_health).await;
    stop_task(providers).await;
    stop_task(provider_files).await;
    stop_task(ntp).await;
    stop_task(ui_updater).await;
    stop_task(geo_updater).await;
    // Producers have stopped; now retire pooled QUIC/UDP tunnel workers.
    state.clear_tuic_clients().await;
    state.clear_wireguard_clients().await;
    state.clear_ssh_clients().await;
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
    tun: &mut Option<(rewrite_config::TunConfig, RuntimeTask)>,
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
            tun,
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rewrite_config::Config;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;

    use super::run_with_reload;
    use crate::types::RuntimeError;

    fn reserve_port() -> u16 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve port");
        let port = listener.local_addr().expect("port").port();
        drop(listener);
        port
    }

    fn failing_tun_yaml() -> String {
        let device = if cfg!(target_os = "linux") {
            "lo"
        } else if cfg!(target_os = "macos") {
            "tun0"
        } else if cfg!(windows) {
            "Loopback Pseudo-Interface 1"
        } else {
            "unsupported-tun"
        };
        format!(
            "tun:\n  enable: true\n  stack: smoltcp\n  device: {device}\n  inet4-address:\n    - 198.18.0.1/30\n"
        )
    }

    async fn wait_controller_ready(
        client: &reqwest::Client,
        url: &str,
        runtime: &JoinHandle<Result<(), RuntimeError>>,
    ) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if client
                .get(format!("{url}/version"))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "controller did not become ready; runtime finished: {}",
                runtime.is_finished()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_tcp_open(address: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{address} did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[cfg(not(windows))]
    async fn assert_tcp_closed(address: &str) {
        if let Ok(Ok(_)) = tokio::time::timeout(
            Duration::from_millis(200),
            tokio::net::TcpStream::connect(address),
        )
        .await
        {
            panic!("{address} stayed open after rollback");
        }
    }

    fn ss_listener_yaml(port: u16, password: &str) -> String {
        format!(
            "listeners:\n  - name: ss-reload\n    type: shadowsocks\n    listen: 127.0.0.1\n    port: {port}\n    cipher: aes-128-gcm\n    password: {password}\n"
        )
    }

    fn put_config_body(payload: &str) -> String {
        let escaped = payload
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n");
        format!(r#"{{"path":"","payload":"{escaped}"}}"#)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn controller_updates_continue_after_reload_source_closes() {
        rewrite_services::install_default_crypto_provider();
        let mixed_port = reserve_port();
        let controller_port = reserve_port();
        let initial = Config::from_yaml(&format!(
            "mixed-port: {mixed_port}\nexternal-controller: 127.0.0.1:{controller_port}\nmode: rule\nipv6: false\nrules: ['MATCH,DIRECT']\n"
        ))
        .expect("initial config");
        let (reload_sender, reload_receiver) = mpsc::channel(1);
        drop(reload_sender);
        let shutdown = CancellationToken::new();
        let runtime = tokio::spawn(run_with_reload(initial, reload_receiver, shutdown.clone()));
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("HTTP client");
        let url = format!("http://127.0.0.1:{controller_port}");
        wait_controller_ready(&client, &url, &runtime).await;
        let response = client
            .put(format!("{url}/configs"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(format!(
                r#"{{"path":"","payload":"mixed-port: {mixed_port}\nmode: direct\nipv6: false\nrules: ['MATCH,DIRECT']\n"}}"#
            ))
            .send()
            .await
            .expect("controller update completes");
        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
        drop(response);
        drop(client);
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(2), runtime)
            .await
            .expect("runtime stops")
            .expect("runtime task joins")
            .expect("runtime succeeds");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_port_replacement_restored_after_failed_tun_reload() {
        rewrite_services::install_default_crypto_provider();
        let mixed_port = reserve_port();
        let ss_port = reserve_port();
        let controller_port = reserve_port();
        let initial_yaml = format!(
            "mixed-port: {mixed_port}\nexternal-controller: 127.0.0.1:{controller_port}\n{}\nmode: rule\nipv6: false\nrules: ['MATCH,DIRECT']\n",
            ss_listener_yaml(ss_port, "rollback-old")
        );
        let initial = Config::from_yaml(&initial_yaml).expect("initial config");
        let (reload_sender, reload_receiver) = mpsc::channel(1);
        drop(reload_sender);
        let shutdown = CancellationToken::new();
        let runtime = tokio::spawn(run_with_reload(initial, reload_receiver, shutdown.clone()));
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .expect("HTTP client");
        let url = format!("http://127.0.0.1:{controller_port}");
        wait_controller_ready(&client, &url, &runtime).await;
        wait_tcp_open(&format!("127.0.0.1:{ss_port}")).await;
        wait_tcp_open(&format!("127.0.0.1:{mixed_port}")).await;
        let payload = format!(
            "mixed-port: {mixed_port}\nallow-lan: true\nbind-address: \"*\"\n{}\n{}\nmode: rule\nipv6: false\nrules: ['MATCH,DIRECT']\n",
            ss_listener_yaml(ss_port, "rollback-new"),
            failing_tun_yaml()
        );
        let response = client
            .put(format!("{url}/configs"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(put_config_body(&payload))
            .send()
            .await
            .expect("controller update completes");
        assert!(
            !response.status().is_success(),
            "TUN reload should fail: {}",
            response.status()
        );
        drop(response);
        wait_tcp_open(&format!("127.0.0.1:{ss_port}")).await;
        wait_tcp_open(&format!("127.0.0.1:{mixed_port}")).await;
        #[cfg(not(windows))]
        assert_tcp_closed(&format!("127.0.0.2:{mixed_port}")).await;
        drop(client);
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(3), runtime)
            .await
            .expect("runtime stops")
            .expect("runtime task joins")
            .expect("runtime succeeds");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stopped_listener_restored_when_replacement_bind_fails() {
        rewrite_services::install_default_crypto_provider();
        let mixed_port = reserve_port();
        let controller_port = reserve_port();
        let initial = Config::from_yaml(&format!(
            "mixed-port: {mixed_port}\nexternal-controller: 127.0.0.1:{controller_port}\nmode: rule\nipv6: false\nrules: ['MATCH,DIRECT']\n"
        ))
        .expect("initial config");
        let (reload_sender, reload_receiver) = mpsc::channel(1);
        drop(reload_sender);
        let shutdown = CancellationToken::new();
        let runtime = tokio::spawn(run_with_reload(initial, reload_receiver, shutdown.clone()));
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .expect("HTTP client");
        let url = format!("http://127.0.0.1:{controller_port}");
        wait_controller_ready(&client, &url, &runtime).await;
        wait_tcp_open(&format!("127.0.0.1:{mixed_port}")).await;
        let payload = format!(
            "mixed-port: {mixed_port}\nallow-lan: true\nbind-address: 192.0.2.1\nmode: rule\nipv6: false\nrules: ['MATCH,DIRECT']\n"
        );
        let response = client
            .put(format!("{url}/configs"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(put_config_body(&payload))
            .send()
            .await
            .expect("controller update completes");
        assert!(
            !response.status().is_success(),
            "unassigned bind-address reload should fail: {}",
            response.status()
        );
        drop(response);
        wait_tcp_open(&format!("127.0.0.1:{mixed_port}")).await;
        drop(client);
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(3), runtime)
            .await
            .expect("runtime stops")
            .expect("runtime task joins")
            .expect("runtime succeeds");
    }
}

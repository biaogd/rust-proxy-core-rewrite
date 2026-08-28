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
use rewrite_inbound::{BoxedInboundStream, InboundCommand, ListenerProtocol};
use rewrite_model::{Destination, Host, Metadata, unmap_ip};
use rewrite_rules::{LazyEvaluation, Route};
use rewrite_state::{ConnectionGuard, RuntimeState};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

mod generation;
mod lifecycle;
mod listener;
mod services;
mod tcp;

use generation::{apply_generation, cleanup_controller_key, stop_task};
pub use lifecycle::{run, run_with_reload, run_with_reload_lifecycle};
use listener::run_listener;
use services::{
    hydrate_http_proxy_providers, refresh_http_proxy_provider, refresh_rule_provider,
    start_file_provider_watcher, start_geo_updater, start_group_health_scheduler,
    start_http_provider_scheduler, start_ntp_service, start_provider_health_scheduler,
    start_ui_updater,
};
use tcp::{
    apply_host_mapping, configured_proxy, direct_tcp_options, mode_decision,
    resolve_rematch_target, serve_connection,
};

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

enum LocalTcpListener {
    Plain(TcpListener),
    FastOpen(tokio_tfo::TfoListener),
}

impl LocalTcpListener {
    async fn accept(&self) -> std::io::Result<(BoxedInboundStream, SocketAddr)> {
        match self {
            Self::Plain(listener) => listener
                .accept()
                .await
                .map(|(stream, address)| (Box::new(stream) as BoxedInboundStream, address)),
            Self::FastOpen(listener) => listener
                .accept()
                .await
                .map(|(stream, address)| (Box::new(stream) as BoxedInboundStream, address)),
        }
    }
}

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

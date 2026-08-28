use std::net::SocketAddr;
use std::path::PathBuf;

use rewrite_config::{ConfigError, ControllerTls, ListenerKind};
use rewrite_inbound::BoxedInboundStream;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("local listener error: {0}")]
    Listener(#[from] std::io::Error),
}

pub(crate) struct RuntimeTask {
    pub(crate) shutdown: CancellationToken,
    pub(crate) handle: JoinHandle<()>,
}

pub(crate) type ListenerKey = (ListenerKind, u16, SocketAddr);

pub(crate) enum LocalTcpListener {
    Plain(TcpListener),
    FastOpen(tokio_tfo::TfoListener),
}

impl LocalTcpListener {
    pub(crate) async fn accept(&self) -> std::io::Result<(BoxedInboundStream, SocketAddr)> {
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
pub(crate) enum ControllerKey {
    Tcp(SocketAddr, i64, Option<PathBuf>),
    Tls(SocketAddr, i64, ControllerTls, Option<PathBuf>),
    #[cfg(unix)]
    Unix(PathBuf, Option<PathBuf>),
    #[cfg(windows)]
    Pipe(String, Option<PathBuf>),
}

pub(crate) enum PreparedController {
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
    pub(crate) ready: oneshot::Sender<()>,
    pub(crate) shutdown_hook_ready: oneshot::Sender<()>,
    pub(crate) continue_shutdown: oneshot::Receiver<()>,
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

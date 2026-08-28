use std::sync::Arc;

use axum::Router;
use axum::middleware;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use hyper_util::service::TowerToHyperService;
use rewrite_config::Config;
use rewrite_dns::DnsService;
use rewrite_state::RuntimeState;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tower_http::services::ServeDir;

use crate::context::{ConfigUpdate, ControllerState};
use crate::cors::apply_dynamic_cors;
use crate::routes::{authenticate_or_serve_public, controller_router};

/// Serves the declared REST subset and Phase 4F15 DNS control surface.
pub async fn serve(
    listener: TcpListener,
    dns_service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    runtime: Arc<RuntimeState>,
    config_updates: mpsc::Sender<ConfigUpdate>,
    shutdown: CancellationToken,
) {
    serve_tcp(
        listener,
        dns_service,
        config,
        runtime,
        config_updates,
        shutdown,
        true,
    )
    .await;
}

/// Serves one already-bound plain TCP controller.
pub async fn serve_tcp(
    listener: TcpListener,
    dns_service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    runtime: Arc<RuntimeState>,
    config_updates: mpsc::Sender<ConfigUpdate>,
    shutdown: CancellationToken,
    require_auth: bool,
) {
    let state = ControllerState {
        dns_service,
        config,
        runtime: Arc::clone(&runtime),
        shutdown: shutdown.clone(),
        config_updates,
        require_auth,
    };
    serve_accept_loop(listener, controller_app(state), runtime, shutdown).await;
}

/// Serves one already-bound TLS controller.
pub async fn serve_tls(
    listener: TcpListener,
    dns_service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    runtime: Arc<RuntimeState>,
    config_updates: mpsc::Sender<ConfigUpdate>,
    shutdown: CancellationToken,
    tls: tokio_rustls::rustls::ServerConfig,
) {
    let tls = Arc::new(tls);
    let state = ControllerState {
        dns_service,
        config,
        runtime: Arc::clone(&runtime),
        shutdown: shutdown.clone(),
        config_updates,
        require_auth: true,
    };
    let app = controller_app(state);
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let acceptor = acceptor.clone();
                    let app = app.clone();
                    let connection_shutdown = shutdown.clone();
                    connections.spawn(async move {
                        if let Ok(stream) = acceptor.accept(stream).await {
                            serve_io(stream, app, connection_shutdown).await;
                        }
                    });
                }
                Err(error) => {
                    runtime.log("error", format!("controller TLS accept failed: {error}"));
                    break;
                }
            }
        }
    }
    while connections.join_next().await.is_some() {}
}

#[cfg(unix)]
/// Serves one already-bound Unix-domain controller without secret auth.
pub async fn serve_unix(
    listener: UnixListener,
    dns_service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    runtime: Arc<RuntimeState>,
    config_updates: mpsc::Sender<ConfigUpdate>,
    shutdown: CancellationToken,
) {
    let state = ControllerState {
        dns_service,
        config,
        runtime: Arc::clone(&runtime),
        shutdown: shutdown.clone(),
        config_updates,
        require_auth: false,
    };
    let app = controller_app(state);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    connections.spawn(serve_io(stream, app.clone(), shutdown.clone()));
                }
                Err(error) => {
                    runtime.log("error", format!("controller Unix accept failed: {error}"));
                    break;
                }
            }
        }
    }
    while connections.join_next().await.is_some() {}
}

#[cfg(windows)]
/// Creates the first Windows named-pipe server instance as a bind barrier.
pub fn prepare_named_pipe(name: &str) -> std::io::Result<NamedPipeServer> {
    if !name.starts_with(r"\\.\pipe\") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            r#"windows namedpipe must start with "\\.\pipe\""#,
        ));
    }
    ServerOptions::new().first_pipe_instance(true).create(name)
}

#[cfg(windows)]
/// Serves a Windows named-pipe controller without secret auth.
pub async fn serve_named_pipe(
    mut listener: NamedPipeServer,
    name: String,
    dns_service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    runtime: Arc<RuntimeState>,
    config_updates: mpsc::Sender<ConfigUpdate>,
    shutdown: CancellationToken,
) {
    let state = ControllerState {
        dns_service,
        config,
        runtime: Arc::clone(&runtime),
        shutdown: shutdown.clone(),
        config_updates,
        require_auth: false,
    };
    let app = controller_app(state);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            connected = listener.connect() => match connected {
                Ok(()) => {
                    let next = match ServerOptions::new().create(&name) {
                        Ok(next) => next,
                        Err(error) => {
                            runtime.log("error", format!("controller pipe accept failed: {error}"));
                            break;
                        }
                    };
                    connections.spawn(serve_io(listener, app.clone(), shutdown.clone()));
                    listener = next;
                }
                Err(error) => {
                    runtime.log("error", format!("controller pipe connect failed: {error}"));
                    break;
                }
            }
        }
    }
    while connections.join_next().await.is_some() {}
}

pub(super) fn controller_app(state: ControllerState) -> Router {
    let ui_path = state.current_config().external_ui_path();
    let mut app = controller_router(state.clone());
    if let Some(path) = ui_path {
        app = app.nest_service("/ui", ServeDir::new(path));
    }
    app.layer(middleware::from_fn_with_state(
        state.clone(),
        authenticate_or_serve_public,
    ))
    .layer(middleware::from_fn_with_state(state, apply_dynamic_cors))
}

pub(super) async fn serve_accept_loop(
    listener: TcpListener,
    app: Router,
    runtime: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    connections.spawn(serve_io(stream, app.clone(), shutdown.clone()));
                }
                Err(error) => {
                    runtime.log("error", format!("controller accept failed: {error}"));
                    break;
                }
            }
        }
    }
    while connections.join_next().await.is_some() {}
}

pub(super) async fn serve_io<I>(stream: I, app: Router, shutdown: CancellationToken)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = TowerToHyperService::new(app);
    let builder = ConnectionBuilder::new(TokioExecutor::new());
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
    tokio::pin!(connection);
    tokio::select! {
        _ = &mut connection => {}
        () = shutdown.cancelled() => connection.as_mut().graceful_shutdown(),
    }
}

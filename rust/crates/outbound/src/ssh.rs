//! SSH outbound adapter (6J-A/B TCP + session reuse + transport keepalive).

use rewrite_config::ProxyConfig;
use rewrite_model::Destination;
use rewrite_protocol_ssh::{Client, ClientOptions};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshProxyError {
    #[error(transparent)]
    Protocol(#[from] rewrite_protocol_ssh::SshProtocolError),
    #[error("SSH dial failed: {0}")]
    Dial(String),
}

/// Socket / cache identity inputs that are not stored on `ProxyConfig`.
#[derive(Clone, Copy, Debug)]
pub struct SshTransportHints<'a> {
    pub dial_server: &'a str,
    pub bind_interface: &'a str,
    pub routing_mark: i64,
    pub keep_alive_idle: i64,
    pub keep_alive_interval: i64,
    pub disable_keep_alive: bool,
}

/// Long-lived outbound client matching Go `adapter/outbound.Ssh`.
pub struct SshClient {
    inner: std::sync::Arc<Client>,
}

impl std::fmt::Debug for SshClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SshClient")
    }
}

impl SshClient {
    /// Dials `hints.dial_server` (typically a PSN-resolved IP) for the SSH TCP
    /// transport. Interface, routing-mark and transport keepalive apply to that
    /// socket.
    ///
    /// # Errors
    ///
    /// Returns when the proxy is missing SSH options or key material is invalid.
    pub fn from_proxy_with_dial_server(
        proxy: &ProxyConfig,
        hints: SshTransportHints<'_>,
    ) -> Result<Self, SshProxyError> {
        let mut options = client_options_from_proxy(proxy)?;
        hints.dial_server.clone_into(&mut options.server);
        hints.bind_interface.clone_into(&mut options.bind_interface);
        options.routing_mark = hints.routing_mark;
        options.keep_alive_idle = hints.keep_alive_idle;
        options.keep_alive_interval = hints.keep_alive_interval;
        options.disable_keep_alive = hints.disable_keep_alive;
        let inner = Client::new(options)?;
        Ok(Self {
            inner: std::sync::Arc::new(inner),
        })
    }

    /// Opens a proxied TCP stream to `destination` over `direct-tcpip`.
    ///
    /// # Errors
    ///
    /// Returns handshake, authentication, or channel-open failures.
    pub async fn create_proxy(
        &self,
        destination: &Destination,
    ) -> Result<crate::BoxedOutboundStream, SshProxyError> {
        self.inner.open_tcp(destination).await.map_err(Into::into)
    }

    pub async fn retire(&self) {
        self.inner.close().await;
    }
}

/// Cache identity for a configured SSH adapter.
#[must_use]
pub fn ssh_adapter_identity(proxy: &ProxyConfig, hints: SshTransportHints<'_>) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{proxy:?}",
        hints.dial_server,
        hints.bind_interface,
        hints.routing_mark,
        hints.keep_alive_idle,
        hints.keep_alive_interval,
        hints.disable_keep_alive
    )
}

fn client_options_from_proxy(proxy: &ProxyConfig) -> Result<ClientOptions, SshProxyError> {
    let ssh = proxy
        .ssh
        .as_ref()
        .ok_or_else(|| SshProxyError::Dial("SSH proxy configuration is missing".to_owned()))?;
    Ok(ClientOptions {
        server: proxy.server.clone(),
        port: proxy.port,
        username: ssh.username.clone(),
        password: ssh.password.clone(),
        private_key: ssh.private_key.clone(),
        private_key_passphrase: ssh.private_key_passphrase.clone(),
        host_keys: ssh.host_keys.clone(),
        host_key_algorithms: ssh.host_key_algorithms.clone(),
        bind_interface: String::new(),
        routing_mark: 0,
        keep_alive_idle: 0,
        keep_alive_interval: 0,
        disable_keep_alive: false,
    })
}

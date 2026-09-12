//! SSH outbound adapter (6J-A TCP + session reuse).

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
    /// Dials `dial_server` (typically a PSN-resolved IP) for the SSH TCP
    /// transport. `bind_interface` / `routing_mark` apply to that socket.
    ///
    /// # Errors
    ///
    /// Returns when the proxy is missing SSH options or key material is invalid.
    pub fn from_proxy_with_dial_server(
        proxy: &ProxyConfig,
        dial_server: &str,
        bind_interface: &str,
        routing_mark: i64,
    ) -> Result<Self, SshProxyError> {
        let mut options = client_options_from_proxy(proxy)?;
        dial_server.clone_into(&mut options.server);
        bind_interface.clone_into(&mut options.bind_interface);
        options.routing_mark = routing_mark;
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
pub fn ssh_adapter_identity(
    proxy: &ProxyConfig,
    dial_server: &str,
    bind_interface: &str,
    routing_mark: i64,
) -> String {
    format!("{dial_server}|{bind_interface}|{routing_mark}|{proxy:?}")
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
    })
}

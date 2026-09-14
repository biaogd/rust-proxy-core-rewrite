use std::borrow::Cow;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use rand::RngExt;
use rewrite_model::Destination;
use rewrite_platform::{OutboundTcpOptions, connect_tcp};
use russh::client::{self, AuthResult, Handle};
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKey, decode_secret_key};
use russh::{Preferred, SshId};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::SshProtocolError;

/// Long-lived SSH client matching Go `adapter/outbound.Ssh` session reuse.
pub struct Client {
    options: ClientOptions,
    session: Mutex<Option<Arc<ConnectedSession>>>,
    shutdown: CancellationToken,
}

const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

struct ConnectedSession {
    handle: Handle<HostKeyHandler>,
    _socket: DisconnectOnDrop,
}

// russh detaches its task during key exchange. Closing the shared transport
// also wakes that task if connect_stream is cancelled before it returns a handle.
struct DisconnectOnDrop(socket2::Socket);

impl Drop for DisconnectOnDrop {
    fn drop(&mut self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Clash `type: ssh` options accepted in 6J-A/B.
#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    /// Inline PEM (`PRIVATE KEY`) or a resolved filesystem path.
    pub private_key: Option<String>,
    pub private_key_passphrase: Option<String>,
    /// `authorized_keys` lines. Empty means insecure-ignore like Go.
    pub host_keys: Vec<String>,
    /// Host-key algorithms offered during negotiation. Empty keeps russh defaults.
    pub host_key_algorithms: Vec<String>,
    pub bind_interface: String,
    pub routing_mark: i64,
    /// Transport-socket keepalive from the global Mihomo dialer, not SSH-level
    /// keepalive. Identity with Go's SSH keepalive packets is not claimed.
    pub keep_alive_idle: i64,
    pub keep_alive_interval: i64,
    pub disable_keep_alive: bool,
}

struct HostKeyHandler {
    allowed: Vec<PublicKey>,
}

impl client::Handler for HostKeyHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        if self.allowed.is_empty() {
            return Ok(true);
        }
        Ok(self
            .allowed
            .iter()
            .any(|allowed| same_public_key(allowed, server_public_key)))
    }
}

impl Client {
    /// Builds a client after validating key material and host-key algorithms.
    ///
    /// # Errors
    ///
    /// Returns when a configured private key, host key, or host-key algorithm
    /// cannot be parsed.
    pub fn new(options: ClientOptions) -> Result<Self, SshProtocolError> {
        validate_material(
            options.private_key.as_deref(),
            options.private_key_passphrase.as_deref(),
            &options.host_keys,
            &options.host_key_algorithms,
        )?;
        Ok(Self {
            options,
            session: Mutex::new(None),
            shutdown: CancellationToken::new(),
        })
    }

    /// Opens a multiplexed `direct-tcpip` stream. Destination failure must not
    /// drop the shared SSH session. A dead transport is replaced on the next
    /// dial without requiring the caller to `close()`.
    ///
    /// # Errors
    ///
    /// Returns handshake, authentication, or channel-open failures.
    pub async fn open_tcp(
        &self,
        destination: &Destination,
    ) -> Result<rewrite_io::BoxedStream, SshProtocolError> {
        self.bounded(async {
            let handle = self.connected_session().await?;
            match open_direct_tcpip(&handle.handle, destination).await {
                Ok(stream) => Ok(stream),
                Err(_) if handle.handle.is_closed() => {
                    let replacement = self.connected_session().await?;
                    open_direct_tcpip(&replacement.handle, destination).await
                }
                Err(error) => Err(error),
            }
        })
        .await
    }

    async fn connected_session(&self) -> Result<Arc<ConnectedSession>, SshProtocolError> {
        let mut guard = self.session.lock().await;
        if let Some(handle) = guard.as_ref().filter(|handle| !handle.handle.is_closed()) {
            return Ok(Arc::clone(handle));
        }
        let handle = Arc::new(self.handshake().await?);
        *guard = Some(Arc::clone(&handle));
        Ok(handle)
    }

    async fn bounded<T>(
        &self,
        operation: impl Future<Output = Result<T, SshProtocolError>>,
    ) -> Result<T, SshProtocolError> {
        tokio::select! {
            biased;
            () = self.shutdown.cancelled() => Err(SshProtocolError::Protocol("SSH client retired".to_owned())),
            result = tokio::time::timeout(OPERATION_TIMEOUT, operation) => result.unwrap_or_else(|_| Err(SshProtocolError::Protocol("SSH operation timed out".to_owned()))),
        }
    }

    /// Disconnects the reused SSH client.
    pub async fn close(&self) {
        self.shutdown.cancel();
        let handle = self.session.lock().await.take();
        if let Some(handle) = handle {
            let _ = tokio::time::timeout(
                OPERATION_TIMEOUT,
                handle.handle.disconnect(
                    russh::Disconnect::ByApplication,
                    "rewrite ssh outbound closed",
                    "",
                ),
            )
            .await;
        }
    }

    async fn handshake(&self) -> Result<ConnectedSession, SshProtocolError> {
        let address = resolve_server(&self.options).await?;
        let config = Arc::new(client::Config {
            nodelay: true,
            client_id: random_openssh_id(),
            inactivity_timeout: None,
            preferred: preferred_host_keys(&self.options.host_key_algorithms)?,
            ..client::Config::default()
        });
        let handler = HostKeyHandler {
            allowed: parse_host_keys(&self.options.host_keys)?,
        };
        let stream = connect_tcp(
            address,
            OutboundTcpOptions {
                interface: &self.options.bind_interface,
                routing_mark: self.options.routing_mark,
                keep_alive_idle: self.options.keep_alive_idle,
                keep_alive_interval: self.options.keep_alive_interval,
                disable_keep_alive: self.options.disable_keep_alive,
            },
        )
        .await?;
        let socket = DisconnectOnDrop(socket2::SockRef::from(&stream).try_clone()?);
        let mut handle = client::connect_stream(config, stream, handler)
            .await
            .map_err(|error| {
                SshProtocolError::Protocol(format!("SSH transport handshake failed: {error}"))
            })?;
        if !authenticate(&mut handle, &self.options).await? {
            return Err(SshProtocolError::Protocol(
                "SSH authentication rejected".to_owned(),
            ));
        }
        Ok(ConnectedSession {
            handle,
            _socket: socket,
        })
    }
}

async fn authenticate(
    handle: &mut Handle<HostKeyHandler>,
    options: &ClientOptions,
) -> Result<bool, SshProtocolError> {
    if let Some(material) = options.private_key.as_deref() {
        let key = load_private_key(material, options.private_key_passphrase.as_deref())?;
        let hash = if key.algorithm().is_rsa() {
            // Match Go's key-format fallback for servers without EXT_INFO;
            // advertised RSA SHA-2 algorithms are preferred when available.
            handle.best_supported_rsa_hash().await?.flatten()
        } else {
            None
        };
        let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
        if matches!(
            handle
                .authenticate_publickey(&options.username, key)
                .await?,
            AuthResult::Success
        ) {
            return Ok(true);
        }
    }
    if let Some(password) = options.password.as_deref() {
        return Ok(matches!(
            handle
                .authenticate_password(&options.username, password)
                .await?,
            AuthResult::Success
        ));
    }
    Ok(false)
}

async fn open_direct_tcpip(
    handle: &Handle<HostKeyHandler>,
    destination: &Destination,
) -> Result<rewrite_io::BoxedStream, SshProtocolError> {
    let host = destination.host.to_string();
    let channel = handle
        .channel_open_direct_tcpip(host, u32::from(destination.port), "127.0.0.1", 0)
        .await
        .map_err(|error| SshProtocolError::Protocol(format!("SSH direct-tcpip failed: {error}")))?;
    Ok(Box::new(channel.into_stream()))
}

async fn resolve_server(options: &ClientOptions) -> Result<SocketAddr, SshProtocolError> {
    if let Ok(ip) = options.server.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, options.port));
    }
    if let Ok(address) = options.server.parse::<SocketAddr>() {
        return Ok(address);
    }
    let mut candidates = tokio::net::lookup_host((options.server.as_str(), options.port)).await?;
    candidates.next().ok_or_else(|| {
        SshProtocolError::Protocol(format!("SSH server {} did not resolve", options.server))
    })
}

fn random_openssh_id() -> SshId {
    let mut rng = rand::rng();
    let version = if rng.random_bool(0.5) {
        format!("OpenSSH_7.{}", rng.random_range(0..10))
    } else {
        format!("OpenSSH_8.{}", rng.random_range(0..9))
    };
    SshId::Standard(format!("SSH-2.0-{version}"))
}

pub(crate) fn same_public_key(left: &PublicKey, right: &PublicKey) -> bool {
    left.key_data() == right.key_data()
}

fn load_private_key(
    material: &str,
    passphrase: Option<&str>,
) -> Result<PrivateKey, SshProtocolError> {
    let pem = if material.contains("PRIVATE KEY") {
        material.to_owned()
    } else {
        std::fs::read_to_string(material)?
    };
    decode_secret_key(&pem, passphrase).map_err(Into::into)
}

fn preferred_host_keys(names: &[String]) -> Result<Preferred, SshProtocolError> {
    if names.is_empty() {
        return Ok(Preferred::DEFAULT);
    }
    let mut key = Vec::with_capacity(names.len());
    for name in names {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(SshProtocolError::Protocol(
                "empty SSH host-key-algorithm".to_owned(),
            ));
        }
        let algorithm = Algorithm::from_str(trimmed).map_err(|error| {
            SshProtocolError::Protocol(format!(
                "unsupported SSH host-key-algorithm {trimmed}: {error}"
            ))
        })?;
        if matches!(algorithm, Algorithm::Other(_)) {
            return Err(SshProtocolError::Protocol(format!(
                "unsupported SSH host-key-algorithm {trimmed}"
            )));
        }
        key.push(algorithm);
    }
    Ok(Preferred {
        key: Cow::Owned(key),
        ..Preferred::DEFAULT
    })
}

pub(crate) fn parse_host_keys(lines: &[String]) -> Result<Vec<PublicKey>, SshProtocolError> {
    lines
        .iter()
        .map(|line| parse_authorized_key(line))
        .collect()
}

/// Validates SSH configuration before accepting a configuration or reload.
///
/// # Errors
///
/// Rejects unreadable/invalid private keys, incorrect passphrases, malformed
/// host keys (including blank/comment entries), and unknown host algorithms.
pub fn validate_material(
    private_key: Option<&str>,
    passphrase: Option<&str>,
    host_keys: &[String],
    algorithms: &[String],
) -> Result<(), SshProtocolError> {
    if let Some(material) = private_key {
        let _ = load_private_key(material, passphrase)?;
    }
    let _ = parse_host_keys(host_keys)?;
    let _ = preferred_host_keys(algorithms)?;
    Ok(())
}

fn parse_authorized_key(line: &str) -> Result<PublicKey, SshProtocolError> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Err(SshProtocolError::Protocol(
            "empty/comment SSH host-key entry".to_owned(),
        ));
    }
    if let Ok(key) = PublicKey::from_openssh(trimmed) {
        return Ok(key);
    }
    let mut parts = trimmed.split_whitespace();
    let _algorithm = parts
        .next()
        .ok_or_else(|| SshProtocolError::Protocol(format!("invalid SSH host-key: {trimmed}")))?;
    let payload = parts
        .next()
        .ok_or_else(|| SshProtocolError::Protocol(format!("invalid SSH host-key: {trimmed}")))?;
    russh::keys::parse_public_key_base64(payload).map_err(Into::into)
}

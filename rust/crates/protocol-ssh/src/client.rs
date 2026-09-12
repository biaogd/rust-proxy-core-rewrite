use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rand::RngExt;
use rewrite_model::Destination;
use rewrite_platform::{OutboundTcpOptions, connect_tcp};
use russh::SshId;
use russh::client::{self, AuthResult, Handle};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, decode_secret_key};
use tokio::sync::Mutex;

use crate::SshProtocolError;

/// Long-lived SSH client matching Go `adapter/outbound.Ssh` session reuse.
pub struct Client {
    options: ClientOptions,
    session: Mutex<Option<Handle<HostKeyHandler>>>,
}

/// Clash `type: ssh` options accepted in 6J-A.
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
    /// Accepted at parse; default russh host-key algorithms are used in 6J-A.
    pub host_key_algorithms: Vec<String>,
    pub bind_interface: String,
    pub routing_mark: i64,
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
            .any(|allowed| allowed == server_public_key))
    }
}

impl Client {
    /// Builds a client after validating key material.
    ///
    /// # Errors
    ///
    /// Returns when a configured private key or host key cannot be parsed.
    pub fn new(options: ClientOptions) -> Result<Self, SshProtocolError> {
        if let Some(material) = options.private_key.as_deref() {
            let _ = load_private_key(material, options.private_key_passphrase.as_deref())?;
        }
        let _ = parse_host_keys(&options.host_keys)?;
        Ok(Self {
            options,
            session: Mutex::new(None),
        })
    }

    /// Opens a multiplexed `direct-tcpip` stream. Destination failure must not
    /// drop the shared SSH session.
    ///
    /// # Errors
    ///
    /// Returns handshake, authentication, or channel-open failures.
    pub async fn open_tcp(
        &self,
        destination: &Destination,
    ) -> Result<rewrite_io::BoxedStream, SshProtocolError> {
        let mut guard = self.session.lock().await;
        if guard.as_ref().is_some_and(Handle::is_closed) {
            *guard = None;
        }
        if guard.is_none() {
            *guard = Some(self.handshake().await?);
        }
        let Some(handle) = guard.as_ref() else {
            return Err(SshProtocolError::Protocol(
                "SSH session was not established".to_owned(),
            ));
        };
        match open_direct_tcpip(handle, destination).await {
            Ok(stream) => Ok(stream),
            Err(error) if session_is_dead(&error) => {
                *guard = Some(self.handshake().await?);
                let Some(handle) = guard.as_ref() else {
                    return Err(SshProtocolError::Protocol(
                        "SSH session was not re-established".to_owned(),
                    ));
                };
                open_direct_tcpip(handle, destination).await
            }
            Err(error) => Err(error),
        }
    }

    /// Disconnects the reused SSH client.
    pub async fn close(&self) {
        let handle = self.session.lock().await.take();
        if let Some(handle) = handle {
            let _ = handle
                .disconnect(
                    russh::Disconnect::ByApplication,
                    "rewrite ssh outbound closed",
                    "",
                )
                .await;
        }
    }

    async fn handshake(&self) -> Result<Handle<HostKeyHandler>, SshProtocolError> {
        let address = resolve_server(&self.options).await?;
        let stream = connect_tcp(
            address,
            OutboundTcpOptions {
                interface: &self.options.bind_interface,
                routing_mark: self.options.routing_mark,
                keep_alive_idle: 0,
                keep_alive_interval: 0,
                disable_keep_alive: false,
            },
        )
        .await?;
        let config = client::Config {
            nodelay: true,
            client_id: random_openssh_id(),
            inactivity_timeout: None,
            ..client::Config::default()
        };
        let handler = HostKeyHandler {
            allowed: parse_host_keys(&self.options.host_keys)?,
        };
        let mut handle = client::connect_stream(Arc::new(config), stream, handler).await?;
        if !authenticate(&mut handle, &self.options).await? {
            return Err(SshProtocolError::Protocol(
                "SSH authentication rejected".to_owned(),
            ));
        }
        Ok(handle)
    }
}

async fn authenticate(
    handle: &mut Handle<HostKeyHandler>,
    options: &ClientOptions,
) -> Result<bool, SshProtocolError> {
    if let Some(material) = options.private_key.as_deref() {
        let key = load_private_key(material, options.private_key_passphrase.as_deref())?;
        let key = PrivateKeyWithHashAlg::new(Arc::new(key), None);
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
        .await?;
    Ok(Box::new(channel.into_stream()))
}

fn session_is_dead(error: &SshProtocolError) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("disconnect")
        || text.contains("not authenticated")
        || text.contains("connection reset")
        || text.contains("broken pipe")
        || text.contains("eof")
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
    SshId::Standard(version)
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

pub(crate) fn parse_host_keys(lines: &[String]) -> Result<Vec<PublicKey>, SshProtocolError> {
    lines
        .iter()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .map(|line| parse_authorized_key(line))
        .collect()
}

fn parse_authorized_key(line: &str) -> Result<PublicKey, SshProtocolError> {
    let trimmed = line.trim();
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

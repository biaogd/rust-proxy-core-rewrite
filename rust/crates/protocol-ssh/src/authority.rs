//! In-process / CLI SSH authority used by 6J tests. This is not an inbound.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Auth, Handler, Msg, Session};
use russh::{Channel, Disconnect, MethodKind, MethodSet};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};

use crate::SshProtocolError;
use crate::client::parse_host_keys;

/// Password and/or public-key credentials accepted by the test authority.
#[derive(Clone, Debug)]
pub struct AuthorityOptions {
    pub username: String,
    pub password: Option<String>,
    pub authorized_keys: Vec<String>,
}

struct ClientHandler {
    username: String,
    password: Option<String>,
    authorized: Vec<PublicKey>,
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == self.username
            && self
                .password
                .as_deref()
                .is_some_and(|expected| expected == password)
        {
            Ok(Auth::Accept)
        } else {
            Ok(reject())
        }
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if user == self.username
            && self
                .authorized
                .iter()
                .any(|allowed| crate::client::same_public_key(allowed, public_key))
        {
            Ok(Auth::Accept)
        } else {
            Ok(reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.auth_publickey_offered(user, public_key).await
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let dest = match u16::try_from(port_to_connect) {
            Ok(port) => format!("{host_to_connect}:{port}"),
            Err(_) => return Ok(false),
        };
        tokio::spawn(async move {
            let Ok(mut tcp) = TcpStream::connect(&dest).await else {
                return;
            };
            let mut stream = channel.into_stream();
            let _ = copy_bidirectional(&mut stream, &mut tcp).await;
        });
        Ok(true)
    }
}

fn reject() -> Auth {
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);
    methods.push(MethodKind::PublicKey);
    Auth::Reject {
        proceed_with_methods: Some(methods),
        partial_success: false,
    }
}

/// In-process SSH `direct-tcpip` authority for crate tests and differentials.
///
/// Dropping or calling [`TestAuthority::shutdown`] aborts the accept loop and
/// every live session so the listen port can be rebound.
pub struct TestAuthority {
    /// Bound listen address, including the ephemeral port.
    pub listen: SocketAddr,
    /// OpenSSH `authorized_keys` line for the generated host key.
    pub host_key: String,
    accept: tokio::task::AbortHandle,
    sessions: Arc<Mutex<Vec<server::Handle>>>,
}

impl TestAuthority {
    /// Stops accepting and disconnects in-flight sessions.
    ///
    /// Aborting the accept task alone is not enough: russh
    /// `RunningSession` detaches its join handle on drop, so live
    /// sessions must be disconnected explicitly.
    pub fn shutdown(&self) {
        self.accept.abort();
        let handles = {
            let mut sessions = self
                .sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *sessions)
        };
        for handle in handles {
            tokio::spawn(async move {
                let _ = handle
                    .disconnect(
                        Disconnect::ByApplication,
                        "rewrite ssh authority stopped".to_owned(),
                        String::new(),
                    )
                    .await;
            });
        }
    }
}

impl Drop for TestAuthority {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Binds `listen` and serves SSH `direct-tcpip` for tests / differentials.
///
/// # Errors
///
/// Returns when the listen socket, host key, or authorized keys fail.
pub async fn spawn_authority(
    listen: SocketAddr,
    options: AuthorityOptions,
) -> Result<TestAuthority, SshProtocolError> {
    let listener = TcpListener::bind(listen).await?;
    let bound = listener.local_addr()?;
    let host_key = generate_host_key()?;
    let host_key_openssh = host_key
        .public_key()
        .to_openssh()
        .map_err(|error| SshProtocolError::Protocol(error.to_string()))?;
    let authorized = parse_host_keys(&options.authorized_keys)?;
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);
    methods.push(MethodKind::PublicKey);
    let config = Arc::new(server::Config {
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![host_key],
        methods,
        ..server::Config::default()
    });
    let options = Arc::new(options);
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let session_handles = Arc::clone(&sessions);
    let accept = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let handler = ClientHandler {
                username: options.username.clone(),
                password: options.password.clone(),
                authorized: authorized.clone(),
            };
            let config = Arc::clone(&config);
            let session_handles = Arc::clone(&session_handles);
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, stream, handler).await {
                    session_handles
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(running.handle());
                    let _ = running.await;
                }
            });
        }
    });
    Ok(TestAuthority {
        listen: bound,
        host_key: host_key_openssh,
        accept: accept.abort_handle(),
        sessions,
    })
}

fn generate_host_key() -> Result<PrivateKey, SshProtocolError> {
    PrivateKey::random(
        &mut russh::keys::ssh_key::rand_core::OsRng,
        Algorithm::Ed25519,
    )
    .map_err(|error| SshProtocolError::Protocol(error.to_string()))
}

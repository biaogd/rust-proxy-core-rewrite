//! In-process / CLI SSH authority used by 6J-A tests. This is not an inbound.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Auth, Handler, Msg, Session};
use russh::{Channel, MethodKind, MethodSet};
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
        if user == self.username && self.authorized.iter().any(|allowed| allowed == public_key) {
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

/// Binds `listen` and serves SSH `direct-tcpip` for tests / differentials.
///
/// # Errors
///
/// Returns when the listen socket, host key, or authorized keys fail.
pub async fn spawn_authority(
    listen: SocketAddr,
    options: AuthorityOptions,
) -> Result<(SocketAddr, String), SshProtocolError> {
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
    tokio::spawn(async move {
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
            tokio::spawn(async move {
                let _ = server::run_stream(config, stream, handler).await;
            });
        }
    });
    Ok((bound, host_key_openssh))
}

fn generate_host_key() -> Result<PrivateKey, SshProtocolError> {
    PrivateKey::random(
        &mut russh::keys::ssh_key::rand_core::OsRng,
        Algorithm::Ed25519,
    )
    .map_err(|error| SshProtocolError::Protocol(error.to_string()))
}

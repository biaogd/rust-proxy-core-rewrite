//! TUIC v5 outbound session: QUIC/TLS, uni-stream auth, bidi TCP Connect.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rewrite_io::BoxedStream;
use rewrite_model::Destination;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::TuicProtocolError;
use crate::protocol::encode_authenticate;
use crate::stream::TuicStream;
use crate::tls::build_endpoint;

/// TLS options for the TUIC QUIC dial.
#[derive(Clone, Debug)]
pub struct TlsOptions {
    pub server_name: String,
    pub skip_certificate_verification: bool,
    pub alpn: Vec<String>,
    pub custom_roots: Vec<String>,
}

/// Named congestion controllers accepted in 6H-A. Algorithm bytes are not
/// claimed to match Go's quic-go Cubic/BBR implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CongestionController {
    Cubic,
    NewReno,
    Bbr,
}

/// Client construction options (6H-A TCP).
#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub password: String,
    pub tls: TlsOptions,
    pub congestion: CongestionController,
    pub request_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub max_open_streams: u64,
    pub stream_receive_window: Option<u64>,
    pub connection_receive_window: Option<u64>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 443,
            uuid: Uuid::nil(),
            password: String::new(),
            tls: TlsOptions {
                server_name: String::new(),
                skip_certificate_verification: false,
                alpn: vec!["h3".to_owned()],
                custom_roots: Vec::new(),
            },
            congestion: CongestionController::Cubic,
            request_timeout: Duration::from_secs(8),
            heartbeat_interval: Duration::from_secs(10),
            max_open_streams: 90,
            stream_receive_window: None,
            connection_receive_window: None,
        }
    }
}

struct SessionInner {
    connection: quinn::Connection,
    closed: AtomicBool,
}

/// Long-lived TUIC v5 client with one reusable QUIC connection.
pub struct Client {
    options: ClientOptions,
    inner: Mutex<ClientState>,
}

struct ClientState {
    endpoint: Option<quinn::Endpoint>,
    session: Option<Arc<SessionInner>>,
}

impl Client {
    /// # Errors
    ///
    /// Returns when UUID/password options are structurally unusable.
    pub fn new(options: ClientOptions) -> Result<Self, TuicProtocolError> {
        if options.server.is_empty() {
            return Err(TuicProtocolError::Protocol(
                "TUIC server is required".to_owned(),
            ));
        }
        if options.port == 0 {
            return Err(TuicProtocolError::Protocol(
                "TUIC port is required".to_owned(),
            ));
        }
        Ok(Self {
            options,
            inner: Mutex::new(ClientState {
                endpoint: None,
                session: None,
            }),
        })
    }

    /// Opens a proxied TCP stream to `destination`.
    ///
    /// # Errors
    ///
    /// Returns dial, TLS, authentication or stream-open failures.
    pub async fn open_tcp(
        &self,
        destination: &Destination,
    ) -> Result<BoxedStream, TuicProtocolError> {
        let timeout = self.options.request_timeout;
        let open = async {
            let session = self.session().await?;
            if session.closed.load(Ordering::Acquire) || session.connection.close_reason().is_some()
            {
                self.invalidate().await;
                let session = self.session().await?;
                let stream = TuicStream::open(&session.connection, destination).await?;
                return Ok(Box::new(stream) as BoxedStream);
            }
            match TuicStream::open(&session.connection, destination).await {
                Ok(stream) => Ok(Box::new(stream) as BoxedStream),
                Err(error) => {
                    self.invalidate().await;
                    Err(error)
                }
            }
        };
        tokio::time::timeout(timeout, open)
            .await
            .map_err(|_| TuicProtocolError::Protocol("TUIC request timed out".to_owned()))?
    }

    pub async fn close(&self) {
        let mut state = self.inner.lock().await;
        if let Some(session) = state.session.take() {
            session.closed.store(true, Ordering::Release);
            session
                .connection
                .close(0xffff_fff0_u32.into(), b"TUIC client closed");
        }
        if let Some(endpoint) = state.endpoint.take() {
            endpoint.close(0_u32.into(), b"TUIC client closed");
        }
    }

    async fn invalidate(&self) {
        let mut state = self.inner.lock().await;
        if let Some(session) = state.session.take() {
            session.closed.store(true, Ordering::Release);
            if session.connection.close_reason().is_none() {
                session
                    .connection
                    .close(0xffff_fff0_u32.into(), b"TUIC session reset");
            }
        }
    }

    async fn session(&self) -> Result<Arc<SessionInner>, TuicProtocolError> {
        let mut state = self.inner.lock().await;
        if let Some(session) = &state.session
            && !session.closed.load(Ordering::Acquire)
            && session.connection.close_reason().is_none()
        {
            return Ok(Arc::clone(session));
        }
        state.session = None;
        self.dial_locked(&mut state).await
    }

    async fn dial_locked(
        &self,
        state: &mut ClientState,
    ) -> Result<Arc<SessionInner>, TuicProtocolError> {
        let address = resolve_server(&self.options.server, self.options.port).await?;
        let bind = unspecified_bind(address);
        if state.endpoint.is_none() {
            state.endpoint = Some(build_endpoint(&self.options, bind)?);
        }
        let endpoint = state.endpoint.as_ref().ok_or_else(|| {
            TuicProtocolError::Protocol("TUIC endpoint missing after construction".to_owned())
        })?;
        let server_name = if self.options.tls.server_name.is_empty() {
            "localhost".to_owned()
        } else {
            self.options.tls.server_name.clone()
        };
        let connecting = endpoint
            .connect(address, &server_name)
            .map_err(|error| TuicProtocolError::Quinn(error.to_string()))?;
        let connection = connecting.await?;
        authenticate(&connection, self.options.uuid, &self.options.password).await?;
        spawn_datagram_drain(connection.clone());
        let session = Arc::new(SessionInner {
            connection,
            closed: AtomicBool::new(false),
        });
        state.session = Some(Arc::clone(&session));
        Ok(session)
    }
}

async fn authenticate(
    connection: &quinn::Connection,
    uuid: Uuid,
    password: &str,
) -> Result<(), TuicProtocolError> {
    let mut token = [0_u8; 32];
    connection
        .export_keying_material(&mut token, uuid.as_bytes(), password.as_bytes())
        .map_err(|error| TuicProtocolError::Protocol(format!("TLS exporter failed: {error:?}")))?;
    let mut stream = connection.open_uni().await?;
    stream
        .write_all(&encode_authenticate(*uuid.as_bytes(), token))
        .await
        .map_err(|error| TuicProtocolError::Io(std::io::Error::other(error.to_string())))?;
    stream
        .finish()
        .map_err(|error| TuicProtocolError::Io(std::io::Error::other(error.to_string())))?;
    Ok(())
}

fn spawn_datagram_drain(connection: quinn::Connection) {
    tokio::spawn(async move {
        loop {
            if connection.read_datagram().await.is_err() {
                break;
            }
        }
    });
}

async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr, TuicProtocolError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(TuicProtocolError::Io)?;
    addresses
        .next()
        .ok_or_else(|| TuicProtocolError::Protocol(format!("failed to resolve TUIC server {host}")))
}

fn unspecified_bind(address: SocketAddr) -> SocketAddr {
    if address.is_ipv6() {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    }
}

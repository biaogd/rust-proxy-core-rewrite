//! TUIC v5 outbound session: QUIC/TLS, uni-stream auth, bidi TCP Connect.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rewrite_io::BoxedStream;
use rewrite_model::Destination;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::TuicProtocolError;
use crate::lease::StreamLease;
use crate::protocol::{compute_max_udp_relay_packet_size, encode_authenticate, encode_heartbeat};
use crate::stream::TuicStream;
use crate::tls::build_endpoint;
use crate::udp::{UdpHub, UdpRelayMode, UdpSession};

const IDLE_POOL_TTL: Duration = Duration::from_mins(30);

/// TLS options for the TUIC QUIC dial.
#[derive(Clone, Debug)]
pub struct TlsOptions {
    pub server_name: String,
    pub skip_certificate_verification: bool,
    /// When set, rustls omits the SNI extension (`enable_sni = false`). Quinn
    /// still needs a dummy `ServerName` for the connect API.
    pub disable_sni: bool,
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
    /// v4-only in Go. Zero means do not wrap v5 `open_tcp` / `open_udp`.
    pub request_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub max_open_streams: u64,
    pub stream_receive_window: Option<u64>,
    pub connection_receive_window: Option<u64>,
    pub udp_relay_mode: UdpRelayMode,
    pub max_udp_relay_packet_size: usize,
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
                disable_sni: false,
                alpn: vec!["h3".to_owned()],
                custom_roots: Vec::new(),
            },
            congestion: CongestionController::Cubic,
            request_timeout: Duration::ZERO,
            heartbeat_interval: Duration::from_secs(10),
            max_open_streams: 90,
            stream_receive_window: None,
            connection_receive_window: None,
            udp_relay_mode: UdpRelayMode::Native,
            max_udp_relay_packet_size: compute_max_udp_relay_packet_size(0),
        }
    }
}

struct SessionInner {
    connection: quinn::Connection,
    closed: AtomicBool,
    udp: Arc<UdpHub>,
    open_streams: Arc<AtomicU64>,
    last_visited: std::sync::Mutex<Instant>,
}

impl SessionInner {
    fn live(&self) -> bool {
        !self.closed.load(Ordering::Acquire) && self.connection.close_reason().is_none()
    }

    fn touch(&self) {
        if let Ok(mut visited) = self.last_visited.lock() {
            *visited = Instant::now();
        }
    }

    fn last_visited_at(&self) -> Instant {
        self.last_visited
            .lock()
            .map_or_else(|poisoned| *poisoned.into_inner(), |guard| *guard)
    }

    /// Go `openStreams.Add(1)` then `>= MaxOpenStreams` rollback.
    fn try_reserve(&self, max_open_streams: u64) -> Option<StreamLease> {
        let next = self.open_streams.fetch_add(1, Ordering::AcqRel) + 1;
        if next >= max_open_streams {
            self.open_streams.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        self.touch();
        Some(StreamLease::new(Arc::clone(&self.open_streams)))
    }

    fn invalidate(&self) {
        self.closed.store(true, Ordering::Release);
        if self.connection.close_reason().is_none() {
            self.connection
                .close(0xffff_fff0_u32.into(), b"TUIC session reset");
        }
    }
}

/// Long-lived TUIC v5 client with a Go-style pool of QUIC connections.
pub struct Client {
    options: ClientOptions,
    inner: Mutex<ClientState>,
}

struct ClientState {
    endpoint: Option<quinn::Endpoint>,
    sessions: Vec<Arc<SessionInner>>,
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
                sessions: Vec::new(),
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
        let max_open_streams = self.options.max_open_streams.max(1);
        let open = async {
            let mut last_error = None;
            for _ in 0..3_u8 {
                let (session, lease) = self.reserve_session(max_open_streams).await?;
                match TuicStream::open(&session.connection, destination, lease).await {
                    Ok(stream) => return Ok(Box::new(stream) as BoxedStream),
                    Err(error) => {
                        session.invalidate();
                        last_error = Some(error);
                    }
                }
            }
            Err(last_error
                .unwrap_or_else(|| TuicProtocolError::Protocol("TUIC TCP dial failed".to_owned())))
        };
        maybe_timeout(timeout, open).await
    }

    /// Opens a UDP association (`ASSOC_ID`) on the shared QUIC connection.
    ///
    /// # Errors
    ///
    /// Returns dial, TLS, authentication or association-allocation failures.
    pub async fn open_udp(&self) -> Result<UdpSession, TuicProtocolError> {
        let timeout = self.options.request_timeout;
        let max_open_streams = self.options.max_open_streams.max(1);
        let open = async {
            let mut last_error = None;
            for _ in 0..3_u8 {
                let (session, lease) = self.reserve_session(max_open_streams).await?;
                match session.udp.open_session() {
                    Ok(mut udp) => {
                        udp.attach_lease(lease);
                        return Ok(udp);
                    }
                    Err(error) => {
                        lease.release_now();
                        session.invalidate();
                        last_error = Some(error);
                    }
                }
            }
            Err(last_error.unwrap_or_else(|| {
                TuicProtocolError::Protocol("TUIC UDP association failed".to_owned())
            }))
        };
        maybe_timeout(timeout, open).await
    }

    pub async fn close(&self) {
        let mut state = self.inner.lock().await;
        for session in state.sessions.drain(..) {
            session.closed.store(true, Ordering::Release);
            session
                .connection
                .close(0xffff_fff0_u32.into(), b"TUIC client closed");
        }
        if let Some(endpoint) = state.endpoint.take() {
            endpoint.close(0_u32.into(), b"TUIC client closed");
        }
    }

    async fn reserve_session(
        &self,
        max_open_streams: u64,
    ) -> Result<(Arc<SessionInner>, StreamLease), TuicProtocolError> {
        let mut state = self.inner.lock().await;
        prune_sessions(&mut state.sessions);
        let mut best: Option<Arc<SessionInner>> = None;
        for session in &state.sessions {
            if !session.live() {
                continue;
            }
            let current = session.open_streams.load(Ordering::Acquire);
            let best_load = best
                .as_ref()
                .map_or(u64::MAX, |item| item.open_streams.load(Ordering::Acquire));
            if current < best_load {
                best = Some(Arc::clone(session));
            }
        }
        if let Some(session) = best
            && let Some(lease) = session.try_reserve(max_open_streams)
        {
            return Ok((session, lease));
        }
        let session = self.dial_locked(&mut state).await?;
        let lease = session
            .try_reserve(max_open_streams)
            .ok_or_else(|| TuicProtocolError::Protocol("TUIC too many open streams".to_owned()))?;
        Ok((session, lease))
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
        // rustls `ServerName` cannot be empty. When SNI is disabled the dummy
        // name is not written into ClientHello (`TlsOptions.disable_sni`).
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
        let udp = UdpHub::new(
            connection.clone(),
            self.options.udp_relay_mode,
            self.options.max_udp_relay_packet_size,
        );
        spawn_heartbeat(connection.clone(), self.options.heartbeat_interval);
        let session = Arc::new(SessionInner {
            connection,
            closed: AtomicBool::new(false),
            udp,
            open_streams: Arc::new(AtomicU64::new(0)),
            last_visited: std::sync::Mutex::new(Instant::now()),
        });
        state.sessions.push(Arc::clone(&session));
        Ok(session)
    }
}

async fn maybe_timeout<T>(
    timeout: Duration,
    fut: impl std::future::Future<Output = Result<T, TuicProtocolError>>,
) -> Result<T, TuicProtocolError> {
    if timeout.is_zero() {
        fut.await
    } else {
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| TuicProtocolError::Protocol("TUIC request timed out".to_owned()))?
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

fn spawn_heartbeat(connection: quinn::Connection, interval: Duration) {
    if interval.is_zero() {
        return;
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if connection.close_reason().is_some() {
                break;
            }
            if connection
                .send_datagram(Bytes::from(encode_heartbeat()))
                .is_err()
            {
                break;
            }
        }
    });
}

fn prune_sessions(sessions: &mut Vec<Arc<SessionInner>>) {
    let now = Instant::now();
    sessions.retain(|session| {
        if !session.live() {
            return false;
        }
        let idle = session.open_streams.load(Ordering::Acquire) == 0
            && now.saturating_duration_since(session.last_visited_at()) > IDLE_POOL_TTL;
        if idle {
            session.invalidate();
            false
        } else {
            true
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

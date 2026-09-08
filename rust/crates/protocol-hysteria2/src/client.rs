//! Session client with QUIC connection reuse (HY2-A/B).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use quinn::congestion::BbrConfig;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{AsyncUdpSocket, EndpointConfig, Runtime, TokioRuntime};
use rewrite_io::BoxedStream;
use rewrite_model::Destination;
use tokio::sync::Mutex;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{
    WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};

use crate::auth;
use crate::congestion::{BrutalControl, SwitchableFactory};
use crate::salamander::{MIN_PSK_LEN, Salamander};
use crate::socket::{HopConfig, ObfsHopSocket};
use crate::tcp::Hysteria2Stream;
use crate::udp::{MAX_DATAGRAM_FRAME_SIZE, UdpSession, UdpSessionManager};
use crate::{
    DEFAULT_CONN_RECEIVE_WINDOW, DEFAULT_KEEP_ALIVE_PERIOD, DEFAULT_MAX_IDLE_TIMEOUT,
    DEFAULT_STREAM_RECEIVE_WINDOW, Hysteria2ProtocolError,
};

/// Default hop interval when unset (Go: 30s).
const DEFAULT_HOP_INTERVAL_SECS: u64 = 30;
/// Minimum hop interval (Go floor: 5s).
const MIN_HOP_INTERVAL_SECS: u64 = 5;
/// Default UDP MTU when unset (quic-go `MaxDatagramSize` − 3).
const DEFAULT_UDP_MTU: u16 = 1197;

/// TLS options for the Hysteria2 QUIC dial.
#[derive(Clone, Debug)]
pub struct TlsOptions {
    pub server_name: String,
    pub skip_certificate_verification: bool,
    pub alpn: Vec<String>,
    pub custom_roots: Vec<String>,
}

/// Client construction options (HY2-A + HY2-B).
#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub tls: TlsOptions,
    /// When true, each dial opens an independent QUIC session and does not
    /// close or replace any prior live session (concurrent connections OK).
    pub disable_reuse: bool,
    /// Upload bandwidth (bytes/sec). `0` → stock BBR.
    pub up_bps: u64,
    /// Download bandwidth reported as `Hysteria-CC-RX` (bytes/sec). `0` → auto.
    pub down_bps: u64,
    /// Salamander PSK; empty disables.
    pub obfs_password: String,
    /// Extra hop ports (same host). Empty → single `port`.
    pub hop_ports: Vec<u16>,
    /// Hop interval range in seconds (`0` → default 30s).
    pub hop_interval_min_secs: u64,
    pub hop_interval_max_secs: u64,
    /// QUIC datagram payload budget (fragmentation threshold).
    pub udp_mtu: u16,
    /// QUIC connect + HTTP/3 `/auth` budget (covers the full dial, not just TLS).
    pub handshake_timeout: Duration,
    /// Optional stream receive window override.
    pub stream_receive_window: Option<u64>,
    /// Optional connection receive window override.
    pub connection_receive_window: Option<u64>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 443,
            password: String::new(),
            tls: TlsOptions {
                server_name: String::new(),
                skip_certificate_verification: false,
                alpn: vec!["h3".to_owned()],
                custom_roots: Vec::new(),
            },
            disable_reuse: false,
            up_bps: 0,
            down_bps: 0,
            obfs_password: String::new(),
            hop_ports: Vec::new(),
            hop_interval_min_secs: 0,
            hop_interval_max_secs: 0,
            udp_mtu: DEFAULT_UDP_MTU,
            handshake_timeout: Duration::from_secs(10),
            stream_receive_window: None,
            connection_receive_window: None,
        }
    }
}

struct SessionInner {
    connection: quinn::Connection,
    closed: AtomicBool,
    /// `disable-reuse` dials are not stored on [`Client`]; the last Session Arc
    /// (held by a TCP/UDP business user) must close the QUIC connection.
    independent: bool,
    udp_enabled: bool,
    udp: Option<Arc<UdpSessionManager>>,
    udp_mtu: usize,
    #[allow(dead_code)] // retained for future live Brutal rate introspection
    brutal: Option<BrutalControl>,
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        // Always abort the UDP recv task — weak-ref checks after datagrams are
        // not enough (TCP-only / idle associations never wake the loop).
        if let Some(udp) = self.udp.take() {
            udp.shutdown();
        }
        if self.independent && !self.closed.load(Ordering::Acquire) {
            self.closed.store(true, Ordering::Release);
            self.connection
                .close(0_u32.into(), b"Hysteria2 session closed");
        }
    }
}

/// Authenticated Hysteria2 QUIC session.
#[derive(Clone)]
pub struct Session {
    inner: Arc<SessionInner>,
}

impl Session {
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire) || self.inner.connection.close_reason().is_some()
    }

    #[must_use]
    pub fn is_independent(&self) -> bool {
        self.inner.independent
    }

    #[must_use]
    pub fn udp_enabled(&self) -> bool {
        self.inner.udp_enabled
    }

    pub(crate) fn mark_closed(&self) {
        self.inner.closed.store(true, Ordering::Release);
    }

    /// Opens a TCP proxy stream to `destination`.
    ///
    /// # Errors
    ///
    /// Returns when the session is closed or the Hysteria2 TCP handshake fails.
    pub async fn open_tcp(
        &self,
        destination: &Destination,
    ) -> Result<Hysteria2Stream, Hysteria2ProtocolError> {
        if self.is_closed() {
            return Err(Hysteria2ProtocolError::Protocol(
                "Hysteria2 session is closed".to_owned(),
            ));
        }
        match Hysteria2Stream::open(&self.inner.connection, destination).await {
            Ok(stream) => Ok(stream),
            Err(error) => {
                if matches!(
                    &error,
                    Hysteria2ProtocolError::Quinn(_) | Hysteria2ProtocolError::Io(_)
                ) {
                    self.mark_closed();
                }
                Err(error)
            }
        }
    }

    /// Opens a UDP relay session on this QUIC connection.
    ///
    /// # Errors
    ///
    /// Returns when UDP was not advertised or the session budget is exhausted.
    pub fn open_udp(&self) -> Result<UdpSession, Hysteria2ProtocolError> {
        if self.is_closed() {
            return Err(Hysteria2ProtocolError::Protocol(
                "Hysteria2 session is closed".to_owned(),
            ));
        }
        let Some(manager) = self.inner.udp.as_ref() else {
            return Err(Hysteria2ProtocolError::Protocol(
                "UDP relay not enabled by server".to_owned(),
            ));
        };
        manager.new_session(&self.inner.connection, self.inner.udp_mtu)
    }

    /// Closes the underlying QUIC connection and aborts the UDP recv task.
    pub fn close(&self) {
        self.mark_closed();
        if let Some(udp) = &self.inner.udp {
            udp.shutdown();
        }
        self.inner
            .connection
            .close(0_u32.into(), b"Hysteria2 session closed");
    }
}

/// Keeps an independent [`Session`] alive for the lifetime of a TCP stream so
/// the last business-user drop closes QUIC (and aborts the UDP recv task).
struct SessionBoundTcp {
    inner: Hysteria2Stream,
    _session: Session,
}

impl tokio::io::AsyncRead for SessionBoundTcp {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for SessionBoundTcp {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Fingerprint of the path baked into a Quinn endpoint's hop/obfs socket.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EndpointPathKey {
    canonical: SocketAddr,
    hop_addrs: Vec<SocketAddr>,
}

impl EndpointPathKey {
    fn new(canonical: SocketAddr, hop: Option<&HopConfig>) -> Self {
        let hop_addrs = hop.map_or_else(|| vec![canonical], |cfg| cfg.addrs.clone());
        Self {
            canonical,
            hop_addrs,
        }
    }
}

struct CachedEndpoint {
    endpoint: quinn::Endpoint,
    path: EndpointPathKey,
}

/// Long-lived Hysteria2 client with optional session reuse.
pub struct Client {
    options: ClientOptions,
    session: Mutex<Option<Session>>,
    endpoint: Mutex<Option<CachedEndpoint>>,
    /// When Brutal is enabled, dial installs a fresh control into this slot
    /// before `connect` so each QUIC connection gets independent negotiation.
    brutal_next: Option<Arc<std::sync::Mutex<Option<BrutalControl>>>>,
    /// Serializes Brutal slot install + connect so concurrent disable-reuse
    /// dials cannot steal each other's controls.
    brutal_dial: Mutex<()>,
}

impl Client {
    /// # Errors
    ///
    /// Returns when Salamander PSK is too short.
    pub fn new(options: ClientOptions) -> Result<Self, Hysteria2ProtocolError> {
        if !options.obfs_password.is_empty() && options.obfs_password.len() < MIN_PSK_LEN {
            return Err(Hysteria2ProtocolError::Protocol(format!(
                "salamander password must be at least {MIN_PSK_LEN} bytes"
            )));
        }
        let brutal_next = if options.up_bps > 0 {
            Some(Arc::new(std::sync::Mutex::new(None)))
        } else {
            None
        };
        Ok(Self {
            options,
            session: Mutex::new(None),
            endpoint: Mutex::new(None),
            brutal_next,
            brutal_dial: Mutex::new(()),
        })
    }

    /// Opens a TCP stream, reusing a live session when allowed.
    ///
    /// # Errors
    ///
    /// Returns dial, auth, or TCP framing failures from the underlying session.
    pub async fn open_tcp(
        &self,
        destination: &Destination,
    ) -> Result<BoxedStream, Hysteria2ProtocolError> {
        match self.open_tcp_once(destination).await {
            Ok(stream) => Ok(stream),
            Err(first) => {
                // Dead or raced session after peer loss — drop and redial once.
                self.invalidate().await;
                self.open_tcp_once(destination).await.map_err(|_| first)
            }
        }
    }

    async fn open_tcp_once(
        &self,
        destination: &Destination,
    ) -> Result<BoxedStream, Hysteria2ProtocolError> {
        let session = self.offer_session().await?;
        let stream = match session.open_tcp(destination).await {
            Ok(stream) => stream,
            Err(error) => {
                // Independent dial with no surviving business user: drop closes.
                return Err(error);
            }
        };
        if session.is_independent() {
            // Retain Session for the stream lifetime so QUIC + UDP recv abort
            // when the last business user exits.
            Ok(Box::new(SessionBoundTcp {
                inner: stream,
                _session: session,
            }))
        } else {
            Ok(Box::new(stream))
        }
    }

    /// Opens a UDP association, reusing a live session when allowed.
    ///
    /// # Errors
    ///
    /// Returns dial/auth failures or when the server disabled UDP.
    pub async fn open_udp(&self) -> Result<UdpSession, Hysteria2ProtocolError> {
        let session = self.offer_session().await?;
        let mut udp = session.open_udp()?;
        // Keep the Session (and thus QUIC + manager) alive for disable-reuse;
        // last Arc drop closes the independent connection.
        udp.retain_owner(session);
        Ok(udp)
    }

    /// Forces the next dial to open a fresh QUIC session.
    pub async fn invalidate(&self) {
        let mut guard = self.session.lock().await;
        if let Some(session) = guard.take() {
            session.close();
        }
    }

    pub async fn close(&self) {
        self.invalidate().await;
        let mut endpoint = self.endpoint.lock().await;
        if let Some(cached) = endpoint.take() {
            cached
                .endpoint
                .close(0_u32.into(), b"Hysteria2 client closed");
        }
    }

    async fn offer_session(&self) -> Result<Session, Hysteria2ProtocolError> {
        if !self.options.disable_reuse {
            let guard = self.session.lock().await;
            if let Some(session) = guard.as_ref()
                && !session.is_closed()
            {
                return Ok(session.clone());
            }
        }
        let session = self.dial_session().await?;
        if self.options.disable_reuse {
            // Independent concurrent connections: do not store or close peers.
            return Ok(session);
        }
        let mut guard = self.session.lock().await;
        if let Some(existing) = guard.as_ref()
            && !existing.is_closed()
        {
            session.close();
            return Ok(existing.clone());
        }
        if let Some(previous) = guard.replace(session.clone()) {
            previous.close();
        }
        Ok(session)
    }

    async fn dial_session(&self) -> Result<Session, Hysteria2ProtocolError> {
        // Full connect+auth must honor handshake-timeout (and cancel via drop).
        match tokio::time::timeout(self.options.handshake_timeout, self.dial_session_inner()).await
        {
            Ok(result) => result,
            Err(_) => Err(Hysteria2ProtocolError::Quinn(
                "handshake timed out".to_owned(),
            )),
        }
    }

    async fn dial_session_inner(&self) -> Result<Session, Hysteria2ProtocolError> {
        // Hold across install+connect so concurrent dials cannot swap controls.
        let brutal_dial_guard = if self.brutal_next.is_some() {
            Some(self.brutal_dial.lock().await)
        } else {
            None
        };

        // Fresh Brutal controls per dial — do not inherit a prior connection's
        // CC-RX: auto flip or clamped rate.
        let brutal = self.brutal_next.as_ref().map(|slot| {
            let control = (
                Arc::new(AtomicU64::new(self.options.up_bps)),
                Arc::new(AtomicBool::new(false)),
            );
            *slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(control.clone());
            control
        });

        let (canonical, hop) = resolve_endpoint(&self.options).await?;
        let endpoint = self.endpoint(canonical, hop).await?;
        let connecting = endpoint.connect(canonical, &self.options.tls.server_name)?;
        let connection = connecting
            .await
            .map_err(|error| Hysteria2ProtocolError::Quinn(format!("handshake failed: {error}")))?;
        // Slot consumed by the congestion factory during connect; release dial lock.
        drop(brutal_dial_guard);

        // Close the QUIC connection if auth / post-setup is cancelled (timeout
        // drop) or fails — Quinn does not CONNECTION_CLOSE on handle drop.
        let mut guard = HandshakeConnGuard(Some(connection.clone()));

        let auth = auth::authenticate(
            connection.clone(),
            &self.options.password,
            self.options.down_bps,
        )
        .await
        .map_err(|error| Hysteria2ProtocolError::Protocol(format!("auth failed: {error}")))?;

        if let Some((rate, use_bbr)) = &brutal {
            // Apply the full negotiation outcome for this connection only.
            if auth.rx_auto {
                use_bbr.store(true, Ordering::Relaxed);
            } else {
                use_bbr.store(false, Ordering::Relaxed);
                if auth.rx > 0 {
                    rate.store(self.options.up_bps.min(auth.rx), Ordering::Relaxed);
                } else {
                    // Server advertised no numeric Rx — keep configured up.
                    rate.store(self.options.up_bps, Ordering::Relaxed);
                }
            }
        }

        let udp = if auth.udp_enabled {
            Some(UdpSessionManager::new(connection.clone()))
        } else {
            None
        };
        let udp_mtu = usize::from(self.options.udp_mtu.max(64));

        // Disarm the abort-on-drop guard — session now owns the connection.
        guard.0.take();

        Ok(Session {
            inner: Arc::new(SessionInner {
                connection,
                closed: AtomicBool::new(false),
                independent: self.options.disable_reuse,
                udp_enabled: auth.udp_enabled,
                udp,
                udp_mtu,
                brutal,
            }),
        })
    }

    async fn endpoint(
        &self,
        canonical: SocketAddr,
        hop: Option<HopConfig>,
    ) -> Result<quinn::Endpoint, Hysteria2ProtocolError> {
        let path = EndpointPathKey::new(canonical, hop.as_ref());
        let mut guard = self.endpoint.lock().await;
        if let Some(cached) = guard.as_ref()
            && cached.path == path
        {
            return Ok(cached.endpoint.clone());
        }
        if let Some(previous) = guard.take() {
            // DNS / hop address change: hop socket still has stale addrs if we
            // reused the endpoint — rebuild instead.
            previous
                .endpoint
                .close(0_u32.into(), b"Hysteria2 endpoint path changed");
        }
        let endpoint = build_endpoint(&self.options, canonical, hop, self.brutal_next.clone())?;
        *guard = Some(CachedEndpoint {
            endpoint: endpoint.clone(),
            path,
        });
        Ok(endpoint)
    }
}

fn build_endpoint(
    options: &ClientOptions,
    canonical: SocketAddr,
    hop: Option<HopConfig>,
    brutal_next: Option<Arc<std::sync::Mutex<Option<BrutalControl>>>>,
) -> Result<quinn::Endpoint, Hysteria2ProtocolError> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    for pem in &options.tls.custom_roots {
        let mut cursor = std::io::Cursor::new(pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut cursor).flatten() {
            let _ = roots.add(cert);
        }
    }
    let builder = ClientConfig::builder();
    let mut crypto = if options.tls.skip_certificate_verification {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    crypto.alpn_protocols = options
        .tls
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    if crypto.alpn_protocols.is_empty() {
        crypto.alpn_protocols = vec![b"h3".to_vec()];
    }
    crypto.enable_early_data = false;
    crypto.resumption = tokio_rustls::rustls::client::Resumption::disabled();

    let quic_crypto = QuicClientConfig::try_from(crypto)
        .map_err(|error| Hysteria2ProtocolError::Quinn(error.to_string()))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    let idle = options.handshake_timeout.max(DEFAULT_MAX_IDLE_TIMEOUT);
    transport.max_idle_timeout(Some(
        idle.try_into()
            .map_err(|error| Hysteria2ProtocolError::Quinn(format!("{error}")))?,
    ));
    transport.keep_alive_interval(Some(DEFAULT_KEEP_ALIVE_PERIOD));
    let stream_window = options
        .stream_receive_window
        .unwrap_or(DEFAULT_STREAM_RECEIVE_WINDOW);
    let conn_window = options
        .connection_receive_window
        .unwrap_or(DEFAULT_CONN_RECEIVE_WINDOW);
    transport.stream_receive_window(
        quinn::VarInt::from_u64(stream_window)
            .map_err(|error| Hysteria2ProtocolError::Quinn(error.to_string()))?,
    );
    transport.receive_window(
        quinn::VarInt::from_u64(conn_window)
            .map_err(|error| Hysteria2ProtocolError::Quinn(error.to_string()))?,
    );
    // Enable QUIC datagrams for UDP relay.
    transport.datagram_receive_buffer_size(Some(MAX_DATAGRAM_FRAME_SIZE * 1024));
    transport.datagram_send_buffer_size(MAX_DATAGRAM_FRAME_SIZE * 1024);

    match brutal_next {
        Some(next) => {
            transport.congestion_controller_factory(Arc::new(SwitchableFactory {
                up_bps: options.up_bps,
                next,
            }));
        }
        None => {
            transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
        }
    }
    client_config.transport_config(Arc::new(transport));

    let obfs = if options.obfs_password.is_empty() {
        None
    } else {
        Some(
            Salamander::new(options.obfs_password.as_bytes()).ok_or_else(|| {
                Hysteria2ProtocolError::Protocol("invalid salamander password".to_owned())
            })?,
        )
    };

    let bind_addr = if canonical.is_ipv6() {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    };
    let std_sock = std::net::UdpSocket::bind(bind_addr).map_err(Hysteria2ProtocolError::Io)?;
    let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    let inner = runtime
        .wrap_udp_socket(std_sock)
        .map_err(Hysteria2ProtocolError::Io)?;
    let socket: Arc<dyn AsyncUdpSocket> =
        match ObfsHopSocket::new(inner.clone(), canonical, obfs, hop) {
            Some(wrapped) => wrapped,
            None => inner,
        };

    let mut endpoint =
        quinn::Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, socket, runtime)
            .map_err(Hysteria2ProtocolError::Io)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Closes a QUIC connection if dropped before the handshake completes.
struct HandshakeConnGuard(Option<quinn::Connection>);

impl Drop for HandshakeConnGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.0.take() {
            conn.close(0_u32.into(), b"handshake aborted");
        }
    }
}

async fn resolve_endpoint(
    options: &ClientOptions,
) -> Result<(SocketAddr, Option<HopConfig>), Hysteria2ProtocolError> {
    // Go: when `ports` is set, hop exclusively over that set — do not inject
    // the scalar `port` (it may be 0 or outside the hop range).
    let ports = if options.hop_ports.is_empty() {
        if options.port == 0 {
            return Err(Hysteria2ProtocolError::Protocol(
                "Hysteria2 port is required when ports is empty".to_owned(),
            ));
        }
        vec![options.port]
    } else {
        options.hop_ports.clone()
    };
    let first = ports[0];
    let address = resolve_server(&options.server, first).await?;
    let addrs: Vec<SocketAddr> = ports
        .iter()
        .map(|port| SocketAddr::new(address.ip(), *port))
        .collect();
    if addrs.len() <= 1 {
        return Ok((address, None));
    }
    let min = if options.hop_interval_min_secs == 0 {
        DEFAULT_HOP_INTERVAL_SECS
    } else {
        options.hop_interval_min_secs.max(MIN_HOP_INTERVAL_SECS)
    };
    let max = if options.hop_interval_max_secs == 0 {
        min
    } else {
        options.hop_interval_max_secs.max(min)
    };
    Ok((
        address,
        Some(HopConfig {
            addrs,
            interval_min: Duration::from_secs(min),
            interval_max: Duration::from_secs(max),
        }),
    ))
}

async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr, Hysteria2ProtocolError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(Hysteria2ProtocolError::Io)?;
    addresses.next().ok_or_else(|| {
        Hysteria2ProtocolError::Protocol(format!("failed to resolve Hysteria2 server {host}"))
    })
}

#[derive(Debug)]
struct SkipServerVerification {
    algorithms: WebPkiSupportedAlgorithms,
}

impl SkipServerVerification {
    fn new() -> Self {
        Self {
            algorithms: tokio_rustls::rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn endpoint_path_key_changes_when_canonical_ip_changes() {
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443));
        let b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 443));
        let hop_a = HopConfig {
            addrs: vec![
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8443)),
            ],
            interval_min: Duration::from_secs(5),
            interval_max: Duration::from_secs(5),
        };
        let hop_b = HopConfig {
            addrs: vec![
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 443)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 8443)),
            ],
            interval_min: Duration::from_secs(5),
            interval_max: Duration::from_secs(5),
        };
        assert_ne!(
            EndpointPathKey::new(a, Some(&hop_a)),
            EndpointPathKey::new(b, Some(&hop_b))
        );
    }

    #[tokio::test]
    async fn endpoint_rebuilds_when_resolved_address_changes() {
        let client = Client::new(ClientOptions {
            server: "127.0.0.1".into(),
            port: 1,
            password: "x".into(),
            tls: TlsOptions {
                server_name: "test".into(),
                skip_certificate_verification: true,
                alpn: vec!["h3".into()],
                custom_roots: Vec::new(),
            },
            hop_ports: vec![11_001, 11_002],
            hop_interval_min_secs: 5,
            hop_interval_max_secs: 5,
            ..ClientOptions::default()
        })
        .expect("client");

        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 11_001));
        let hop_a = HopConfig {
            addrs: vec![
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 11_001)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 11_002)),
            ],
            interval_min: Duration::from_secs(5),
            interval_max: Duration::from_secs(5),
        };
        let ep1 = client
            .endpoint(a, Some(hop_a.clone()))
            .await
            .expect("first endpoint");
        let ep1_again = client
            .endpoint(a, Some(hop_a))
            .await
            .expect("same-path reuse");
        // Same path must reuse the cached endpoint object.
        assert_eq!(ep1.local_addr().ok(), ep1_again.local_addr().ok());

        let b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 11_001));
        let hop_b = HopConfig {
            addrs: vec![
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 11_001)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 11_002)),
            ],
            interval_min: Duration::from_secs(5),
            interval_max: Duration::from_secs(5),
        };
        let ep2 = client
            .endpoint(b, Some(hop_b))
            .await
            .expect("rebuilt endpoint");
        // New path must bind a fresh UDP socket (different local port).
        assert_ne!(ep1.local_addr().ok(), ep2.local_addr().ok());
    }
}

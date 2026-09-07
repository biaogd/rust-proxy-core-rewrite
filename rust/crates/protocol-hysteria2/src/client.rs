//! Session client with QUIC connection reuse.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use quinn::congestion::BbrConfig;
use quinn::crypto::rustls::QuicClientConfig;
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
use crate::tcp::Hysteria2Stream;
use crate::{
    DEFAULT_CONN_RECEIVE_WINDOW, DEFAULT_KEEP_ALIVE_PERIOD, DEFAULT_MAX_IDLE_TIMEOUT,
    DEFAULT_STREAM_RECEIVE_WINDOW, Hysteria2ProtocolError,
};

/// TLS options for the Hysteria2 QUIC dial.
#[derive(Clone, Debug)]
pub struct TlsOptions {
    pub server_name: String,
    pub skip_certificate_verification: bool,
    pub alpn: Vec<String>,
    pub custom_roots: Vec<String>,
}

/// Client construction options.
#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub tls: TlsOptions,
    /// When true, never reuse a QUIC session after the first stream batch.
    pub disable_reuse: bool,
}

struct SessionInner {
    connection: quinn::Connection,
    closed: AtomicBool,
    udp_enabled: bool,
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

    /// Closes the underlying QUIC connection.
    pub fn close(&self) {
        self.mark_closed();
        self.inner
            .connection
            .close(0_u32.into(), b"Hysteria2 session closed");
    }
}

/// Long-lived Hysteria2 client with optional session reuse.
pub struct Client {
    options: ClientOptions,
    session: Mutex<Option<Session>>,
    endpoint: Mutex<Option<quinn::Endpoint>>,
}

impl Client {
    #[must_use]
    pub fn new(options: ClientOptions) -> Self {
        Self {
            options,
            session: Mutex::new(None),
            endpoint: Mutex::new(None),
        }
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
        let session = self.offer_session().await?;
        let stream = session.open_tcp(destination).await?;
        Ok(Box::new(stream))
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
        if let Some(endpoint) = endpoint.take() {
            endpoint.close(0_u32.into(), b"Hysteria2 client closed");
        }
    }

    async fn offer_session(&self) -> Result<Session, Hysteria2ProtocolError> {
        {
            let guard = self.session.lock().await;
            if let Some(session) = guard.as_ref()
                && !session.is_closed()
                && !self.options.disable_reuse
            {
                return Ok(session.clone());
            }
        }
        let session = self.dial_session().await?;
        let mut guard = self.session.lock().await;
        if let Some(existing) = guard.as_ref()
            && !existing.is_closed()
            && !self.options.disable_reuse
        {
            // Another task won the dial race; reuse theirs and drop ours.
            session.close();
            return Ok(existing.clone());
        }
        if let Some(previous) = guard.replace(session.clone()) {
            previous.close();
        }
        Ok(session)
    }

    async fn dial_session(&self) -> Result<Session, Hysteria2ProtocolError> {
        let address = resolve_server(&self.options.server, self.options.port).await?;
        let endpoint = self.endpoint().await?;
        let connecting = endpoint.connect(address, &self.options.tls.server_name)?;
        let connection = connecting
            .await
            .map_err(|error| Hysteria2ProtocolError::Quinn(format!("handshake failed: {error}")))?;
        // HY2-A: full handshake only (0-RTT deferred).
        let auth = auth::authenticate(connection.clone(), &self.options.password, 0)
            .await
            .map_err(|error| Hysteria2ProtocolError::Protocol(format!("auth failed: {error}")))?;
        let _ = auth.rx_auto; // Brutal selection is HY2-B; BBR already installed at dial.
        Ok(Session {
            inner: Arc::new(SessionInner {
                connection,
                closed: AtomicBool::new(false),
                udp_enabled: auth.udp_enabled,
            }),
        })
    }

    async fn endpoint(&self) -> Result<quinn::Endpoint, Hysteria2ProtocolError> {
        let mut guard = self.endpoint.lock().await;
        if let Some(endpoint) = guard.as_ref() {
            return Ok(endpoint.clone());
        }
        let endpoint = build_endpoint(&self.options.tls)?;
        *guard = Some(endpoint.clone());
        Ok(endpoint)
    }
}

fn build_endpoint(tls: &TlsOptions) -> Result<quinn::Endpoint, Hysteria2ProtocolError> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    for pem in &tls.custom_roots {
        let mut cursor = std::io::Cursor::new(pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut cursor).flatten() {
            let _ = roots.add(cert);
        }
    }
    let builder = ClientConfig::builder();
    let mut crypto = if tls.skip_certificate_verification {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    crypto.alpn_protocols = tls
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    if crypto.alpn_protocols.is_empty() {
        crypto.alpn_protocols = vec![b"h3".to_vec()];
    }
    // HY2-A: no 0-RTT.
    crypto.enable_early_data = false;
    crypto.resumption = tokio_rustls::rustls::client::Resumption::disabled();

    let quic_crypto = QuicClientConfig::try_from(crypto)
        .map_err(|error| Hysteria2ProtocolError::Quinn(error.to_string()))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        DEFAULT_MAX_IDLE_TIMEOUT
            .try_into()
            .map_err(|error| Hysteria2ProtocolError::Quinn(format!("{error}")))?,
    ));
    transport.keep_alive_interval(Some(DEFAULT_KEEP_ALIVE_PERIOD));
    transport.stream_receive_window(
        quinn::VarInt::from_u64(DEFAULT_STREAM_RECEIVE_WINDOW)
            .map_err(|error| Hysteria2ProtocolError::Quinn(error.to_string()))?,
    );
    transport.receive_window(
        quinn::VarInt::from_u64(DEFAULT_CONN_RECEIVE_WINDOW)
            .map_err(|error| Hysteria2ProtocolError::Quinn(error.to_string()))?,
    );
    // Congestion gate: stock Quinn BBR (Go default when up/down unset).
    transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .map_err(Hysteria2ProtocolError::Io)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
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

// Silence unused dual-stack helper until HY2-B binds both families explicitly.
#[allow(dead_code)]
fn unbound_v6() -> SocketAddr {
    SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
}

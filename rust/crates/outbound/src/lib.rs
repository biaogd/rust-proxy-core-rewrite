use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use fast_socks5::util::target_addr::{TargetAddr, ToTargetAddr, read_address};
use futures_util::stream::{FuturesUnordered, StreamExt};
use http_body_util::Empty;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rewrite_model::{Destination, Host};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{
    WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};

pub trait OutboundStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> OutboundStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedOutboundStream = Box<dyn OutboundStream>;

pub struct Socks5UdpAssociation {
    _control: tokio::sync::Mutex<BoxedOutboundStream>,
    socket: UdpSocket,
    relay: std::net::SocketAddr,
}

impl Socks5UdpAssociation {
    /// Sends one UDP payload through the negotiated SOCKS5 relay.
    ///
    /// # Errors
    ///
    /// Returns an address-encoding or socket error when the relay datagram
    /// cannot be constructed or sent.
    pub async fn send(
        &self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), Socks5ProxyError> {
        let target = destination.host.to_string();
        let address = (target.as_str(), destination.port)
            .to_target_addr()
            .map_err(DirectError::Io)?
            .to_be_bytes()
            .map_err(|error| Socks5ProxyError::InvalidAddress(error.to_string()))?;
        let mut packet = Vec::with_capacity(address.len() + payload.len() + 3);
        packet.extend_from_slice(&[0, 0, 0]);
        packet.extend_from_slice(&address);
        packet.extend_from_slice(payload);
        self.socket
            .send_to(&packet, self.relay)
            .await
            .map_err(DirectError::Io)?;
        Ok(())
    }

    /// Receives and decodes one UDP payload from the negotiated SOCKS5 relay.
    ///
    /// # Errors
    ///
    /// Returns a socket or framing error for packets that do not come from the
    /// negotiated relay or do not contain a valid SOCKS5 UDP address.
    pub async fn recv(&self) -> Result<(Destination, Vec<u8>), Socks5ProxyError> {
        let mut packet = vec![0_u8; 65_535];
        let (length, source) = self
            .socket
            .recv_from(&mut packet)
            .await
            .map_err(DirectError::Io)?;
        if source != self.relay || length < 4 || packet[..3] != [0, 0, 0] {
            return Err(Socks5ProxyError::InvalidAddress(
                "invalid SOCKS5 UDP relay packet".to_owned(),
            ));
        }
        packet.truncate(length);
        let (destination, payload_offset) = decode_socks5_udp_address(&packet[3..])?;
        Ok((destination, packet[(payload_offset + 3)..].to_vec()))
    }
}

#[derive(Debug, Error)]
pub enum DirectError {
    #[error("DIRECT TCP dial timed out")]
    Timeout,
    #[error("DIRECT TCP dial failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("IPv6 is disabled")]
    Ipv6Disabled,
}

#[derive(Debug, Error)]
pub enum HttpProxyError {
    #[error(transparent)]
    Direct(#[from] DirectError),
    #[error("HTTP proxy handshake failed: {0}")]
    Handshake(#[from] hyper::Error),
    #[error("HTTP proxy request is invalid: {0}")]
    Request(#[from] hyper::http::Error),
    #[error("HTTP proxy header name is invalid: {0}")]
    HeaderName(#[from] hyper::http::header::InvalidHeaderName),
    #[error("HTTP proxy header value is invalid: {0}")]
    HeaderValue(#[from] hyper::http::header::InvalidHeaderValue),
    #[error("HTTP proxy TLS configuration is invalid: {0}")]
    TlsConfiguration(String),
    #[error("HTTP proxy TLS handshake timed out")]
    TlsTimeout,
    #[error("HTTP proxy TLS handshake failed: {0}")]
    TlsHandshake(std::io::Error),
    #[error("HTTP proxy rejected CONNECT with status {0}")]
    Status(hyper::StatusCode),
}

#[derive(Clone, Copy, Debug)]
pub struct HttpProxyTls<'a> {
    pub server_name: &'a str,
    pub verification_name: Option<&'a str>,
    pub skip_certificate_verification: bool,
    pub fingerprint: Option<&'a str>,
    pub certificate: Option<&'a str>,
    pub private_key: Option<&'a str>,
    pub custom_roots: &'a [String],
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DirectTcpOptions<'a> {
    pub interface: &'a str,
    pub routing_mark: i64,
    pub keep_alive_idle: i64,
    pub keep_alive_interval: i64,
    pub disable_keep_alive: bool,
    pub tcp_concurrent: bool,
}

#[derive(Debug)]
struct NoCertificateVerification {
    algorithms: WebPkiSupportedAlgorithms,
}

impl NoCertificateVerification {
    fn new() -> Self {
        Self {
            algorithms: tokio_rustls::rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for NoCertificateVerification {
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

#[derive(Debug)]
struct NameOverrideVerification {
    verifier: Arc<WebPkiServerVerifier>,
    verification_name: ServerName<'static>,
}

impl ServerCertVerifier for NameOverrideVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            &self.verification_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verifier
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verifier
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct FingerprintVerification {
    fingerprint: [u8; 32],
    verification_name: Option<ServerName<'static>>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for FingerprintVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if Sha256::digest(end_entity.as_ref()).as_slice() == self.fingerprint {
            return Ok(ServerCertVerified::assertion());
        }
        for (index, certificate) in intermediates.iter().enumerate() {
            if Sha256::digest(certificate.as_ref()).as_slice() != self.fingerprint {
                continue;
            }
            let mut roots = RootCertStore::empty();
            roots
                .add(certificate.clone())
                .map_err(|error| TlsError::General(error.to_string()))?;
            let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|error| TlsError::General(error.to_string()))?;
            return verifier.verify_server_cert(
                end_entity,
                &intermediates[..index],
                self.verification_name.as_ref().unwrap_or(server_name),
                ocsp_response,
                now,
            );
        }
        Err(TlsError::General(
            "certificate fingerprint does not match".to_owned(),
        ))
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

#[derive(Debug, Error)]
pub enum Socks5ProxyError {
    #[error(transparent)]
    Direct(#[from] DirectError),
    #[error(transparent)]
    Socks(#[from] fast_socks5::SocksError),
    #[error("SOCKS5 proxy rejected the offered authentication method")]
    AuthenticationRejected,
    #[error("SOCKS5 proxy selected an unsupported protocol version")]
    UnsupportedVersion,
    #[error("SOCKS5 proxy returned an invalid address: {0}")]
    InvalidAddress(String),
    #[error("SOCKS5 proxy handshake timed out")]
    HandshakeTimeout,
    #[error("SOCKS5 proxy TLS failed: {0}")]
    Tls(String),
}

/// Opens a direct TCP connection with the Phase 1 timeout and IPv6 policy.
///
/// # Errors
///
/// Returns [`DirectError`] when IPv6 is disabled for the destination, name
/// resolution or connection I/O fails, or the five-second deadline expires.
pub async fn connect(
    destination: &Destination,
    allow_ipv6: bool,
) -> Result<TcpStream, DirectError> {
    connect_with_options(destination, allow_ipv6, DirectTcpOptions::default()).await
}

/// Opens a direct TCP connection with global platform socket policy.
///
/// # Errors
///
/// Returns [`DirectError`] for policy, resolution, socket or timeout failures.
pub async fn connect_with_options(
    destination: &Destination,
    allow_ipv6: bool,
    options: DirectTcpOptions<'_>,
) -> Result<TcpStream, DirectError> {
    let connect = async {
        match destination.host {
            Host::Ip(address) => {
                if address.is_ipv6() && !allow_ipv6 {
                    return Err(DirectError::Ipv6Disabled);
                }
                rewrite_platform::connect_tcp(
                    (address, destination.port).into(),
                    platform_options(options),
                )
                .await
                .map_err(DirectError::Io)
            }
            Host::Domain(ref domain) => {
                let addresses = tokio::net::lookup_host((domain.as_str(), destination.port))
                    .await
                    .map_err(DirectError::Io)?;
                let addresses: Vec<_> = addresses
                    .filter(|address| allow_ipv6 || address.is_ipv4())
                    .collect();
                let mut last_error = None;
                if options.tcp_concurrent {
                    let mut attempts = FuturesUnordered::new();
                    for address in addresses {
                        attempts.push(rewrite_platform::connect_tcp(
                            address,
                            platform_options(options),
                        ));
                    }
                    while let Some(result) = attempts.next().await {
                        match result {
                            Ok(stream) => return Ok(stream),
                            Err(error) => last_error = Some(error),
                        }
                    }
                } else {
                    for address in addresses {
                        match rewrite_platform::connect_tcp(address, platform_options(options))
                            .await
                        {
                            Ok(stream) => return Ok(stream),
                            Err(error) => last_error = Some(error),
                        }
                    }
                }
                Err(DirectError::Io(last_error.unwrap_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "no permitted address resolved",
                    )
                })))
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), connect)
        .await
        .map_err(|_| DirectError::Timeout)?
}

fn platform_options(options: DirectTcpOptions<'_>) -> rewrite_platform::OutboundTcpOptions<'_> {
    rewrite_platform::OutboundTcpOptions {
        interface: options.interface,
        routing_mark: options.routing_mark,
        keep_alive_idle: options.keep_alive_idle,
        keep_alive_interval: options.keep_alive_interval,
        disable_keep_alive: options.disable_keep_alive,
    }
}

/// Opens a TCP tunnel through an HTTP CONNECT proxy, optionally over TLS.
///
/// # Errors
///
/// Returns [`HttpProxyError`] when the proxy cannot be reached, the CONNECT
/// exchange fails, or the proxy returns a non-success status.
pub async fn connect_http(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    credentials: Option<(&str, &str)>,
    headers: &BTreeMap<String, String>,
    tls: Option<HttpProxyTls<'_>>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
) -> Result<BoxedOutboundStream, HttpProxyError> {
    connect_http_with_options(
        server,
        destination,
        allow_ipv6,
        credentials,
        headers,
        tls,
        clock,
        DirectTcpOptions::default(),
    )
    .await
}

/// Opens an HTTP CONNECT tunnel with global platform socket policy.
///
/// # Errors
///
/// Returns [`HttpProxyError`] under the same conditions as [`connect_http`].
#[allow(clippy::too_many_arguments)]
pub async fn connect_http_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    credentials: Option<(&str, &str)>,
    headers: &BTreeMap<String, String>,
    tls: Option<HttpProxyTls<'_>>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
    options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, HttpProxyError> {
    let stream = connect_with_options(server, allow_ipv6, options).await?;
    let stream: BoxedOutboundStream = if let Some(tls) = tls {
        let config = http_tls_config(tls, clock)?;
        let server_name = ServerName::try_from(tls.server_name.to_owned())
            .map_err(|_| HttpProxyError::TlsConfiguration("invalid server name".to_owned()))?;
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            TlsConnector::from(Arc::new(config)).connect(server_name, stream),
        )
        .await
        .map_err(|_| HttpProxyError::TlsTimeout)?
        .map_err(HttpProxyError::TlsHandshake)?;
        Box::new(stream)
    } else {
        Box::new(stream)
    };
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let authority = destination.authority();
    let mut request = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(&authority)
        .header(hyper::header::HOST, &authority)
        .header(hyper::header::USER_AGENT, "Go-http-client/1.1")
        .header("proxy-connection", "Keep-Alive")
        .body(Empty::<Bytes>::new())?;
    for (name, value) in headers {
        let name = hyper::http::HeaderName::from_bytes(name.as_bytes())?;
        let value = hyper::http::HeaderValue::from_str(value)?;
        request.headers_mut().insert(name, value);
    }
    if let Some((username, password)) = credentials {
        let token = STANDARD.encode(format!("{username}:{password}"));
        request.headers_mut().insert(
            hyper::header::PROXY_AUTHORIZATION,
            hyper::http::HeaderValue::from_str(&format!("Basic {token}"))?,
        );
    }
    let response = sender.send_request(request).await?;
    if response.status() != hyper::StatusCode::OK {
        return Err(HttpProxyError::Status(response.status()));
    }
    let upgraded = hyper::upgrade::on(response).await?;
    Ok(Box::new(TokioIo::new(upgraded)))
}

/// Wraps an established outbound stream in client TLS for HTTPS health checks.
///
/// # Errors
///
/// Returns configuration, server-name or TLS handshake failures.
pub async fn wrap_client_tls(
    stream: BoxedOutboundStream,
    server_name: &str,
    skip_certificate_verification: bool,
    custom_roots: &[String],
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
) -> Result<BoxedOutboundStream, HttpProxyError> {
    let tls = HttpProxyTls {
        server_name,
        verification_name: None,
        skip_certificate_verification,
        fingerprint: None,
        certificate: None,
        private_key: None,
        custom_roots,
    };
    let config = http_tls_config(tls, clock)?;
    let server_name = ServerName::try_from(server_name.to_owned())
        .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
        .map_err(HttpProxyError::TlsHandshake)?;
    Ok(Box::new(stream))
}

fn http_tls_config(
    tls: HttpProxyTls<'_>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
) -> Result<ClientConfig, HttpProxyError> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let clock = clock.unwrap_or_else(|| Arc::new(rewrite_services::AdjustedClock::default()));
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for certificate in native.certs {
        roots
            .add(certificate)
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
    }
    let embedded = rustls_pemfile::certs(&mut Cursor::new(include_bytes!(
        "../../../../component/ca/ca-certificates.crt"
    )))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
    for certificate in embedded {
        roots
            .add(certificate)
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
    }
    for pem in tls.custom_roots {
        let certificates = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        }
    }
    let builder = ClientConfig::builder_with_details(provider, clock)
        .with_safe_default_protocol_versions()
        .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
    let builder = if let Some(fingerprint) = tls.fingerprint {
        let normalized = fingerprint.trim().replace(':', "");
        let fingerprint = hex::decode(normalized)
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        let fingerprint: [u8; 32] = fingerprint.try_into().map_err(|_| {
            HttpProxyError::TlsConfiguration(
                "certificate fingerprint must contain 32 bytes".to_owned(),
            )
        })?;
        let verification_name = tls
            .verification_name
            .map(str::to_owned)
            .map(ServerName::try_from)
            .transpose()
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(FingerprintVerification {
                fingerprint,
                verification_name,
                algorithms: tokio_rustls::rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms,
            }))
    } else if let Some(verification_name) = tls.verification_name {
        let verification_name = ServerName::try_from(verification_name.to_owned())
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NameOverrideVerification {
                verifier,
                verification_name,
            }))
    } else if tls.skip_certificate_verification {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification::new()))
    } else {
        builder.with_root_certificates(roots)
    };
    match (tls.certificate, tls.private_key) {
        (Some(certificate), Some(private_key)) => {
            let certificates = load_certificates(certificate)?;
            let private_key = load_private_key(private_key)?;
            builder
                .with_client_auth_cert(certificates, private_key)
                .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))
        }
        (None, None) => Ok(builder.with_no_client_auth()),
        _ => Err(HttpProxyError::TlsConfiguration(
            "client certificate and private key must be configured together".to_owned(),
        )),
    }
}

fn load_pem_or_path(value: &str) -> Result<Vec<u8>, HttpProxyError> {
    if value.contains("-----BEGIN") {
        Ok(value.as_bytes().to_vec())
    } else {
        std::fs::read(value).map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))
    }
}

fn load_certificates(value: &str) -> Result<Vec<CertificateDer<'static>>, HttpProxyError> {
    let bytes = load_pem_or_path(value)?;
    let certificates = rustls_pemfile::certs(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
    if certificates.is_empty() {
        return Err(HttpProxyError::TlsConfiguration(
            "client certificate contains no certificate".to_owned(),
        ));
    }
    Ok(certificates)
}

fn load_private_key(value: &str) -> Result<PrivateKeyDer<'static>, HttpProxyError> {
    let bytes = load_pem_or_path(value)?;
    rustls_pemfile::private_key(&mut Cursor::new(bytes))
        .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?
        .ok_or_else(|| HttpProxyError::TlsConfiguration("client private key is missing".to_owned()))
}

/// Opens a TCP stream through a SOCKS5 proxy using remote target addressing.
///
/// # Errors
///
/// Returns [`Socks5ProxyError`] when proxy connection, authentication or the
/// CONNECT request fails.
pub async fn connect_socks5(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    credentials: Option<(&str, &str)>,
) -> Result<BoxedOutboundStream, Socks5ProxyError> {
    connect_socks5_with_options(
        server,
        destination,
        allow_ipv6,
        credentials,
        None,
        None,
        DirectTcpOptions::default(),
    )
    .await
}

/// Opens a SOCKS5 tunnel with global platform socket policy.
///
/// # Errors
///
/// Returns [`Socks5ProxyError`] under the same conditions as [`connect_socks5`].
pub async fn connect_socks5_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    credentials: Option<(&str, &str)>,
    tls: Option<HttpProxyTls<'_>>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
    options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, Socks5ProxyError> {
    let mut stream = connect_socks5_control(server, allow_ipv6, tls, clock, options).await?;
    tokio::time::timeout(
        Duration::from_secs(5),
        socks5_command_handshake(&mut stream, destination, 1, credentials),
    )
    .await
    .map_err(|_| Socks5ProxyError::HandshakeTimeout)??;
    Ok(stream)
}

/// Opens one RFC 1928 UDP ASSOCIATE session through a configured SOCKS5 proxy.
///
/// # Errors
///
/// Returns a TCP/TLS, authentication, UDP bind or SOCKS5 framing error when
/// the association cannot be established.
#[allow(clippy::too_many_arguments)]
pub async fn associate_socks5_udp_with_options(
    server: &Destination,
    allow_ipv6: bool,
    credentials: Option<(&str, &str)>,
    tls: Option<HttpProxyTls<'_>>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
    options: DirectTcpOptions<'_>,
) -> Result<Socks5UdpAssociation, Socks5ProxyError> {
    let mut control = connect_socks5_control(server, allow_ipv6, tls, clock, options).await?;
    let request = Destination {
        host: Host::Ip(std::net::Ipv4Addr::UNSPECIFIED.into()),
        port: 0,
    };
    let relay = tokio::time::timeout(
        Duration::from_secs(5),
        socks5_command_handshake(&mut control, &request, 3, credentials),
    )
    .await
    .map_err(|_| Socks5ProxyError::HandshakeTimeout)??;
    let relay = resolve_socks5_relay(relay, server, allow_ipv6).await?;
    let bind = if relay.is_ipv4() {
        std::net::SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        std::net::SocketAddr::from(([0_u16; 8], 0))
    };
    let socket = rewrite_platform::bind_outbound_udp(bind, options.interface, options.routing_mark)
        .and_then(UdpSocket::from_std)
        .map_err(DirectError::Io)?;
    Ok(Socks5UdpAssociation {
        _control: tokio::sync::Mutex::new(control),
        socket,
        relay,
    })
}

async fn connect_socks5_control(
    server: &Destination,
    allow_ipv6: bool,
    tls: Option<HttpProxyTls<'_>>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
    options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, Socks5ProxyError> {
    let socket = connect_with_options(server, allow_ipv6, options).await?;
    if let Some(tls) = tls {
        let config = http_tls_config(tls, clock)
            .map_err(|error| Socks5ProxyError::Tls(error.to_string()))?;
        let server_name = ServerName::try_from(tls.server_name.to_owned())
            .map_err(|error| Socks5ProxyError::Tls(error.to_string()))?;
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            TlsConnector::from(Arc::new(config)).connect(server_name, socket),
        )
        .await
        .map_err(|_| Socks5ProxyError::HandshakeTimeout)?
        .map_err(|error| Socks5ProxyError::Tls(error.to_string()))?;
        Ok(Box::new(stream))
    } else {
        Ok(Box::new(socket))
    }
}

async fn socks5_command_handshake<S>(
    stream: &mut S,
    destination: &Destination,
    command: u8,
    credentials: Option<(&str, &str)>,
) -> Result<TargetAddr, Socks5ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let method = if credentials.is_some() { 2 } else { 0 };
    stream
        .write_all(&[5, 1, method])
        .await
        .map_err(DirectError::Io)?;
    let mut selection = [0_u8; 2];
    stream
        .read_exact(&mut selection)
        .await
        .map_err(DirectError::Io)?;
    if selection[0] != 5 {
        return Err(Socks5ProxyError::UnsupportedVersion);
    }
    if selection[1] == 2 {
        let Some((username, password)) = credentials else {
            return Err(Socks5ProxyError::AuthenticationRejected);
        };
        password_auth(stream, username, password).await?;
    } else if selection[1] != 0 {
        return Err(Socks5ProxyError::AuthenticationRejected);
    }

    let target = destination.host.to_string();
    let address = (target.as_str(), destination.port)
        .to_target_addr()
        .map_err(DirectError::Io)?;
    let address = address
        .to_be_bytes()
        .map_err(|error| Socks5ProxyError::InvalidAddress(error.to_string()))?;
    let mut request = Vec::with_capacity(address.len() + 3);
    request.extend_from_slice(&[5, command, 0]);
    request.extend_from_slice(&address);
    stream.write_all(&request).await.map_err(DirectError::Io)?;

    // The pinned Go client intentionally ignores VER, REP and RSV here and
    // accepts the tunnel when the returned bind address is well-formed.
    let mut response = [0_u8; 4];
    stream
        .read_exact(&mut response)
        .await
        .map_err(DirectError::Io)?;
    let address = read_address(stream, response[3])
        .await
        .map_err(|error| Socks5ProxyError::InvalidAddress(error.to_string()))?;
    Ok(address)
}

async fn password_auth<S>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Result<(), Socks5ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // The pinned Go oracle casts the byte lengths to uint8 but still writes the
    // complete credential bytes. Preserve that unusual overlength wire shape.
    let username_length =
        u8::try_from(username.len() % 256).expect("a byte length modulo 256 always fits in u8");
    let password_length =
        u8::try_from(password.len() % 256).expect("a byte length modulo 256 always fits in u8");
    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.extend_from_slice(&[1, username_length]);
    request.extend_from_slice(username.as_bytes());
    request.push(password_length);
    request.extend_from_slice(password.as_bytes());
    stream.write_all(&request).await.map_err(DirectError::Io)?;
    let mut response = [0_u8; 2];
    stream
        .read_exact(&mut response)
        .await
        .map_err(DirectError::Io)?;
    if response[1] != 0 {
        return Err(Socks5ProxyError::AuthenticationRejected);
    }
    Ok(())
}

async fn resolve_socks5_relay(
    relay: TargetAddr,
    server: &Destination,
    allow_ipv6: bool,
) -> Result<std::net::SocketAddr, Socks5ProxyError> {
    let (host, port) = relay.into_string_and_port();
    let lookup_host = match host.parse::<std::net::IpAddr>() {
        Ok(address) if !address.is_unspecified() => {
            return Ok(std::net::SocketAddr::new(address, port));
        }
        Ok(_) => server.host.to_string(),
        Err(_) => host,
    };
    let mut addresses = tokio::net::lookup_host((lookup_host.as_str(), port))
        .await
        .map_err(DirectError::Io)?;
    addresses
        .find(|address| allow_ipv6 || address.is_ipv4())
        .ok_or_else(|| {
            Socks5ProxyError::InvalidAddress(
                "SOCKS5 UDP relay resolved to no permitted address".to_owned(),
            )
        })
}

fn decode_socks5_udp_address(packet: &[u8]) -> Result<(Destination, usize), Socks5ProxyError> {
    let invalid = || Socks5ProxyError::InvalidAddress("truncated SOCKS5 UDP address".to_owned());
    let (host, port_offset) = match packet.first().copied() {
        Some(1) if packet.len() >= 7 => (
            Host::Ip(std::net::Ipv4Addr::new(packet[1], packet[2], packet[3], packet[4]).into()),
            5,
        ),
        Some(4) if packet.len() >= 19 => {
            let octets: [u8; 16] = packet[1..17].try_into().map_err(|_| invalid())?;
            (Host::Ip(std::net::Ipv6Addr::from(octets).into()), 17)
        }
        Some(3) if packet.len() >= 2 => {
            let length = usize::from(packet[1]);
            if packet.len() < length + 4 {
                return Err(invalid());
            }
            let host = std::str::from_utf8(&packet[2..(2 + length)])
                .map_err(|error| Socks5ProxyError::InvalidAddress(error.to_string()))?;
            (Host::Domain(host.to_owned()), length + 2)
        }
        _ => return Err(invalid()),
    };
    let port = u16::from_be_bytes(
        packet[port_offset..(port_offset + 2)]
            .try_into()
            .map_err(|_| invalid())?,
    );
    Ok((Destination { host, port }, port_offset + 2))
}

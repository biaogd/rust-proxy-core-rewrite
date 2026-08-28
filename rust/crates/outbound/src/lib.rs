use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use fast_socks5::util::target_addr::ToTargetAddr;
use futures_util::stream::{FuturesUnordered, StreamExt};
use http_body_util::Empty;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rewrite_model::{Destination, Host};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
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

pub trait OutboundStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> OutboundStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedOutboundStream = Box<dyn OutboundStream>;

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
    pub skip_certificate_verification: bool,
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

#[derive(Debug, Error)]
pub enum Socks5ProxyError {
    #[error(transparent)]
    Direct(#[from] DirectError),
    #[error(transparent)]
    Socks(#[from] fast_socks5::SocksError),
    #[error("SOCKS5 username/password length must be between 1 and 255 bytes")]
    InvalidCredentials,
    #[error("SOCKS5 proxy did not accept username/password authentication")]
    AuthenticationRejected,
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
        let config = http_tls_config(tls, &[], clock)?;
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
        skip_certificate_verification,
    };
    let config = http_tls_config(tls, custom_roots, clock)?;
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
    custom_roots: &[String],
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
) -> Result<ClientConfig, HttpProxyError> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let clock = clock.unwrap_or_else(|| Arc::new(rewrite_services::AdjustedClock::default()));
    if tls.skip_certificate_verification {
        return Ok(ClientConfig::builder_with_details(provider, clock)
            .with_safe_default_protocol_versions()
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification::new()))
            .with_no_client_auth());
    }
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
    for pem in custom_roots {
        let certificates = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        }
    }
    Ok(ClientConfig::builder_with_details(provider, clock)
        .with_safe_default_protocol_versions()
        .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth())
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
    options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, Socks5ProxyError> {
    let target = destination.host.to_string();
    let mut config = fast_socks5::client::Config::default();
    config.set_connect_timeout(Duration::from_secs(5));
    let mut socket = connect_with_options(server, allow_ipv6, options).await?;
    let stream = if let Some((username, password)) = credentials {
        strict_password_auth(&mut socket, username, password).await?;
        config.set_skip_auth(true);
        let mut stream =
            fast_socks5::client::Socks5Stream::use_stream(socket, None, config).await?;
        let address = (target.as_str(), destination.port)
            .to_target_addr()
            .map_err(DirectError::Io)?;
        stream
            .request(fast_socks5::Socks5Command::TCPConnect, address)
            .await?;
        stream
    } else {
        let mut stream =
            fast_socks5::client::Socks5Stream::use_stream(socket, None, config).await?;
        let address = (target.as_str(), destination.port)
            .to_target_addr()
            .map_err(DirectError::Io)?;
        stream
            .request(fast_socks5::Socks5Command::TCPConnect, address)
            .await?;
        stream
    };
    Ok(Box::new(stream))
}

async fn strict_password_auth(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<(), Socks5ProxyError> {
    let username_length = u8::try_from(username.len())
        .ok()
        .filter(|length| *length != 0)
        .ok_or(Socks5ProxyError::InvalidCredentials)?;
    let password_length = u8::try_from(password.len())
        .ok()
        .filter(|length| *length != 0)
        .ok_or(Socks5ProxyError::InvalidCredentials)?;
    stream
        .write_all(&[5, 1, 2])
        .await
        .map_err(DirectError::Io)?;
    let mut selection = [0_u8; 2];
    stream
        .read_exact(&mut selection)
        .await
        .map_err(DirectError::Io)?;
    if selection != [5, 2] {
        return Err(Socks5ProxyError::AuthenticationRejected);
    }
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
    if response != [1, 0] {
        return Err(Socks5ProxyError::AuthenticationRejected);
    }
    Ok(())
}

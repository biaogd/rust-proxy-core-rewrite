use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::Empty;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rewrite_model::Destination;
use thiserror::Error;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::BoxedOutboundStream;
use crate::direct::{DirectError, DirectTcpOptions, connect_with_options};
use rewrite_transport::{
    ClientTlsOptions as HttpProxyTls, TlsClientError, VisionDirectControl, client_config,
    connect_vision_tls,
};

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
    #[error(transparent)]
    Tls(#[from] TlsClientError),
    #[error("HTTP proxy rejected CONNECT with status {0}")]
    Status(hyper::StatusCode),
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
        let config = client_config(tls, clock)?;
        let server_name = ServerName::try_from(tls.server_name.to_owned())
            .map_err(|_| TlsClientError::Configuration("invalid server name".to_owned()))?;
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            TlsConnector::from(Arc::new(config)).connect(server_name, stream),
        )
        .await
        .map_err(|_| TlsClientError::Timeout)?
        .map_err(TlsClientError::Handshake)?;
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
        ech_config: None,
        alpn_protocols: &[],
        tls12_only: false,
        tls13_only: false,
    };
    wrap_client_tls_with_options(stream, tls, clock).await
}

/// Wraps an established outbound stream using the complete shared TLS option set.
///
/// # Errors
///
/// Returns configuration, server-name or TLS handshake failures.
pub async fn wrap_client_tls_with_options(
    stream: BoxedOutboundStream,
    tls: HttpProxyTls<'_>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
) -> Result<BoxedOutboundStream, HttpProxyError> {
    wrap_client_tls_with_alpn(stream, tls, clock)
        .await
        .map(|(stream, _)| stream)
}

/// Wraps an established stream in the record-bounded TLS carrier required by XTLS Vision.
///
/// # Errors
///
/// Returns configuration, server-name or TLS handshake failures.
pub async fn wrap_client_vision_tls_with_options(
    stream: BoxedOutboundStream,
    tls: HttpProxyTls<'_>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
    control: VisionDirectControl,
) -> Result<BoxedOutboundStream, HttpProxyError> {
    let config = client_config(tls, clock)?;
    connect_vision_tls(stream, tls.server_name, config, control)
        .await
        .map_err(Into::into)
}

/// Wraps an established stream in TLS and returns the negotiated ALPN value.
///
/// # Errors
///
/// Returns configuration, server-name or TLS handshake failures.
pub async fn wrap_client_tls_with_alpn(
    stream: BoxedOutboundStream,
    tls: HttpProxyTls<'_>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
) -> Result<(BoxedOutboundStream, Option<Vec<u8>>), HttpProxyError> {
    let config = client_config(tls, clock)?;
    let server_name = ServerName::try_from(tls.server_name.to_owned())
        .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
        .map_err(TlsClientError::Handshake)?;
    let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    Ok((Box::new(stream), alpn))
}

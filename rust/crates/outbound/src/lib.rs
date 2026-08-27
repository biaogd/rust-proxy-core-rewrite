use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::Empty;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rewrite_model::{Destination, Host};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

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
    #[error("HTTP proxy rejected CONNECT with status {0}")]
    Status(hyper::StatusCode),
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
    let connect = async {
        match destination.host {
            Host::Ip(address) => {
                if address.is_ipv6() && !allow_ipv6 {
                    return Err(DirectError::Ipv6Disabled);
                }
                TcpStream::connect((address, destination.port))
                    .await
                    .map_err(DirectError::Io)
            }
            Host::Domain(ref domain) => {
                let addresses = tokio::net::lookup_host((domain.as_str(), destination.port))
                    .await
                    .map_err(DirectError::Io)?;
                let mut last_error = None;
                for address in addresses.filter(|address| allow_ipv6 || address.is_ipv4()) {
                    match TcpStream::connect(address).await {
                        Ok(stream) => return Ok(stream),
                        Err(error) => last_error = Some(error),
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

/// Opens a TCP tunnel through a plaintext HTTP CONNECT proxy.
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
) -> Result<BoxedOutboundStream, HttpProxyError> {
    let stream = connect(server, allow_ipv6).await?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let authority = destination.authority();
    let mut builder = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(&authority)
        .header(hyper::header::HOST, &authority);
    if let Some((username, password)) = credentials {
        let token = STANDARD.encode(format!("{username}:{password}"));
        builder = builder.header(hyper::header::PROXY_AUTHORIZATION, format!("Basic {token}"));
    }
    let response = sender
        .send_request(builder.body(Empty::<Bytes>::new())?)
        .await?;
    if !response.status().is_success() {
        return Err(HttpProxyError::Status(response.status()));
    }
    let upgraded = hyper::upgrade::on(response).await?;
    Ok(Box::new(TokioIo::new(upgraded)))
}

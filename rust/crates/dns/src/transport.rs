use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::{Buf, Bytes};
use http::header::{ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, USER_AGENT};
use http::{HeaderValue, Method, Request};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use rewrite_config::{DnsTlsConfig, DnsTransport, DohProtocol};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::enhancer::{answer_addresses, make_query};
use crate::service::{Http1Sender, HttpConnectionPool, TlsConnectionPool};
use crate::{
    DNS_HEADER_LENGTH, DnsError, MAX_DNS_MESSAGE, MAX_DOH_REDIRECT_REQUESTS,
    MAX_POOLED_TLS_CONNECTIONS, NameOverrideVerification, NoCertificateVerification,
    UPSTREAM_TIMEOUT,
};

pub(crate) async fn query_udp(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
    let bind = match upstream.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(upstream).await?;
    socket.send(query).await?;
    let mut response = vec![0_u8; MAX_DNS_MESSAGE];
    let length = tokio::time::timeout(UPSTREAM_TIMEOUT, socket.recv(&mut response))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    response.truncate(length);
    Ok(response)
}

pub(crate) async fn query_udp_with_tcp_retry(
    query: &[u8],
    upstream: SocketAddr,
) -> Result<Vec<u8>, DnsError> {
    let response = query_udp(query, upstream).await?;
    if response.len() >= DNS_HEADER_LENGTH && response[2] & 0x02 != 0 {
        query_tcp(query, upstream).await
    } else {
        Ok(response)
    }
}

pub(crate) async fn query_tcp(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
    let mut stream = tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(upstream))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    let length = u16::try_from(query.len())
        .map_err(|_| DnsError::InvalidMessage("query exceeds TCP DNS frame"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(query).await?;
    let mut length = [0_u8; 2];
    tokio::time::timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut length))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    let mut response = vec![0_u8; usize::from(u16::from_be_bytes(length))];
    tokio::time::timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut response))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    Ok(response)
}

pub(crate) async fn query_tls(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
    let mut stream = connect_tls_insecure(upstream).await?;
    exchange_tls(query, &mut stream).await
}

pub(crate) async fn connect_tls_insecure(
    upstream: SocketAddr,
) -> Result<TlsStream<TcpStream>, DnsError> {
    install_default_crypto_provider();
    let stream = tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(upstream))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification::new()))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::IpAddress(upstream.ip().into());
    tokio::time::timeout(UPSTREAM_TIMEOUT, connector.connect(server_name, stream))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)
        .map_err(DnsError::Io)
}

pub(crate) async fn query_tls_verified(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
) -> Result<Vec<u8>, DnsError> {
    let mut stream = connect_tls_verified(upstream, tls).await?;
    exchange_tls(query, &mut stream).await
}

pub(crate) async fn connect_tls_verified(
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
) -> Result<TlsStream<TcpStream>, DnsError> {
    connect_tls_verified_with_alpn(upstream, tls, false).await
}

pub(crate) async fn connect_https_verified(
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
) -> Result<TlsStream<TcpStream>, DnsError> {
    connect_tls_verified_with_alpn(upstream, tls, true).await
}

pub(crate) async fn connect_tls_verified_with_alpn(
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    https: bool,
) -> Result<TlsStream<TcpStream>, DnsError> {
    let mut client_config = verified_client_config(tls)?;
    if https {
        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(tls.tls_server_name.clone())
        .map_err(|_| DnsError::InvalidMessage("invalid TLS server name"))?;
    let upstream = resolve_tls_endpoint(upstream, tls).await?;
    let stream = tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(upstream))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    tokio::time::timeout(UPSTREAM_TIMEOUT, connector.connect(server_name, stream))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)
        .map_err(DnsError::Io)
}

pub(crate) fn verified_client_config(tls: &DnsTlsConfig) -> Result<ClientConfig, DnsError> {
    install_default_crypto_provider();
    let mut roots = RootCertStore::empty();
    if !go_style_env_flag("DISABLE_SYSTEM_CA") {
        let native = rustls_native_certs::load_native_certs();
        for certificate in native.certs {
            roots.add(certificate).map_err(std::io::Error::other)?;
        }
    }
    if !go_style_env_flag("DISABLE_EMBED_CA") {
        let embedded = rustls_pemfile::certs(&mut Cursor::new(include_bytes!(
            "../../../../component/ca/ca-certificates.crt"
        )))
        .collect::<Result<Vec<_>, _>>()?;
        for certificate in embedded {
            roots.add(certificate).map_err(std::io::Error::other)?;
        }
    }
    for pem in &tls.trust_certificates {
        let certificates = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        if certificates.is_empty() {
            return Err(DnsError::InvalidMessage(
                "custom TLS root contains no certificate",
            ));
        }
        for certificate in certificates {
            roots.add(certificate).map_err(std::io::Error::other)?;
        }
    }
    let client_config = if tls.skip_certificate_verification {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification::new()))
            .with_no_client_auth()
    } else {
        let verification_name = ServerName::try_from(tls.server_name.clone())
            .map_err(|_| DnsError::InvalidMessage("invalid TLS verification name"))?;
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(std::io::Error::other)?;
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NameOverrideVerification {
                verifier,
                verification_name,
            }))
            .with_no_client_auth()
    };
    Ok(client_config)
}

fn install_default_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

pub(crate) fn go_style_env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| go_style_true(&value))
}

pub(crate) fn go_style_true(value: &str) -> bool {
    matches!(value, "1" | "t" | "T" | "true" | "TRUE" | "True")
}

pub(crate) async fn resolve_tls_endpoint(
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
) -> Result<SocketAddr, DnsError> {
    let Some(host) = &tls.endpoint_host else {
        return Ok(upstream);
    };
    let bootstrap = tls.bootstrap.ok_or(DnsError::InvalidMessage(
        "domain TLS endpoint lacks bootstrap resolver",
    ))?;
    let query = make_query(host, 1)?;
    let response = match bootstrap.transport {
        DnsTransport::Udp => query_udp(&query, bootstrap.address).await?,
        DnsTransport::Tcp => query_tcp(&query, bootstrap.address).await?,
        _ => {
            return Err(DnsError::InvalidMessage(
                "Phase 4E9 bootstrap resolver must use UDP or TCP",
            ));
        }
    };
    let address = answer_addresses(&response)?
        .into_iter()
        .map(|(address, _)| address)
        .find(IpAddr::is_ipv4)
        .ok_or(DnsError::NoAddress)?;
    Ok(SocketAddr::new(address, upstream.port()))
}

pub(crate) async fn exchange_tls(
    query: &[u8],
    stream: &mut TlsStream<TcpStream>,
) -> Result<Vec<u8>, DnsError> {
    let length = u16::try_from(query.len())
        .map_err(|_| DnsError::InvalidMessage("query exceeds TLS DNS frame"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(query).await?;
    let mut length = [0_u8; 2];
    tokio::time::timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut length))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    let mut response = vec![0_u8; usize::from(u16::from_be_bytes(length))];
    tokio::time::timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut response))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    Ok(response)
}

pub(crate) fn tls_pool_key(upstream: SocketAddr, tls: &DnsTlsConfig) -> Vec<u8> {
    let mut key = upstream.to_string().into_bytes();
    key.push(0);
    key.extend_from_slice(tls.server_name.as_bytes());
    key.push(0xff);
    key.extend_from_slice(tls.tls_server_name.as_bytes());
    key.push(u8::from(tls.skip_certificate_verification));
    key.push(tls.doh_protocol as u8);
    if let Some(endpoint_host) = &tls.endpoint_host {
        key.push(0xfe);
        key.extend_from_slice(endpoint_host.as_bytes());
    }
    if let Some(bootstrap) = tls.bootstrap {
        key.push(0xfd);
        key.extend_from_slice(bootstrap.address.to_string().as_bytes());
        key.push(bootstrap.transport as u8);
    }
    for certificate in &tls.trust_certificates {
        key.push(0);
        key.extend_from_slice(certificate.as_bytes());
    }
    if let Some(path) = &tls.doh_path {
        key.push(0);
        key.extend_from_slice(path.as_bytes());
    }
    if let Some(credentials) = &tls.doh_basic_credentials {
        key.push(0xfc);
        key.extend_from_slice(credentials.as_bytes());
    }
    key
}

pub(crate) fn insecure_tls_pool_key(upstream: SocketAddr) -> Vec<u8> {
    let mut key = b"insecure\0".to_vec();
    key.extend_from_slice(upstream.to_string().as_bytes());
    key
}

pub(crate) async fn return_tls_connection(
    pool: &Mutex<TlsConnectionPool>,
    key: &[u8],
    stream: TlsStream<TcpStream>,
) {
    let mut pool = pool.lock().await;
    if pool.key != key {
        return;
    }
    if pool.connections.len() >= MAX_POOLED_TLS_CONNECTIONS {
        pool.connections.remove(0);
    }
    pool.connections.push(stream);
}

pub(crate) async fn return_tls_http1_sender(
    pool: &Mutex<TlsConnectionPool>,
    key: &[u8],
    sender: Http1Sender,
) {
    let mut pool = pool.lock().await;
    if pool.h1_key != key {
        return;
    }
    if pool.h1_senders.len() >= MAX_POOLED_TLS_CONNECTIONS {
        pool.h1_senders.remove(0);
    }
    pool.h1_senders.push(sender);
}

pub(crate) async fn query_tls_verified_reuse(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let Some(pool) = pool else {
        return query_tls_verified(query, upstream, tls).await;
    };
    let key = tls_pool_key(upstream, tls);
    let old_stream = {
        let mut pool = pool.lock().await;
        if pool.key != key {
            pool.connections.clear();
            pool.key.clone_from(&key);
        }
        pool.connections.pop()
    };
    if let Some(mut stream) = old_stream
        && let Ok(response) = exchange_tls(query, &mut stream).await
    {
        return_tls_connection(pool, &key, stream).await;
        return Ok(response);
    }

    let mut stream = connect_tls_verified(upstream, tls).await?;
    let response = exchange_tls(query, &mut stream).await?;
    return_tls_connection(pool, &key, stream).await;
    Ok(response)
}

pub(crate) async fn query_tls_insecure_reuse(
    query: &[u8],
    upstream: SocketAddr,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let Some(pool) = pool else {
        return query_tls(query, upstream).await;
    };
    let key = insecure_tls_pool_key(upstream);
    let old_stream = {
        let mut pool = pool.lock().await;
        if pool.key != key {
            pool.connections.clear();
            pool.key.clone_from(&key);
        }
        pool.connections.pop()
    };
    if let Some(mut stream) = old_stream
        && let Ok(response) = exchange_tls(query, &mut stream).await
    {
        return_tls_connection(pool, &key, stream).await;
        return Ok(response);
    }

    let mut stream = connect_tls_insecure(upstream).await?;
    let response = exchange_tls(query, &mut stream).await?;
    return_tls_connection(pool, &key, stream).await;
    Ok(response)
}

pub(crate) async fn start_http1<S>(stream: S) -> Result<Http1Sender, DnsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = tokio::time::timeout(
        UPSTREAM_TIMEOUT,
        hyper::client::conn::http1::handshake(TokioIo::new(stream)),
    )
    .await
    .map_err(|_| DnsError::UpstreamTimeout)?
    .map_err(std::io::Error::other)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

pub(crate) async fn exchange_doh_http1(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    sender: &mut Http1Sender,
) -> Result<(Vec<u8>, bool), DnsError> {
    let path = tls
        .doh_path
        .as_deref()
        .ok_or(DnsError::InvalidMessage("DoH path is missing"))?;
    let mut upstream_query = query.to_vec();
    upstream_query[..2].fill(0);
    let encoded = URL_SAFE_NO_PAD.encode(&upstream_query);
    let mut target = format!("{path}?dns={encoded}");
    let authority = tls.endpoint_host.as_ref().map_or_else(
        || upstream.to_string(),
        |host| format!("{host}:{}", upstream.port()),
    );

    for request_number in 0..MAX_DOH_REDIRECT_REQUESTS {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(&target)
            .header(HOST, &authority)
            .header(ACCEPT, "application/dns-message")
            .header(USER_AGENT, "");
        if let Some(credentials) = &tls.doh_basic_credentials {
            let authorization = HeaderValue::from_str(&format!(
                "Basic {}",
                STANDARD.encode(credentials.as_bytes())
            ))
            .map_err(|_| DnsError::InvalidMessage("invalid DoH authorization"))?;
            request = request.header(AUTHORIZATION, authorization);
        }
        let request = request
            .body(Empty::new())
            .map_err(|_| DnsError::InvalidMessage("invalid DoH request"))?;
        let response = tokio::time::timeout(UPSTREAM_TIMEOUT, sender.send_request(request))
            .await
            .map_err(|_| DnsError::UpstreamTimeout)?
            .map_err(std::io::Error::other)?;
        let (status, location, mut response, reusable) = read_doh_http1_response(response).await?;
        if status == 200 {
            if response.len() < DNS_HEADER_LENGTH || response[..2] != [0, 0] {
                return Err(DnsError::InvalidMessage("DoH response DNS ID is not zero"));
            }
            response[..2].copy_from_slice(&query[..2]);
            return Ok((response, reusable));
        }
        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
            return Err(DnsError::InvalidMessage("DoH response status is not 200"));
        }
        if !reusable {
            return Err(DnsError::InvalidMessage(
                "DoH redirect closed its connection",
            ));
        }
        if request_number + 1 == MAX_DOH_REDIRECT_REQUESTS {
            return Err(DnsError::InvalidMessage("DoH redirect limit exceeded"));
        }
        let location =
            location.ok_or(DnsError::InvalidMessage("DoH redirect Location is missing"))?;
        let location = location.split('#').next().unwrap_or_default();
        if !location.starts_with('/') || location.starts_with("//") || location.is_empty() {
            return Err(DnsError::InvalidMessage(
                "DoH redirect is not same-origin relative",
            ));
        }
        location.clone_into(&mut target);
    }
    Err(DnsError::InvalidMessage("DoH redirect limit exceeded"))
}

pub(crate) async fn read_doh_http1_response(
    response: http::Response<hyper::body::Incoming>,
) -> Result<(u16, Option<String>, Vec<u8>, bool), DnsError> {
    let status = response.status().as_u16();
    let location = response
        .headers()
        .get(http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let reusable = !response
        .headers()
        .get(CONNECTION)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"close"));
    let expected_length = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or(DnsError::InvalidMessage(
            "DoH response Content-Length is missing",
        ))?;
    if expected_length > MAX_DNS_MESSAGE {
        return Err(DnsError::InvalidMessage("DoH response is too large"));
    }
    let mut body = response.into_body();
    let mut message = Vec::with_capacity(expected_length);
    while let Some(frame) = tokio::time::timeout(UPSTREAM_TIMEOUT, body.frame())
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .transpose()
        .map_err(std::io::Error::other)?
    {
        if let Some(data) = frame.data_ref() {
            if message.len().saturating_add(data.len()) > expected_length {
                return Err(DnsError::InvalidMessage("DoH response is too large"));
            }
            message.extend_from_slice(data);
        }
    }
    if message.len() != expected_length {
        return Err(DnsError::InvalidMessage("DoH response body is truncated"));
    }
    Ok((status, location, message, reusable))
}

pub(crate) fn http_pool_key(upstream: SocketAddr, http: &DnsTlsConfig) -> Vec<u8> {
    let mut key = b"http\0".to_vec();
    key.extend_from_slice(upstream.to_string().as_bytes());
    key.push(0);
    if let Some(path) = &http.doh_path {
        key.extend_from_slice(path.as_bytes());
    }
    if let Some(credentials) = &http.doh_basic_credentials {
        key.push(0xfc);
        key.extend_from_slice(credentials.as_bytes());
    }
    key
}

pub(crate) async fn return_http_sender(
    pool: &Mutex<HttpConnectionPool>,
    key: &[u8],
    sender: Http1Sender,
) {
    let mut pool = pool.lock().await;
    if pool.key != key {
        return;
    }
    if pool.senders.len() >= MAX_POOLED_TLS_CONNECTIONS {
        pool.senders.remove(0);
    }
    pool.senders.push(sender);
}

pub(crate) async fn query_http_reuse(
    query: &[u8],
    upstream: SocketAddr,
    http: &DnsTlsConfig,
    pool: Option<&Mutex<HttpConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let key = http_pool_key(upstream, http);
    if let Some(pool) = pool {
        let old_sender = {
            let mut pool = pool.lock().await;
            if pool.key != key {
                pool.senders.clear();
                pool.key.clone_from(&key);
            }
            pool.senders.pop()
        };
        if let Some(mut sender) = old_sender
            && let Ok((response, reusable)) =
                exchange_doh_http1(query, upstream, http, &mut sender).await
        {
            if reusable {
                return_http_sender(pool, &key, sender).await;
            }
            return Ok(response);
        }
    }

    let stream = tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(upstream))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    let mut sender = start_http1(stream).await?;
    let (response, reusable) = exchange_doh_http1(query, upstream, http, &mut sender).await?;
    if reusable && let Some(pool) = pool {
        return_http_sender(pool, &key, sender).await;
    }
    Ok(response)
}

pub(crate) async fn query_https_verified_reuse(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let protocol = match tls.doh_protocol {
        DohProtocol::Http => DohProtocol::Http,
        DohProtocol::Http3Only => DohProtocol::Http3Only,
        DohProtocol::PreferHttp3 => select_doh_protocol(upstream, tls, pool).await?,
    };
    match protocol {
        DohProtocol::Http => query_https_http_reuse(query, upstream, tls, pool).await,
        DohProtocol::Http3Only => query_https_h3_reuse(query, upstream, tls, pool).await,
        DohProtocol::PreferHttp3 => unreachable!("preference probe returns a concrete protocol"),
    }
}

pub(crate) async fn select_doh_protocol(
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<DohProtocol, DnsError> {
    let key = tls_pool_key(upstream, tls);
    if let Some(pool) = pool {
        let pool = pool.lock().await;
        if pool.doh_choice_key == key
            && let Some(choice) = pool.doh_choice
        {
            return Ok(choice);
        }
    }

    let h3_probe = probe_h3(upstream, tls);
    let http_probe = async {
        // The pinned Go implementation starts QUIC and TLS probes together,
        // but the local QUIC handshake wins before its TCP goroutine reaches
        // the socket when both transports are immediately available.
        tokio::time::sleep(Duration::from_millis(25)).await;
        connect_https_verified(upstream, tls).await
    };
    tokio::pin!(h3_probe);
    tokio::pin!(http_probe);
    let choice = tokio::select! {
        h3 = &mut h3_probe => if let Ok(()) = h3 {
            DohProtocol::Http3Only
        } else {
                drop(http_probe.await?);
                DohProtocol::Http
        },
        http = &mut http_probe => if let Ok(stream) = http {
            drop(stream);
            DohProtocol::Http
        } else {
            h3_probe.await?;
            DohProtocol::Http3Only
        },
    };
    if let Some(pool) = pool {
        let mut pool = pool.lock().await;
        pool.doh_choice_key = key;
        pool.doh_choice = Some(choice);
    }
    Ok(choice)
}

pub(crate) async fn probe_h3(upstream: SocketAddr, tls: &DnsTlsConfig) -> Result<(), DnsError> {
    let endpoint = h3_endpoint(tls)?;
    let address = resolve_tls_endpoint(upstream, tls).await?;
    let connecting = endpoint
        .connect(address, &tls.tls_server_name)
        .map_err(std::io::Error::other)?;
    let connection = tokio::time::timeout(UPSTREAM_TIMEOUT, connecting)
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)?;
    connection.close(0_u32.into(), b"HTTP/3 probe complete");
    Ok(())
}

pub(crate) fn h3_endpoint(tls: &DnsTlsConfig) -> Result<quinn::Endpoint, DnsError> {
    verified_quic_endpoint(tls, b"h3", true)
}

pub(crate) fn verified_quic_endpoint(
    tls: &DnsTlsConfig,
    alpn: &[u8],
    disable_resumption: bool,
) -> Result<quinn::Endpoint, DnsError> {
    let mut crypto = verified_client_config(tls)?;
    crypto.alpn_protocols = vec![alpn.to_vec()];
    // The pinned Go DoH client leaves ClientSessionCache unset. It labels H3
    // GETs as 0-RTT-capable, but reconnects cannot actually resume TLS and the
    // authority observes a full handshake. Disable rustls resumption to keep
    // that externally visible behavior until the oracle changes.
    if disable_resumption {
        crypto.enable_early_data = false;
        crypto.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    }
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(std::io::Error::other)?;
    let config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

pub(crate) async fn query_quic_verified_reuse(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let address = resolve_tls_endpoint(upstream, tls).await?;
    let Some(pool) = pool else {
        let endpoint = verified_quic_endpoint(tls, b"doq", true)?;
        let connection = connect_quic(&endpoint, address, tls).await?;
        let result = exchange_doq(query, &connection).await;
        connection.close(0_u32.into(), b"one-shot DoQ complete");
        return result;
    };
    let key = tls_pool_key(upstream, tls);
    let (mut connection, had_connection) = acquire_doq_connection(pool, &key, address, tls).await?;
    let attempts = if had_connection { 3 } else { 1 };
    for attempt in 0..attempts {
        match exchange_doq(query, &connection).await {
            Ok(response) => return Ok(response),
            Err(error) => {
                discard_doq_connection(pool, &key, connection.stable_id(), true).await;
                if attempt + 1 == attempts {
                    return Err(error);
                }
                connection = acquire_doq_connection(pool, &key, address, tls).await?.0;
            }
        }
    }
    unreachable!("DoQ always performs at least one attempt")
}

pub(crate) async fn acquire_doq_connection(
    pool: &Mutex<TlsConnectionPool>,
    key: &[u8],
    address: SocketAddr,
    tls: &DnsTlsConfig,
) -> Result<(quinn::Connection, bool), DnsError> {
    let mut pool = pool.lock().await;
    if pool.doq_key != key {
        if let Some(connection) = pool.doq_connection.take() {
            connection.close(0_u32.into(), b"DoQ configuration changed");
        }
        pool.doq_endpoint = None;
        pool.doq_key.clear();
        pool.doq_key.extend_from_slice(key);
    }
    let had_connection = pool.doq_connection.is_some();
    if let Some(connection) = &pool.doq_connection
        && connection.close_reason().is_none()
    {
        return Ok((connection.clone(), had_connection));
    }
    pool.doq_connection = None;
    if pool.doq_endpoint.is_none() {
        // Go keeps QUIC address-validation tokens but has no TLS session cache,
        // so reconnects remain full TLS handshakes rather than 0-RTT.
        pool.doq_endpoint = Some(verified_quic_endpoint(tls, b"doq", true)?);
    }
    let connection = connect_quic(
        pool.doq_endpoint.as_ref().expect("DoQ endpoint"),
        address,
        tls,
    )
    .await?;
    pool.doq_connection = Some(connection.clone());
    Ok((connection, had_connection))
}

pub(crate) async fn discard_doq_connection(
    pool: &Mutex<TlsConnectionPool>,
    key: &[u8],
    stable_id: usize,
    internal_error: bool,
) {
    let mut pool = pool.lock().await;
    if pool.doq_key == key
        && pool
            .doq_connection
            .as_ref()
            .is_some_and(|connection| connection.stable_id() == stable_id)
        && let Some(connection) = pool.doq_connection.take()
    {
        let code = u32::from(internal_error);
        connection.close(code.into(), b"DoQ exchange failed");
    }
}

pub(crate) async fn exchange_doq(
    query: &[u8],
    connection: &quinn::Connection,
) -> Result<Vec<u8>, DnsError> {
    tokio::time::timeout(UPSTREAM_TIMEOUT, async {
        let (mut sender, mut receiver) =
            connection.open_bi().await.map_err(std::io::Error::other)?;
        let mut upstream_query = query.to_vec();
        upstream_query[..2].fill(0);
        let length = u16::try_from(upstream_query.len())
            .map_err(|_| DnsError::InvalidMessage("DoQ query is too large"))?;
        sender
            .write_all(&length.to_be_bytes())
            .await
            .map_err(std::io::Error::other)?;
        sender
            .write_all(&upstream_query)
            .await
            .map_err(std::io::Error::other)?;
        sender.finish().map_err(std::io::Error::other)?;

        let mut length = [0_u8; 2];
        receiver
            .read_exact(&mut length)
            .await
            .map_err(std::io::Error::other)?;
        let response_length = usize::from(u16::from_be_bytes(length));
        if response_length == 0 {
            return Err(DnsError::InvalidMessage("DoQ response is empty"));
        }
        let mut response = vec![0_u8; response_length];
        receiver
            .read_exact(&mut response)
            .await
            .map_err(std::io::Error::other)?;
        if response.len() < DNS_HEADER_LENGTH {
            return Err(DnsError::InvalidMessage("DoQ response is too short"));
        }
        response[..2].copy_from_slice(&query[..2]);
        Ok(response)
    })
    .await
    .map_err(|_| DnsError::UpstreamTimeout)?
}

pub(crate) async fn connect_quic(
    endpoint: &quinn::Endpoint,
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
) -> Result<quinn::Connection, DnsError> {
    let connecting = endpoint
        .connect(upstream, &tls.tls_server_name)
        .map_err(std::io::Error::other)?;
    match connecting.into_0rtt() {
        Ok((connection, accepted)) => {
            tokio::spawn(async move {
                let _ = accepted.await;
            });
            Ok(connection)
        }
        Err(connecting) => tokio::time::timeout(UPSTREAM_TIMEOUT, connecting)
            .await
            .map_err(|_| DnsError::UpstreamTimeout)?
            .map_err(std::io::Error::other)
            .map_err(DnsError::Io),
    }
}

pub(crate) async fn h3_sender(
    connection: quinn::Connection,
) -> Result<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, DnsError> {
    let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(std::io::Error::other)?;
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|context| driver.poll_close(context)).await;
    });
    Ok(sender)
}

pub(crate) async fn query_https_h3_reuse(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let address = resolve_tls_endpoint(upstream, tls).await?;
    let key = tls_pool_key(upstream, tls);
    let Some(pool) = pool else {
        let endpoint = h3_endpoint(tls)?;
        let connection = connect_quic(&endpoint, address, tls).await?;
        let mut sender = h3_sender(connection.clone()).await?;
        let response = exchange_doh_h3(query, upstream, tls, &mut sender).await;
        connection.close(0_u32.into(), b"one-shot HTTP/3 complete");
        return response;
    };

    let mut pool = pool.lock().await;
    if pool.h3_key != key {
        if let Some(connection) = pool.h3_connection.take() {
            connection.close(0_u32.into(), b"HTTP/3 configuration changed");
        }
        pool.h3_sender = None;
        pool.h3_endpoint = None;
        pool.h3_key.clone_from(&key);
    }
    if pool.h3_endpoint.is_none() {
        pool.h3_endpoint = Some(h3_endpoint(tls)?);
    }

    for _ in 0..3 {
        if let Some(mut sender) = pool.h3_sender.take() {
            match exchange_doh_h3(query, upstream, tls, &mut sender).await {
                Ok(response) => {
                    pool.h3_sender = Some(sender);
                    return Ok(response);
                }
                Err(_) => {
                    if let Some(connection) = pool.h3_connection.take() {
                        connection.close(0_u32.into(), b"stale HTTP/3 connection");
                    }
                }
            }
        }
        let endpoint = pool.h3_endpoint.as_ref().expect("HTTP/3 endpoint");
        let connection = connect_quic(endpoint, address, tls).await?;
        let mut sender = h3_sender(connection.clone()).await?;
        match exchange_doh_h3(query, upstream, tls, &mut sender).await {
            Ok(response) => {
                pool.h3_connection = Some(connection);
                pool.h3_sender = Some(sender);
                return Ok(response);
            }
            Err(_) => connection.close(0_u32.into(), b"failed HTTP/3 request"),
        }
    }
    Err(DnsError::InvalidMessage("HTTP/3 retry limit exceeded"))
}

pub(crate) async fn exchange_doh_h3(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    sender: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
) -> Result<Vec<u8>, DnsError> {
    let path = tls
        .doh_path
        .as_deref()
        .ok_or(DnsError::InvalidMessage("DoH path is missing"))?;
    let mut upstream_query = query.to_vec();
    upstream_query[..2].fill(0);
    let encoded = URL_SAFE_NO_PAD.encode(&upstream_query);
    let authority = tls.endpoint_host.as_ref().map_or_else(
        || upstream.to_string(),
        |host| format!("{host}:{}", upstream.port()),
    );
    let uri = format!("https://{authority}{path}?dns={encoded}")
        .parse::<http::Uri>()
        .map_err(std::io::Error::other)?;
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("accept", "application/dns-message")
        .header("user-agent", "");
    if let Some(credentials) = &tls.doh_basic_credentials {
        builder = builder.header(
            "authorization",
            format!("Basic {}", STANDARD.encode(credentials.as_bytes())),
        );
    }
    let request = builder.body(()).map_err(std::io::Error::other)?;
    let mut stream = tokio::time::timeout(UPSTREAM_TIMEOUT, sender.send_request(request))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)?;
    stream.finish().await.map_err(std::io::Error::other)?;
    let response = tokio::time::timeout(UPSTREAM_TIMEOUT, stream.recv_response())
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)?;
    if response.status() != http::StatusCode::OK {
        return Err(DnsError::InvalidMessage("DoH response status is not 200"));
    }
    let mut dns_response = Vec::new();
    while let Some(mut chunk) = tokio::time::timeout(UPSTREAM_TIMEOUT, stream.recv_data())
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)?
    {
        if dns_response.len().saturating_add(chunk.remaining()) > MAX_DNS_MESSAGE {
            return Err(DnsError::InvalidMessage("DoH response is too large"));
        }
        let remaining = chunk.remaining();
        dns_response.extend_from_slice(&chunk.copy_to_bytes(remaining));
    }
    if dns_response.len() < DNS_HEADER_LENGTH || dns_response[..2] != [0, 0] {
        return Err(DnsError::InvalidMessage("DoH response DNS ID is not zero"));
    }
    dns_response[..2].copy_from_slice(&query[..2]);
    Ok(dns_response)
}

pub(crate) async fn query_https_http_reuse(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let key = tls_pool_key(upstream, tls);
    if let Some(pool) = pool {
        let h2_sender = {
            let pool = pool.lock().await;
            (pool.h2_key == key)
                .then(|| pool.h2_sender.clone())
                .flatten()
        };
        if let Some(sender) = h2_sender {
            if let Ok(response) = exchange_doh_h2(query, upstream, tls, sender).await {
                return Ok(response);
            }
            let mut pool = pool.lock().await;
            if pool.h2_key == key {
                pool.h2_sender = None;
            }
        }
    }

    let old_sender = {
        if let Some(pool) = pool {
            let mut pool = pool.lock().await;
            if pool.h1_key != key {
                pool.h1_senders.clear();
                pool.h1_key.clone_from(&key);
            }
            pool.h1_senders.pop()
        } else {
            None
        }
    };
    if let Some(mut sender) = old_sender
        && let Ok((response, reusable)) =
            exchange_doh_http1(query, upstream, tls, &mut sender).await
    {
        if reusable && let Some(pool) = pool {
            return_tls_http1_sender(pool, &key, sender).await;
        }
        return Ok(response);
    }

    let stream = connect_https_verified(upstream, tls).await?;
    if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
        let (sender, connection) =
            tokio::time::timeout(UPSTREAM_TIMEOUT, h2::client::handshake(stream))
                .await
                .map_err(|_| DnsError::UpstreamTimeout)?
                .map_err(std::io::Error::other)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = exchange_doh_h2(query, upstream, tls, sender.clone()).await?;
        if let Some(pool) = pool {
            let mut pool = pool.lock().await;
            pool.h2_key.clone_from(&key);
            pool.h2_sender = Some(sender);
        }
        return Ok(response);
    }
    let mut sender = start_http1(stream).await?;
    let (response, reusable) = exchange_doh_http1(query, upstream, tls, &mut sender).await?;
    if reusable && let Some(pool) = pool {
        return_tls_http1_sender(pool, &key, sender).await;
    }
    Ok(response)
}

pub(crate) async fn exchange_doh_h2(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    sender: h2::client::SendRequest<Bytes>,
) -> Result<Vec<u8>, DnsError> {
    let path = tls
        .doh_path
        .as_deref()
        .ok_or(DnsError::InvalidMessage("DoH path is missing"))?;
    let mut upstream_query = query.to_vec();
    upstream_query[..2].fill(0);
    let encoded = URL_SAFE_NO_PAD.encode(&upstream_query);
    let authority = tls.endpoint_host.as_ref().map_or_else(
        || upstream.to_string(),
        |host| format!("{host}:{}", upstream.port()),
    );
    let uri = format!("https://{authority}{path}?dns={encoded}")
        .parse::<http::Uri>()
        .map_err(std::io::Error::other)?;
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("accept", "application/dns-message")
        .header("user-agent", "");
    if let Some(credentials) = &tls.doh_basic_credentials {
        builder = builder.header(
            "authorization",
            format!("Basic {}", STANDARD.encode(credentials.as_bytes())),
        );
    }
    let request = builder.body(()).map_err(std::io::Error::other)?;
    let mut sender = tokio::time::timeout(UPSTREAM_TIMEOUT, sender.ready())
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)?;
    let (response, _) = sender
        .send_request(request, true)
        .map_err(std::io::Error::other)?;
    let response = tokio::time::timeout(UPSTREAM_TIMEOUT, response)
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)?;
    if response.status() != http::StatusCode::OK {
        return Err(DnsError::InvalidMessage("DoH response status is not 200"));
    }
    let mut body = response.into_body();
    let mut dns_response = Vec::new();
    while let Some(chunk) = tokio::time::timeout(UPSTREAM_TIMEOUT, body.data())
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
    {
        let chunk = chunk.map_err(std::io::Error::other)?;
        if dns_response.len().saturating_add(chunk.len()) > MAX_DNS_MESSAGE {
            return Err(DnsError::InvalidMessage("DoH response is too large"));
        }
        dns_response.extend_from_slice(&chunk);
    }
    if dns_response.len() < DNS_HEADER_LENGTH || dns_response[..2] != [0, 0] {
        return Err(DnsError::InvalidMessage("DoH response DNS ID is not zero"));
    }
    dns_response[..2].copy_from_slice(&query[..2]);
    Ok(dns_response)
}

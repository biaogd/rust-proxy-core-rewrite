//! Hysteria2 server Accept: HTTP/3 `/auth`, TCP request framing, and helpers
//! for UDP datagram relay (wire owned here; listen/route owned by runtime).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::congestion::BbrConfig;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{AsyncUdpSocket, EndpointConfig, Runtime, TokioRuntime};
use rewrite_model::{Destination, Host};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::ServerConfig;

use crate::auth::{
    AUTH_HOST, AUTH_PATH, HEADER_AUTH, HEADER_CC_RX, HEADER_PADDING, HEADER_UDP, random_padding,
};
use crate::salamander::{MIN_PSK_LEN, Salamander};
use crate::socket::ObfsHopSocket;
use crate::varint;
use crate::{
    DEFAULT_CONN_RECEIVE_WINDOW, DEFAULT_KEEP_ALIVE_PERIOD, DEFAULT_MAX_IDLE_TIMEOUT,
    DEFAULT_STREAM_RECEIVE_WINDOW, FRAME_TYPE_TCP_REQUEST, Hysteria2ProtocolError, STATUS_AUTH_OK,
};

const MAX_ADDRESS_LENGTH: u64 = 2048;
const MAX_MESSAGE_LENGTH: u64 = 2048;
const MAX_PADDING_LENGTH: u64 = 4096;
const MAX_TCP_REQUEST_SCRATCH: usize =
    8 + MAX_ADDRESS_LENGTH as usize + 8 + MAX_PADDING_LENGTH as usize;

/// Result of a successful HTTP/3 `/auth` Accept.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerAuthResult {
    pub username: String,
    pub udp_enabled: bool,
}

/// Server-side auth response knobs (stock BBR / first-slice defaults).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerAuthOptions {
    /// Advertise UDP relay support (`Hysteria-UDP`).
    pub udp_enabled: bool,
    /// When `None`, respond with `Hysteria-CC-RX: auto` (stock BBR path).
    pub cc_rx: Option<u64>,
}

impl Default for ServerAuthOptions {
    fn default() -> Self {
        Self {
            udp_enabled: true,
            cc_rx: None,
        }
    }
}

/// Options for binding a Hysteria2 QUIC server endpoint.
#[derive(Clone, Debug)]
pub struct ServerEndpointOptions {
    pub listen: SocketAddr,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub alpn: Vec<String>,
    /// Empty disables Salamander.
    pub salamander_password: String,
    pub max_idle_timeout: Duration,
    pub stream_receive_window: u64,
    pub connection_receive_window: u64,
    pub max_concurrent_bidi_streams: u32,
}

impl Default for ServerEndpointOptions {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            certificate_pem: String::new(),
            private_key_pem: String::new(),
            alpn: vec!["h3".to_owned()],
            salamander_password: String::new(),
            max_idle_timeout: DEFAULT_MAX_IDLE_TIMEOUT,
            stream_receive_window: DEFAULT_STREAM_RECEIVE_WINDOW,
            connection_receive_window: DEFAULT_CONN_RECEIVE_WINDOW,
            max_concurrent_bidi_streams: 1024,
        }
    }
}

/// Look up a username by password (Go `userMap[password]`).
#[must_use]
pub fn lookup_user<'a>(users: &'a HashMap<String, String>, password: &str) -> Option<&'a str> {
    users.get(password).map(String::as_str)
}

/// Build the inverted password→username table from Clash `users` name→password.
#[must_use]
pub fn password_user_table<I, S1, S2>(users: I) -> HashMap<String, String>
where
    I: IntoIterator<Item = (S1, S2)>,
    S1: Into<String>,
    S2: Into<String>,
{
    users
        .into_iter()
        .map(|(name, password)| (password.into(), name.into()))
        .collect()
}

/// True when the request is `POST https://hysteria/auth` (host + path).
#[must_use]
pub fn is_auth_request(method: &http::Method, uri: &http::Uri) -> bool {
    if method != http::Method::POST {
        return false;
    }
    let path = uri.path();
    if path != AUTH_PATH {
        return false;
    }
    let host = uri
        .host()
        .or_else(|| {
            // Some stacks put the authority only in the Host header; callers
            // should prefer [`auth_password_from_headers`] + host checks.
            None
        })
        .unwrap_or("");
    host.eq_ignore_ascii_case(AUTH_HOST)
}

/// Extract the auth password from request headers (case-insensitive names).
#[must_use]
pub fn auth_password_from_headers(headers: &http::HeaderMap) -> Option<&str> {
    headers
        .get(HEADER_AUTH)
        .or_else(|| headers.get("Hysteria-Auth"))
        .and_then(|value| value.to_str().ok())
}

fn auth_host_matches(uri: &http::Uri, headers: &http::HeaderMap) -> bool {
    if let Some(host) = uri.host() {
        return host.eq_ignore_ascii_case(AUTH_HOST);
    }
    headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|host| {
            host.split(':')
                .next()
                .unwrap_or(host)
                .eq_ignore_ascii_case(AUTH_HOST)
        })
}

/// Guard that keeps the HTTP/3 server connection alive after `/auth`.
///
/// `h3::server::Connection`'s `Drop` closes the Quinn connection with
/// `H3_NO_ERROR`. Hold this for the session lifetime while the runtime
/// `accept_bi`s TCP streams and reads datagrams on the same Quinn connection
/// (do not call [`h3::server::Connection::accept`] again).
pub struct H3ConnectionGuard {
    _inner: h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
}

/// Successful `/auth` Accept: username plus an h3 guard that must outlive TCP/UDP.
pub struct AuthenticatedIncoming {
    pub result: ServerAuthResult,
    pub h3_guard: H3ConnectionGuard,
}

/// Authenticate one accepted Quinn connection via HTTP/3 `/auth`.
///
/// On success returns an [`AuthenticatedIncoming`] whose [`H3ConnectionGuard`]
/// must be retained. Wrong password yields a non-233 response and closes the
/// Quinn connection.
pub async fn authenticate_incoming(
    connection: quinn::Connection,
    users: &HashMap<String, String>,
    options: ServerAuthOptions,
) -> Result<AuthenticatedIncoming, Hysteria2ProtocolError> {
    let mut h3_conn = h3::server::builder()
        .build::<_, bytes::Bytes>(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;

    let resolver = h3_conn
        .accept()
        .await
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?
        .ok_or_else(|| {
            Hysteria2ProtocolError::Protocol("h3 connection closed before auth".to_owned())
        })?;

    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;

    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();

    let auth_ok = method == http::Method::POST
        && uri.path() == AUTH_PATH
        && auth_host_matches(&uri, &headers);
    let password = auth_password_from_headers(&headers).unwrap_or("");
    let username = if auth_ok {
        lookup_user(users, password).map(str::to_owned)
    } else {
        None
    };

    let Some(username) = username else {
        let response = http::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .body(())
            .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;
        let _ = stream.send_response(response).await;
        let _ = stream.finish().await;
        drop(stream);
        drop(h3_conn);
        connection.close(0_u32.into(), b"authentication failed");
        return Err(Hysteria2ProtocolError::Protocol(
            "authentication failed".to_owned(),
        ));
    };

    let status = http::StatusCode::from_u16(STATUS_AUTH_OK)
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;
    let mut response = http::Response::builder().status(status);
    {
        let headers = response
            .headers_mut()
            .ok_or_else(|| Hysteria2ProtocolError::Protocol("response headers".to_owned()))?;
        headers.insert(
            HEADER_UDP,
            http::HeaderValue::from_static(if options.udp_enabled { "true" } else { "false" }),
        );
        let cc_rx = match options.cc_rx {
            Some(bps) => bps.to_string(),
            None => "auto".to_owned(),
        };
        headers.insert(
            HEADER_CC_RX,
            http::HeaderValue::from_str(&cc_rx)
                .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?,
        );
        headers.insert(
            HEADER_PADDING,
            http::HeaderValue::from_str(&random_padding(64, 512))
                .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?,
        );
    }
    let response = response
        .body(())
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;
    stream
        .send_response(response)
        .await
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;
    stream
        .finish()
        .await
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;
    drop(stream);

    Ok(AuthenticatedIncoming {
        result: ServerAuthResult {
            username,
            udp_enabled: options.udp_enabled,
        },
        h3_guard: H3ConnectionGuard { _inner: h3_conn },
    })
}

/// Parse a host:port (or `[ipv6]:port`) authority into [`Destination`].
pub fn parse_destination_authority(authority: &str) -> Result<Destination, Hysteria2ProtocolError> {
    if let Ok(address) = authority.parse::<SocketAddr>() {
        return Ok(Destination {
            host: Host::Ip(address.ip()),
            port: address.port(),
        });
    }
    let (host, port) = authority.rsplit_once(':').ok_or_else(|| {
        Hysteria2ProtocolError::Protocol(format!("invalid destination authority: {authority}"))
    })?;
    let port = port.parse::<u16>().map_err(|_| {
        Hysteria2ProtocolError::Protocol(format!("invalid destination port: {authority}"))
    })?;
    if host.is_empty() {
        return Err(Hysteria2ProtocolError::Protocol(format!(
            "invalid destination host: {authority}"
        )));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Destination {
            host: Host::Ip(ip),
            port,
        });
    }
    Ok(Destination {
        host: Host::Domain(host.to_owned()),
        port,
    })
}

#[derive(Debug)]
enum TcpRequestParse {
    NeedMore,
    Done {
        destination: Destination,
        consumed: usize,
    },
    Invalid(&'static str),
}

fn parse_tcp_request_buf(buf: &[u8]) -> TcpRequestParse {
    let mut pos = 0_usize;
    let Some((frame_type, n)) = varint::read_from(buf.get(pos..).unwrap_or_default()) else {
        return TcpRequestParse::NeedMore;
    };
    pos += n;
    if frame_type != FRAME_TYPE_TCP_REQUEST {
        return TcpRequestParse::Invalid("invalid TCP request frame type");
    }

    let Some((addr_len, n)) = varint::read_from(buf.get(pos..).unwrap_or_default()) else {
        return TcpRequestParse::NeedMore;
    };
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH {
        return TcpRequestParse::Invalid("invalid address length");
    }
    pos += n;
    let addr_len = usize::try_from(addr_len).unwrap_or(usize::MAX);
    if buf.len() < pos.saturating_add(addr_len) {
        return TcpRequestParse::NeedMore;
    }
    let address = match std::str::from_utf8(&buf[pos..pos + addr_len]) {
        Ok(value) => value,
        Err(_) => return TcpRequestParse::Invalid("address is not utf-8"),
    };
    pos += addr_len;
    let destination = match parse_destination_authority(address) {
        Ok(destination) => destination,
        Err(_) => return TcpRequestParse::Invalid("invalid destination authority"),
    };

    let Some((pad_len, n)) = varint::read_from(buf.get(pos..).unwrap_or_default()) else {
        return TcpRequestParse::NeedMore;
    };
    if pad_len > MAX_PADDING_LENGTH {
        return TcpRequestParse::Invalid("invalid padding length");
    }
    pos += n;
    let pad_len = usize::try_from(pad_len).unwrap_or(usize::MAX);
    if buf.len() < pos.saturating_add(pad_len) {
        return TcpRequestParse::NeedMore;
    }
    pos += pad_len;

    TcpRequestParse::Done {
        destination,
        consumed: pos,
    }
}

/// Encode a successful TCPResponse (`status=0`, empty message, padding).
pub fn encode_tcp_response_ok() -> Result<Vec<u8>, Hysteria2ProtocolError> {
    encode_tcp_response(true, "")
}

/// Encode a TCPResponse.
pub fn encode_tcp_response(ok: bool, message: &str) -> Result<Vec<u8>, Hysteria2ProtocolError> {
    let message = if message.len() as u64 > MAX_MESSAGE_LENGTH {
        &message[..MAX_MESSAGE_LENGTH as usize]
    } else {
        message
    };
    let padding = random_padding(64, 512);
    let mut frame = Vec::new();
    frame.push(u8::from(!ok));
    varint::write_into(&mut frame, message.len() as u64)?;
    frame.extend_from_slice(message.as_bytes());
    varint::write_into(&mut frame, padding.len() as u64)?;
    frame.extend_from_slice(padding.as_bytes());
    Ok(frame)
}

/// Parse a complete TCPRequest from bytes (unit-test helper).
pub fn parse_tcp_request(buf: &[u8]) -> Result<(Destination, usize), Hysteria2ProtocolError> {
    match parse_tcp_request_buf(buf) {
        TcpRequestParse::Done {
            destination,
            consumed,
        } => Ok((destination, consumed)),
        TcpRequestParse::NeedMore => Err(Hysteria2ProtocolError::Protocol(
            "truncated TCP request".to_owned(),
        )),
        TcpRequestParse::Invalid(reason) => {
            Err(Hysteria2ProtocolError::Protocol(reason.to_owned()))
        }
    }
}

/// Encode a TCPRequest (test / round-trip helper).
pub fn encode_tcp_request(destination: &Destination) -> Result<Vec<u8>, Hysteria2ProtocolError> {
    let address = destination.authority();
    let padding = random_padding(64, 512);
    let mut frame = Vec::new();
    varint::write_into(&mut frame, FRAME_TYPE_TCP_REQUEST)?;
    varint::write_into(&mut frame, address.len() as u64)?;
    frame.extend_from_slice(address.as_bytes());
    varint::write_into(&mut frame, padding.len() as u64)?;
    frame.extend_from_slice(padding.as_bytes());
    Ok(frame)
}

/// Accept a TCP proxy stream after auth: parse request, write ok response.
pub async fn accept_tcp_request(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(Destination, Hysteria2ServerStream), Hysteria2ProtocolError> {
    let mut scratch = Vec::with_capacity(256);
    let destination = loop {
        match parse_tcp_request_buf(&scratch) {
            TcpRequestParse::Done {
                destination,
                consumed,
            } => {
                if consumed < scratch.len() {
                    // Application payload may already follow the request
                    // (fast-open). Keep leftover for the first read.
                    let leftover = scratch.split_off(consumed);
                    let response = encode_tcp_response_ok()?;
                    send.write_all(&response).await.map_err(|error| {
                        Hysteria2ProtocolError::Io(std::io::Error::other(error.to_string()))
                    })?;
                    return Ok((
                        destination,
                        Hysteria2ServerStream {
                            send,
                            recv,
                            write_closed: false,
                            leftover,
                            leftover_pos: 0,
                        },
                    ));
                }
                break destination;
            }
            TcpRequestParse::Invalid(reason) => {
                return Err(Hysteria2ProtocolError::Protocol(reason.to_owned()));
            }
            TcpRequestParse::NeedMore => {
                if scratch.len() >= MAX_TCP_REQUEST_SCRATCH {
                    return Err(Hysteria2ProtocolError::Protocol(
                        "TCP request exceeded size bound".to_owned(),
                    ));
                }
                let mut tmp = [0_u8; 512];
                let n = recv.read(&mut tmp).await.map_err(|error| {
                    Hysteria2ProtocolError::Io(std::io::Error::other(error.to_string()))
                })?;
                let Some(n) = n else {
                    return Err(Hysteria2ProtocolError::Protocol(
                        "stream closed before TCP request".to_owned(),
                    ));
                };
                scratch.extend_from_slice(&tmp[..n]);
            }
        }
    };

    let response = encode_tcp_response_ok()?;
    send.write_all(&response)
        .await
        .map_err(|error| Hysteria2ProtocolError::Io(std::io::Error::other(error.to_string())))?;
    Ok((
        destination,
        Hysteria2ServerStream {
            send,
            recv,
            write_closed: false,
            leftover: Vec::new(),
            leftover_pos: 0,
        },
    ))
}

/// Server-side TCP proxy stream after the TCPResponse has been written.
pub struct Hysteria2ServerStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    write_closed: bool,
    leftover: Vec<u8>,
    leftover_pos: usize,
}

impl AsyncRead for Hysteria2ServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = &mut *self;
        if me.leftover_pos < me.leftover.len() {
            let rest = &me.leftover[me.leftover_pos..];
            let n = rest.len().min(buffer.remaining());
            buffer.put_slice(&rest[..n]);
            me.leftover_pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.recv).poll_read(context, buffer)
    }
}

impl AsyncWrite for Hysteria2ServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        <quinn::SendStream as tokio::io::AsyncWrite>::poll_write(
            Pin::new(&mut self.send),
            context,
            buffer,
        )
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        <quinn::SendStream as tokio::io::AsyncWrite>::poll_flush(Pin::new(&mut self.send), context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        match <quinn::SendStream as tokio::io::AsyncWrite>::poll_shutdown(
            Pin::new(&mut self.send),
            context,
        ) {
            Poll::Ready(Ok(())) => {
                self.write_closed = true;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

fn load_server_crypto(
    certificate_pem: &str,
    private_key_pem: &str,
    alpn: &[String],
) -> Result<ServerConfig, Hysteria2ProtocolError> {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut cert_cursor = std::io::Cursor::new(certificate_pem.as_bytes());
    let certificates = rustls_pemfile::certs(&mut cert_cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;
    if certificates.is_empty() {
        return Err(Hysteria2ProtocolError::Protocol(
            "certificate not found".to_owned(),
        ));
    }
    let mut key_cursor = std::io::Cursor::new(private_key_pem.as_bytes());
    let private_key = rustls_pemfile::private_key(&mut key_cursor)
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?
        .ok_or_else(|| Hysteria2ProtocolError::Protocol("private key not found".to_owned()))?;
    let mut crypto = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;
    crypto.alpn_protocols = if alpn.is_empty() {
        vec![b"h3".to_vec()]
    } else {
        alpn.iter().map(|value| value.as_bytes().to_vec()).collect()
    };
    crypto.max_early_data_size = u32::MAX;
    Ok(crypto)
}

/// Bind a Hysteria2 QUIC server endpoint (stock BBR, optional Salamander).
pub fn bind_server_endpoint(
    options: &ServerEndpointOptions,
) -> Result<quinn::Endpoint, Hysteria2ProtocolError> {
    let crypto = load_server_crypto(
        &options.certificate_pem,
        &options.private_key_pem,
        &options.alpn,
    )?;
    let quic = QuicServerConfig::try_from(crypto)
        .map_err(|error| Hysteria2ProtocolError::Quinn(error.to_string()))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        options
            .max_idle_timeout
            .try_into()
            .map_err(|error| Hysteria2ProtocolError::Quinn(format!("{error}")))?,
    ));
    transport.keep_alive_interval(Some(DEFAULT_KEEP_ALIVE_PERIOD));
    transport.stream_receive_window(
        quinn::VarInt::from_u64(options.stream_receive_window)
            .map_err(|error| Hysteria2ProtocolError::Quinn(error.to_string()))?,
    );
    transport.receive_window(
        quinn::VarInt::from_u64(options.connection_receive_window)
            .map_err(|error| Hysteria2ProtocolError::Quinn(error.to_string()))?,
    );
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(options.max_concurrent_bidi_streams));
    transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
    transport.datagram_receive_buffer_size(Some(crate::udp::MAX_DATAGRAM_FRAME_SIZE * 1024));
    transport.datagram_send_buffer_size(crate::udp::MAX_DATAGRAM_FRAME_SIZE * 1024);
    server_config.transport_config(Arc::new(transport));

    let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    let std_sock = std::net::UdpSocket::bind(options.listen).map_err(Hysteria2ProtocolError::Io)?;
    std_sock
        .set_nonblocking(true)
        .map_err(Hysteria2ProtocolError::Io)?;
    let inner = runtime
        .wrap_udp_socket(std_sock)
        .map_err(Hysteria2ProtocolError::Io)?;
    let obfs = if options.salamander_password.is_empty() {
        None
    } else {
        Some(
            Salamander::new(options.salamander_password.as_bytes()).ok_or_else(|| {
                Hysteria2ProtocolError::Protocol(format!(
                    "salamander password must be at least {MIN_PSK_LEN} bytes"
                ))
            })?,
        )
    };
    let socket: Arc<dyn AsyncUdpSocket> =
        match ObfsHopSocket::new(inner.clone(), options.listen, obfs, None) {
            Some(wrapped) => wrapped,
            None => inner,
        };
    quinn::Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime,
    )
    .map_err(Hysteria2ProtocolError::Io)
}

/// Load PEM certificate/private-key from inline PEM or filesystem path.
pub fn load_pem_or_path(value: &str) -> Result<String, Hysteria2ProtocolError> {
    if value.contains("-----BEGIN") {
        Ok(value.to_owned())
    } else if value.trim().is_empty() {
        Err(Hysteria2ProtocolError::Protocol(
            "TLS PEM value is empty".to_owned(),
        ))
    } else {
        std::fs::read_to_string(value).map_err(Hysteria2ProtocolError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_header_matching_is_case_insensitive() {
        let mut headers = http::HeaderMap::new();
        headers.insert("Hysteria-Auth", http::HeaderValue::from_static("secret"));
        assert_eq!(auth_password_from_headers(&headers), Some("secret"));

        let mut lower = http::HeaderMap::new();
        lower.insert("hysteria-auth", http::HeaderValue::from_static("secret2"));
        assert_eq!(auth_password_from_headers(&lower), Some("secret2"));
    }

    #[test]
    fn password_table_inverts_name_to_password_map() {
        let table = password_user_table([("alice", "pw-a"), ("bob", "pw-b")]);
        assert_eq!(lookup_user(&table, "pw-a"), Some("alice"));
        assert_eq!(lookup_user(&table, "pw-b"), Some("bob"));
        assert_eq!(lookup_user(&table, "missing"), None);
    }

    #[test]
    fn is_auth_request_requires_post_hysteria_auth_path() {
        let uri: http::Uri = "https://hysteria/auth".parse().unwrap();
        assert!(is_auth_request(&http::Method::POST, &uri));
        assert!(!is_auth_request(&http::Method::GET, &uri));
        let bad: http::Uri = "https://hysteria/other".parse().unwrap();
        assert!(!is_auth_request(&http::Method::POST, &bad));
    }

    #[test]
    fn tcp_request_response_round_trip() {
        let destination = Destination {
            host: Host::Domain("example.com".to_owned()),
            port: 443,
        };
        let request = encode_tcp_request(&destination).expect("encode request");
        let (parsed, consumed) = parse_tcp_request(&request).expect("parse request");
        assert_eq!(parsed, destination);
        assert_eq!(consumed, request.len());

        let response = encode_tcp_response_ok().expect("encode response");
        assert_eq!(response[0], 0);
        // status + empty msg varint + pad varint + padding
        assert!(response.len() >= 3);
    }

    #[test]
    fn parse_destination_supports_ipv4_ipv6_and_domain() {
        let v4 = parse_destination_authority("127.0.0.1:8080").unwrap();
        assert_eq!(v4.port, 8080);
        let v6 = parse_destination_authority("[::1]:9").unwrap();
        assert_eq!(v6.port, 9);
        let domain = parse_destination_authority("echo.test:80").unwrap();
        assert_eq!(domain.host, Host::Domain("echo.test".to_owned()));
    }

    #[test]
    fn malformed_tcp_request_corpus_never_panics() {
        let mut corpus = vec![vec![], vec![0], vec![0x40, 0x01], vec![0xff; 16]];
        for length in 0..=96_usize {
            corpus.push(
                (0..length)
                    .map(|index| u8::try_from((index * 17 + length) & 0xff).unwrap())
                    .collect(),
            );
        }
        for bytes in corpus {
            let _ = parse_tcp_request(&bytes);
            let _ = parse_tcp_request_buf(&bytes);
        }
    }
}

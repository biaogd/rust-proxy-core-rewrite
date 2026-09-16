//! TUIC v5 server Accept: TLS-exporter auth, TCP Connect, and QUIC endpoint bind.
//!
//! Wire framing lives here; listen/route/caps are owned by the runtime listener.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::congestion::{BbrConfig, CubicConfig};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{EndpointConfig, Runtime, TokioRuntime};
use rewrite_model::Destination;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::ServerConfig;
use uuid::Uuid;

use crate::CongestionController;
use crate::TuicProtocolError;
use crate::protocol::{
    CMD_CONNECT, ERR_AUTHENTICATION_FAILED, VERSION, decode_authenticate,
};
use crate::tls::{
    DEFAULT_CONNECTION_RECEIVE_WINDOW, DEFAULT_MAX_IDLE_TIMEOUT, DEFAULT_STREAM_RECEIVE_WINDOW,
};

/// Successful Authenticate Accept: UUID string used as inbound user.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerAuthResult {
    pub uuid: Uuid,
    pub user: String,
}

/// Options for binding a TUIC v5 QUIC server endpoint.
#[derive(Clone, Debug)]
pub struct ServerEndpointOptions {
    pub listen: SocketAddr,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub alpn: Vec<String>,
    pub congestion: CongestionController,
    pub max_idle_timeout: Duration,
    pub stream_receive_window: u64,
    pub connection_receive_window: u64,
    pub max_concurrent_bidi_streams: u32,
    pub max_concurrent_uni_streams: u32,
}

impl Default for ServerEndpointOptions {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            certificate_pem: String::new(),
            private_key_pem: String::new(),
            alpn: vec!["h3".to_owned()],
            congestion: CongestionController::Cubic,
            max_idle_timeout: DEFAULT_MAX_IDLE_TIMEOUT,
            stream_receive_window: DEFAULT_STREAM_RECEIVE_WINDOW,
            connection_receive_window: DEFAULT_CONNECTION_RECEIVE_WINDOW,
            max_concurrent_bidi_streams: 1024,
            max_concurrent_uni_streams: 1024,
        }
    }
}

/// Build UUID→password table from Clash `users` (uuid string → password).
///
/// # Errors
///
/// Returns when a key is not a valid UUID.
pub fn users_table<I, S1, S2>(
    users: I,
) -> Result<HashMap<[u8; 16], String>, TuicProtocolError>
where
    I: IntoIterator<Item = (S1, S2)>,
    S1: AsRef<str>,
    S2: Into<String>,
{
    let mut table = HashMap::new();
    for (uuid_raw, password) in users {
        let uuid = Uuid::parse_str(uuid_raw.as_ref().trim()).map_err(|_| {
            TuicProtocolError::Protocol(format!(
                "invalid TUIC user uuid: {}",
                uuid_raw.as_ref()
            ))
        })?;
        table.insert(*uuid.as_bytes(), password.into());
    }
    Ok(table)
}

/// Compute the TLS exporter token (Go `GenToken`).
///
/// # Errors
///
/// Returns when the QUIC/TLS stack cannot export keying material.
pub fn compute_token(
    connection: &quinn::Connection,
    uuid: [u8; 16],
    password: &str,
) -> Result<[u8; 32], TuicProtocolError> {
    let mut token = [0_u8; 32];
    connection
        .export_keying_material(&mut token, &uuid, password.as_bytes())
        .map_err(|error| TuicProtocolError::Protocol(format!("TLS exporter failed: {error:?}")))?;
    Ok(token)
}

/// Verify an Authenticate frame against the configured users map.
///
/// # Errors
///
/// Returns when framing is invalid. Authentication failure is `Ok(None)`.
pub fn verify_authenticate(
    connection: &quinn::Connection,
    users: &HashMap<[u8; 16], String>,
    buf: &[u8],
) -> Result<Option<ServerAuthResult>, TuicProtocolError> {
    let (uuid_bytes, token) = decode_authenticate(buf)?;
    let Some(password) = users.get(&uuid_bytes) else {
        return Ok(None);
    };
    let expected = compute_token(connection, uuid_bytes, password)?;
    if expected != token {
        return Ok(None);
    }
    let uuid = Uuid::from_bytes(uuid_bytes);
    Ok(Some(ServerAuthResult {
        uuid,
        user: uuid.to_string(),
    }))
}

/// Read and verify Authenticate from a uni-stream body.
///
/// # Errors
///
/// Returns I/O or framing failures. Wrong credentials yield `Ok(None)`.
pub async fn authenticate_uni_stream(
    connection: &quinn::Connection,
    mut recv: quinn::RecvStream,
    users: &HashMap<[u8; 16], String>,
) -> Result<Option<ServerAuthResult>, TuicProtocolError> {
    let mut buf = vec![0_u8; 50];
    let mut filled = 0_usize;
    while filled < 50 {
        let n = recv
            .read(&mut buf[filled..])
            .await
            .map_err(|error| TuicProtocolError::Io(std::io::Error::other(error.to_string())))?
            .ok_or_else(|| {
                TuicProtocolError::Protocol("authenticate stream closed early".to_owned())
            })?;
        filled += n;
    }
    // Authenticate is fixed-size; ignore trailing bytes if any.
    verify_authenticate(connection, users, &buf[..50])
}

/// Close the connection with AuthenticationFailed.
pub fn close_authentication_failed(connection: &quinn::Connection) {
    connection.close(ERR_AUTHENTICATION_FAILED.into(), b"AuthenticationFailed");
}

/// Close the connection with AuthenticationTimeout.
pub fn close_authentication_timeout(connection: &quinn::Connection) {
    connection.close(
        crate::protocol::ERR_AUTHENTICATION_TIMEOUT.into(),
        b"AuthenticationTimeout",
    );
}

/// Accept a TCP Connect on an already-accepted bidi stream.
///
/// # Errors
///
/// Returns when the Connect header is truncated or invalid.
pub async fn accept_tcp_connect(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(Destination, TuicServerStream), TuicProtocolError> {
    let mut scratch = Vec::with_capacity(64);
    loop {
        if scratch.len() >= 2 {
            match try_parse_connect(&scratch)? {
                Some((destination, consumed)) => {
                    let leftover = if consumed < scratch.len() {
                        scratch[consumed..].to_vec()
                    } else {
                        Vec::new()
                    };
                    return Ok((
                        destination,
                        TuicServerStream {
                            send,
                            recv,
                            write_closed: false,
                            leftover,
                            leftover_pos: 0,
                        },
                    ));
                }
                None => {}
            }
        }
        if scratch.len() >= 2048 {
            return Err(TuicProtocolError::Protocol(
                "TUIC connect header exceeded size bound".to_owned(),
            ));
        }
        let mut tmp = [0_u8; 256];
        let n = recv
            .read(&mut tmp)
            .await
            .map_err(|error| TuicProtocolError::Io(std::io::Error::other(error.to_string())))?
            .ok_or_else(|| {
                TuicProtocolError::Protocol("stream closed before connect".to_owned())
            })?;
        scratch.extend_from_slice(&tmp[..n]);
    }
}

fn try_parse_connect(buf: &[u8]) -> Result<Option<(Destination, usize)>, TuicProtocolError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    if buf[0] != VERSION {
        return Err(TuicProtocolError::Protocol(format!(
            "unsupported TUIC version {:#04x}",
            buf[0]
        )));
    }
    if buf[1] != CMD_CONNECT {
        return Err(TuicProtocolError::Protocol(format!(
            "expected connect, got {:#04x}",
            buf[1]
        )));
    }
    match crate::protocol::decode_optional_address(&buf[2..]) {
        Ok((Some(destination), addr_len)) => Ok(Some((destination, 2 + addr_len))),
        Ok((None, _)) => Err(TuicProtocolError::Protocol(
            "TUIC connect address type none is invalid".to_owned(),
        )),
        Err(TuicProtocolError::Protocol(message))
            if message.contains("truncated") || message.contains("Truncated") =>
        {
            // Incomplete address — wait for more bytes.
            let _ = message;
            Ok(None)
        }
        Err(error) => {
            // decode_address errors on truncated buffers with "truncated …".
            let text = error.to_string();
            if text.contains("truncated") {
                Ok(None)
            } else {
                Err(error)
            }
        }
    }
}

/// Server-side TCP proxy stream after Connect has been parsed.
pub struct TuicServerStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    write_closed: bool,
    leftover: Vec<u8>,
    leftover_pos: usize,
}

impl AsyncRead for TuicServerStream {
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

impl AsyncWrite for TuicServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        <quinn::SendStream as AsyncWrite>::poll_write(Pin::new(&mut self.send), context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_flush(Pin::new(&mut self.send), context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        match <quinn::SendStream as AsyncWrite>::poll_shutdown(Pin::new(&mut self.send), context) {
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
) -> Result<ServerConfig, TuicProtocolError> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut cert_cursor = std::io::Cursor::new(certificate_pem.as_bytes());
    let certificates = rustls_pemfile::certs(&mut cert_cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TuicProtocolError::Protocol(error.to_string()))?;
    if certificates.is_empty() {
        return Err(TuicProtocolError::Protocol(
            "certificate not found".to_owned(),
        ));
    }
    let mut key_cursor = std::io::Cursor::new(private_key_pem.as_bytes());
    let private_key = rustls_pemfile::private_key(&mut key_cursor)
        .map_err(|error| TuicProtocolError::Protocol(error.to_string()))?
        .ok_or_else(|| TuicProtocolError::Protocol("private key not found".to_owned()))?;
    let mut crypto = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|error| TuicProtocolError::Protocol(error.to_string()))?;
    crypto.alpn_protocols = if alpn.is_empty() {
        vec![b"h3".to_vec()]
    } else {
        alpn.iter().map(|value| value.as_bytes().to_vec()).collect()
    };
    crypto.max_early_data_size = u32::MAX;
    Ok(crypto)
}

/// Bind a TUIC v5 QUIC server endpoint.
///
/// # Errors
///
/// Returns when PEM material, QUIC config, or UDP bind fails.
pub fn bind_server_endpoint(
    options: &ServerEndpointOptions,
) -> Result<quinn::Endpoint, TuicProtocolError> {
    let crypto = load_server_crypto(
        &options.certificate_pem,
        &options.private_key_pem,
        &options.alpn,
    )?;
    let quic = QuicServerConfig::try_from(crypto)
        .map_err(|error| TuicProtocolError::Quinn(error.to_string()))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        options
            .max_idle_timeout
            .try_into()
            .map_err(|error| TuicProtocolError::Quinn(format!("{error}")))?,
    ));
    transport.stream_receive_window(
        quinn::VarInt::from_u64(options.stream_receive_window)
            .map_err(|error| TuicProtocolError::Quinn(error.to_string()))?,
    );
    transport.receive_window(
        quinn::VarInt::from_u64(options.connection_receive_window)
            .map_err(|error| TuicProtocolError::Quinn(error.to_string()))?,
    );
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(options.max_concurrent_bidi_streams));
    transport
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(options.max_concurrent_uni_streams));
    match options.congestion {
        CongestionController::Cubic | CongestionController::NewReno => {
            transport.congestion_controller_factory(Arc::new(CubicConfig::default()));
        }
        CongestionController::Bbr => {
            transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
        }
    }
    transport.datagram_receive_buffer_size(Some(65_535));
    transport.datagram_send_buffer_size(65_535);
    server_config.transport_config(Arc::new(transport));

    let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    let std_sock = std::net::UdpSocket::bind(options.listen).map_err(TuicProtocolError::Io)?;
    std_sock
        .set_nonblocking(true)
        .map_err(TuicProtocolError::Io)?;
    quinn::Endpoint::new(EndpointConfig::default(), Some(server_config), std_sock, runtime)
        .map_err(TuicProtocolError::Io)
}

/// Load PEM certificate/private-key from inline PEM or filesystem path.
///
/// # Errors
///
/// Returns when the value is empty or the path cannot be read.
pub fn load_pem_or_path(value: &str) -> Result<String, TuicProtocolError> {
    if value.contains("-----BEGIN") {
        Ok(value.to_owned())
    } else if value.trim().is_empty() {
        Err(TuicProtocolError::Protocol(
            "TLS PEM value is empty".to_owned(),
        ))
    } else {
        std::fs::read_to_string(value).map_err(TuicProtocolError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{encode_authenticate, encode_connect};
    use rewrite_model::{Destination, Host};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn users_table_parses_uuid_keys() {
        let table = users_table([(
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            "secret",
        )])
        .expect("users");
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        assert_eq!(table.get(uuid.as_bytes()).map(String::as_str), Some("secret"));
    }

    #[test]
    fn decode_authenticate_round_trip() {
        let uuid = [0x11; 16];
        let token = [0x22; 32];
        let frame = encode_authenticate(uuid, token);
        let (decoded_uuid, decoded_token) = decode_authenticate(&frame).expect("decode");
        assert_eq!(decoded_uuid, uuid);
        assert_eq!(decoded_token, token);
    }

    #[test]
    fn accept_connect_parse_handles_partial_and_full() {
        let destination = Destination {
            host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: 9,
        };
        let frame = encode_connect(&destination).expect("encode");
        assert!(matches!(try_parse_connect(&frame[..3]), Ok(None)));
        let (parsed, consumed) = try_parse_connect(&frame)
            .expect("parse")
            .expect("complete");
        assert_eq!(parsed, destination);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn authenticate_command_byte_is_zero() {
        assert_eq!(CMD_AUTHENTICATE, 0);
    }
}

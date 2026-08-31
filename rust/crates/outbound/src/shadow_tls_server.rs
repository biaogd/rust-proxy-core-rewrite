use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::BoxedOutboundStream;
use crate::shadow_tls::{
    APPLICATION_DATA, HANDSHAKE, HMAC_SIZE, SERVER_HELLO, SERVER_RANDOM_INDEX,
    SESSION_ID_LENGTH_INDEX, ShadowTlsError, TLS_HEADER_SIZE, TLS_HMAC_HEADER_SIZE,
    TLS_SESSION_ID_SIZE, VerifiedStream, is_server_hello_tls13, kdf, set_tls_record_length,
    verify_application_data, xor_slice,
};

type HmacSha1 = Hmac<Sha1>;

pub type ShadowTlsHandshakeDial = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<BoxedOutboundStream, io::Error>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone, Debug)]
pub struct ShadowTlsServerConfig {
    pub version: u8,
    pub password: String,
    pub users: Vec<(String, String)>,
    pub handshake_dest: String,
    pub strict_mode: bool,
}

/// Outcome of a completed `ShadowTLS` v3 accept attempt.
pub enum ShadowTlsAcceptResult {
    /// Camouflage TLS finished; inner stream carries post-handshake SS bytes.
    Authenticated {
        stream: BoxedOutboundStream,
        user: String,
    },
    /// Client was relayed to the handshake destination (probe/wrong password/plain TLS).
    FallbackCompleted,
}

/// Accept a `ShadowTLS` v3 inbound connection.
///
/// On authentication failure or post-handshake fallback, relays the client to the
/// handshake destination and returns [`ShadowTlsAcceptResult::FallbackCompleted`].
///
/// # Errors
///
/// Returns [`ShadowTlsError`] when I/O fails or the TLS framing is invalid during
/// an authenticated handshake.
pub async fn accept_shadow_tls_v3<S>(
    mut client: S,
    config: &ShadowTlsServerConfig,
    handshake_dial: &ShadowTlsHandshakeDial,
) -> Result<ShadowTlsAcceptResult, ShadowTlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if config.version != 3 {
        return Err(ShadowTlsError::Protocol(format!(
            "shadow-tls inbound version {} is not supported yet",
            config.version
        )));
    }

    let client_hello = read_tls_frame(&mut client).await?;
    let Ok(user) = verify_client_hello(&client_hello, &config.users) else {
        let mut handshake = (handshake_dial)().await.map_err(ShadowTlsError::Io)?;
        relay_fallback(client, &mut handshake, Some(client_hello)).await?;
        return Ok(ShadowTlsAcceptResult::FallbackCompleted);
    };

    let mut handshake = (handshake_dial)().await.map_err(ShadowTlsError::Io)?;
    handshake
        .write_all(&client_hello)
        .await
        .map_err(ShadowTlsError::Io)?;
    let server_hello = read_tls_frame(&mut handshake).await?;
    client
        .write_all(&server_hello)
        .await
        .map_err(ShadowTlsError::Io)?;

    let Some(server_random) = extract_server_random(&server_hello) else {
        relay_fallback(client, &mut handshake, None).await?;
        return Ok(ShadowTlsAcceptResult::FallbackCompleted);
    };
    if config.strict_mode && !is_server_hello_tls13(&server_hello) {
        relay_fallback(client, &mut handshake, None).await?;
        return Ok(ShadowTlsAcceptResult::FallbackCompleted);
    }

    let mut hmac_write = HmacSha1::new_from_slice(user.1.as_bytes())
        .map_err(|error| ShadowTlsError::Protocol(format!("HMAC key: {error}")))?;
    hmac_write.update(&server_random);
    let mut hmac_add = HmacSha1::new_from_slice(user.1.as_bytes())
        .map_err(|error| ShadowTlsError::Protocol(format!("HMAC key: {error}")))?;
    hmac_add.update(&server_random);
    hmac_add.update(b"S");
    let mut hmac_verify = HmacSha1::new_from_slice(user.1.as_bytes())
        .map_err(|error| ShadowTlsError::Protocol(format!("HMAC key: {error}")))?;
    hmac_verify.update(&server_random);
    hmac_verify.update(b"C");
    let pending = relay_v3_handshake(
        &mut client,
        &mut handshake,
        &user.1,
        &server_random,
        &mut hmac_write,
        &mut hmac_verify,
    )
    .await?;
    Ok(ShadowTlsAcceptResult::Authenticated {
        stream: Box::new(VerifiedStream::from_server(
            Box::new(client) as BoxedOutboundStream,
            hmac_add,
            hmac_verify,
            pending,
        )) as BoxedOutboundStream,
        user: user.0,
    })
}

async fn relay_fallback<S>(
    mut client: S,
    handshake: &mut BoxedOutboundStream,
    prefix: Option<Vec<u8>>,
) -> Result<(), ShadowTlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    if let Some(prefix) = prefix.filter(|data| !data.is_empty()) {
        handshake
            .write_all(&prefix)
            .await
            .map_err(ShadowTlsError::Io)?;
    }
    tokio::io::copy_bidirectional(&mut client, handshake)
        .await
        .map_err(ShadowTlsError::Io)?;
    Ok(())
}

async fn relay_v3_handshake<S>(
    client: &mut S,
    handshake: &mut BoxedOutboundStream,
    password: &str,
    server_random: &[u8; 32],
    hmac_write: &mut HmacSha1,
    hmac_verify: &mut HmacSha1,
) -> Result<Vec<u8>, ShadowTlsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let write_key = kdf(password, server_random);
    loop {
        tokio::select! {
            biased;
            frame = read_tls_frame(handshake) => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(ShadowTlsError::Io(error))
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                        ) =>
                    {
                        break;
                    }
                    Err(error) => return Err(error),
                };
                forward_server_frame(client, &frame, &write_key, hmac_write).await?;
            }
            frame = read_tls_frame(client) => {
                let frame = frame?;
                if frame.len() > TLS_HMAC_HEADER_SIZE && frame[0] == APPLICATION_DATA {
                    reset_hmac_verify(hmac_verify, server_random, password);
                    if verify_application_data(&frame, hmac_verify, false) {
                        reset_hmac_verify(hmac_verify, server_random, password);
                        hmac_verify.update(&frame[TLS_HMAC_HEADER_SIZE..]);
                        hmac_verify.update(&frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]);
                        return Ok(frame[TLS_HMAC_HEADER_SIZE..].to_vec());
                    }
                }
                handshake
                    .write_all(&frame)
                    .await
                    .map_err(ShadowTlsError::Io)?;
            }
        }
    }
    Ok(Vec::new())
}

async fn forward_server_frame(
    client: &mut (impl AsyncWrite + Unpin),
    frame: &[u8],
    write_key: &[u8],
    hmac_write: &mut HmacSha1,
) -> Result<(), ShadowTlsError> {
    if frame[0] != APPLICATION_DATA {
        client.write_all(frame).await.map_err(ShadowTlsError::Io)?;
        return Ok(());
    }
    let mut modified = frame.to_vec();
    xor_slice(&mut modified[TLS_HEADER_SIZE..], write_key);
    hmac_write.update(&modified[TLS_HEADER_SIZE..]);
    let record_length = modified.len() - TLS_HEADER_SIZE + HMAC_SIZE;
    set_tls_record_length(&mut modified, record_length).map_err(ShadowTlsError::Io)?;
    let hmac_hash = hmac_write.clone().finalize().into_bytes()[..HMAC_SIZE].to_vec();
    client
        .write_all(&modified[..TLS_HEADER_SIZE])
        .await
        .map_err(ShadowTlsError::Io)?;
    client
        .write_all(&hmac_hash)
        .await
        .map_err(ShadowTlsError::Io)?;
    client
        .write_all(&modified[TLS_HEADER_SIZE..])
        .await
        .map_err(ShadowTlsError::Io)?;
    Ok(())
}

async fn read_tls_frame(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, ShadowTlsError> {
    let mut header = [0_u8; TLS_HEADER_SIZE];
    reader
        .read_exact(&mut header)
        .await
        .map_err(ShadowTlsError::Io)?;
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut frame = vec![0_u8; TLS_HEADER_SIZE + length];
    frame[..TLS_HEADER_SIZE].copy_from_slice(&header);
    reader
        .read_exact(&mut frame[TLS_HEADER_SIZE..])
        .await
        .map_err(ShadowTlsError::Io)?;
    Ok(frame)
}

fn verify_client_hello(
    frame: &[u8],
    users: &[(String, String)],
) -> Result<(String, String), ShadowTlsError> {
    const MIN_LENGTH: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + 32 + 1 + TLS_SESSION_ID_SIZE;
    const HMAC_INDEX: usize = SESSION_ID_LENGTH_INDEX + 1 + TLS_SESSION_ID_SIZE - HMAC_SIZE;
    if frame.len() < MIN_LENGTH {
        return Err(ShadowTlsError::Protocol(
            "shadow-tls: truncated ClientHello".to_owned(),
        ));
    }
    if frame[0] != HANDSHAKE || frame[TLS_HEADER_SIZE] != 1 {
        return Err(ShadowTlsError::Protocol(
            "shadow-tls: unexpected ClientHello record".to_owned(),
        ));
    }
    if frame[SESSION_ID_LENGTH_INDEX] != u8::try_from(TLS_SESSION_ID_SIZE).expect("session id") {
        return Err(ShadowTlsError::Protocol(
            "shadow-tls: unexpected session ID length".to_owned(),
        ));
    }
    for (name, password) in users {
        let mut mac = HmacSha1::new_from_slice(password.as_bytes())
            .map_err(|error| ShadowTlsError::Protocol(format!("HMAC key: {error}")))?;
        mac.update(&frame[TLS_HEADER_SIZE..HMAC_INDEX]);
        mac.update(&[0, 0, 0, 0]);
        mac.update(&frame[HMAC_INDEX + HMAC_SIZE..]);
        if mac.finalize().into_bytes()[..HMAC_SIZE] == frame[HMAC_INDEX..HMAC_INDEX + HMAC_SIZE] {
            return Ok((name.clone(), password.clone()));
        }
    }
    Err(ShadowTlsError::Protocol(
        "shadow-tls: ClientHello HMAC mismatch".to_owned(),
    ))
}

fn extract_server_random(frame: &[u8]) -> Option<[u8; 32]> {
    if frame.len() < SERVER_RANDOM_INDEX + 32
        || frame[0] != HANDSHAKE
        || frame[TLS_HEADER_SIZE] != SERVER_HELLO
    {
        return None;
    }
    let mut server_random = [0_u8; 32];
    server_random.copy_from_slice(&frame[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + 32]);
    Some(server_random)
}

fn reset_hmac_verify(hmac_verify: &mut HmacSha1, server_random: &[u8; 32], password: &str) {
    *hmac_verify = HmacSha1::new_from_slice(password.as_bytes()).expect("HMAC key");
    hmac_verify.update(server_random);
    hmac_verify.update(b"C");
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener as StdTcpListener};
    use std::sync::Arc;

    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    fn local_dial(addr: SocketAddr) -> ShadowTlsHandshakeDial {
        Arc::new(move || {
            let addr = addr;
            Box::pin(async move {
                TcpStream::connect(addr)
                    .await
                    .map(|stream| Box::new(stream) as BoxedOutboundStream)
            })
        })
    }

    #[tokio::test]
    async fn hmac_mismatch_replays_client_hello_to_handshake_server() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind");
        let hs_addr = listener.local_addr().expect("addr");
        let hs_task = tokio::task::spawn_blocking(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0_u8; 4096];
            let read = stream.read(&mut buf).expect("read");
            assert!(read >= 5);
            assert_eq!(buf[0], HANDSHAKE);
            stream
                .write_all(&[0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00])
                .ok();
        });

        let server = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let server_addr = server.local_addr().expect("addr");
        let accept_task = tokio::spawn(async move {
            let (inbound, _) = server.accept().await.expect("accept");
            let config = ShadowTlsServerConfig {
                version: 3,
                password: String::new(),
                users: vec![("alice".to_owned(), "secret".to_owned())],
                handshake_dest: hs_addr.to_string(),
                strict_mode: false,
            };
            let dial = local_dial(hs_addr);
            accept_shadow_tls_v3(inbound, &config, &dial).await
        });

        let client_task = tokio::spawn(async move {
            let mut stream = TcpStream::connect(server_addr).await.expect("connect");
            stream
                .write_all(&[0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
                .await
                .expect("write");
            stream.shutdown().await.ok();
        });

        let result = accept_task.await.expect("accept task").expect("accept");
        assert!(matches!(result, ShadowTlsAcceptResult::FallbackCompleted));
        client_task.await.expect("client");
        hs_task.await.expect("hs");
    }

    #[tokio::test]
    async fn parallel_fallback_connections_complete_independently() {
        let hs_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind");
        let hs_addr = hs_listener.local_addr().expect("addr");
        let hs_task = tokio::task::spawn_blocking(move || {
            for _ in 0..2 {
                let (mut stream, _) = hs_listener.accept().expect("accept");
                let mut buf = [0_u8; 4096];
                let _ = stream.read(&mut buf);
            }
        });

        let server = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let server_addr = server.local_addr().expect("addr");
        let config = ShadowTlsServerConfig {
            version: 3,
            password: String::new(),
            users: vec![("alice".to_owned(), "secret".to_owned())],
            handshake_dest: hs_addr.to_string(),
            strict_mode: false,
        };
        let dial = local_dial(hs_addr);

        let accept_task = tokio::spawn(async move {
            let mut joins = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let (inbound, _) = server.accept().await.expect("accept");
                let config = config.clone();
                let dial = Arc::clone(&dial);
                joins.spawn(async move { accept_shadow_tls_v3(inbound, &config, &dial).await });
            }
            let mut results = Vec::new();
            while let Some(result) = joins.join_next().await {
                results.push(result.expect("join").expect("accept"));
            }
            results
        });

        for _ in 0..2 {
            let client = tokio::spawn(async move {
                let mut stream = TcpStream::connect(server_addr).await.expect("connect");
                stream
                    .write_all(&[0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
                    .await
                    .expect("write");
                stream.shutdown().await.ok();
            });
            client.await.expect("client");
        }

        let results = accept_task.await.expect("accept task");
        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .all(|result| matches!(result, ShadowTlsAcceptResult::FallbackCompleted))
        );
        hs_task.await.expect("hs");
    }

    #[tokio::test]
    async fn fallback_drains_server_response_after_half_close() {
        let hs_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind");
        let hs_addr = hs_listener.local_addr().expect("addr");
        let hs_task = tokio::task::spawn_blocking(move || {
            let (mut stream, _) = hs_listener.accept().expect("accept");
            stream.write_all(b"server-response").expect("write");
            stream.shutdown(std::net::Shutdown::Write).ok();
            let mut buf = [0_u8; 256];
            while stream.read(&mut buf).unwrap_or(0) > 0 {}
        });

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let relay_addr = relay_listener.local_addr().expect("addr");
        let relay_task = tokio::spawn(async move {
            let (mut inbound, _) = relay_listener.accept().await.expect("accept");
            let mut upstream: BoxedOutboundStream =
                Box::new(TcpStream::connect(hs_addr).await.expect("connect"));
            relay_fallback(&mut inbound, &mut upstream, None).await
        });

        let mut probe = TcpStream::connect(relay_addr).await.expect("connect");
        probe.write_all(b"probe").await.expect("write");
        probe.shutdown().await.ok();
        let mut response = Vec::new();
        probe
            .read_to_end(&mut response)
            .await
            .expect("read response");
        assert_eq!(response, b"server-response");
        relay_task.await.expect("relay").expect("fallback");
        hs_task.await.expect("hs");
    }
}

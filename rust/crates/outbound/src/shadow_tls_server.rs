use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::BoxedOutboundStream;
use crate::shadow_tls::{
    APPLICATION_DATA, HANDSHAKE, HMAC_SIZE, SERVER_HELLO, SERVER_RANDOM_INDEX,
    SESSION_ID_LENGTH_INDEX, ShadowTlsError, TLS_HEADER_SIZE, TLS_HMAC_HEADER_SIZE,
    TLS_SESSION_ID_SIZE, VerifiedStream, is_server_hello_tls13, kdf, set_tls_record_length,
    verify_application_data, xor_slice,
};

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone, Debug)]
pub struct ShadowTlsServerConfig {
    pub version: u8,
    pub password: String,
    pub users: Vec<(String, String)>,
    pub handshake_dest: String,
    pub strict_mode: bool,
}

pub struct ShadowTlsServer<S> {
    config: ShadowTlsServerConfig,
    state: ServerState<S>,
}

enum ServerState<S> {
    Initial(Option<S>),
    Handshaking(Pin<Box<dyn Future<Output = Result<VerifiedStream, ShadowTlsError>> + Send>>),
    Ready(Box<VerifiedStream>),
    Failed(io::Error),
}

impl<S> ShadowTlsServer<S> {
    pub fn new(inner: S, config: ShadowTlsServerConfig) -> Self {
        Self {
            config,
            state: ServerState::Initial(Some(inner)),
        }
    }

    fn start_handshake(&mut self) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let ServerState::Initial(inner) = &mut self.state else {
            return Ok(());
        };
        let Some(inner) = inner.take() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "shadow-tls server handshake already started",
            ));
        };
        let config = self.config.clone();
        self.state = ServerState::Handshaking(Box::pin(async move {
            match config.version {
                3 => accept_shadow_tls_v3(inner, &config).await,
                other => Err(ShadowTlsError::Protocol(format!(
                    "shadow-tls inbound version {other} is not supported yet"
                ))),
            }
        }));
        Ok(())
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let ServerState::Handshaking(future) = &mut self.state else {
            return Poll::Ready(Ok(()));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready(Ok(stream)) => {
                self.state = ServerState::Ready(Box::new(stream));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                let io_error = io::Error::new(io::ErrorKind::InvalidData, error.to_string());
                let kind = io_error.kind();
                self.state = ServerState::Failed(io_error);
                Poll::Ready(Err(io::Error::new(
                    kind,
                    "shadow-tls server handshake failed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncRead for ShadowTlsServer<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match &mut self.state {
                ServerState::Initial(_) => {
                    self.start_handshake()?;
                }
                ServerState::Handshaking(_) => ready!(self.poll_handshake(cx))?,
                ServerState::Ready(stream) => return Pin::new(stream).poll_read(cx, buf),
                ServerState::Failed(error) => {
                    return Poll::Ready(Err(io::Error::new(error.kind(), error.to_string())));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncWrite for ShadowTlsServer<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match &mut self.state {
                ServerState::Initial(_) => {
                    self.start_handshake()?;
                }
                ServerState::Handshaking(_) => ready!(self.poll_handshake(cx))?,
                ServerState::Ready(stream) => return Pin::new(stream).poll_write(cx, buf),
                ServerState::Failed(error) => {
                    return Poll::Ready(Err(io::Error::new(error.kind(), error.to_string())));
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.state {
            ServerState::Ready(stream) => Pin::new(stream).poll_flush(cx),
            ServerState::Failed(error) => {
                Poll::Ready(Err(io::Error::new(error.kind(), error.to_string())))
            }
            _ => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.state {
            ServerState::Ready(stream) => Pin::new(stream).poll_shutdown(cx),
            ServerState::Failed(error) => {
                Poll::Ready(Err(io::Error::new(error.kind(), error.to_string())))
            }
            _ => Poll::Ready(Ok(())),
        }
    }
}

async fn accept_shadow_tls_v3<S>(
    mut client: S,
    config: &ShadowTlsServerConfig,
) -> Result<VerifiedStream, ShadowTlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let client_hello = read_tls_frame(&mut client).await?;
    let user = verify_client_hello(&client_hello, &config.users)?;
    let mut handshake = TcpStream::connect(&config.handshake_dest)
        .await
        .map_err(|error| ShadowTlsError::Protocol(format!("dial handshake server: {error}")))?;
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
        relay_fallback(client, handshake, client_hello).await?;
        return Err(ShadowTlsError::Protocol(
            "shadow-tls: connection relayed to fallback".to_owned(),
        ));
    };
    if config.strict_mode && !is_server_hello_tls13(&server_hello) {
        relay_fallback(client, handshake, client_hello).await?;
        return Err(ShadowTlsError::Protocol(
            "shadow-tls: connection relayed to fallback".to_owned(),
        ));
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
    Ok(VerifiedStream::from_server(
        Box::new(client) as BoxedOutboundStream,
        hmac_add,
        hmac_verify,
        pending,
    ))
}

async fn relay_fallback<S>(
    mut client: S,
    mut handshake: TcpStream,
    prefix: Vec<u8>,
) -> Result<(), ShadowTlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    if !prefix.is_empty() {
        handshake
            .write_all(&prefix)
            .await
            .map_err(ShadowTlsError::Io)?;
    }
    let mut client_buffer = vec![0_u8; 16_384];
    let mut handshake_buffer = vec![0_u8; 16_384];
    loop {
        tokio::select! {
            read = client.read(&mut client_buffer) => {
                match read.map_err(ShadowTlsError::Io)? {
                    0 => break,
                    count => handshake.write_all(&client_buffer[..count]).await.map_err(ShadowTlsError::Io)?,
                }
            }
            read = handshake.read(&mut handshake_buffer) => {
                match read.map_err(ShadowTlsError::Io)? {
                    0 => break,
                    count => client.write_all(&handshake_buffer[..count]).await.map_err(ShadowTlsError::Io)?,
                }
            }
        }
    }
    Ok(())
}

async fn relay_v3_handshake<S>(
    client: &mut S,
    handshake: &mut TcpStream,
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

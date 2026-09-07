//! JLS client carrier (Go `transport/jls` / Clash `jls-opts`).
//!
//! Wire crypto matches `github.com/metacubex/jls-tls` and `rustls-jls`:
//! username → IV material, password → key material. Successful JLS auth skips
//! certificate verification on the client (same as rustls-jls / Go client).

use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use rustls_jls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls_jls::jls::{JlsClientConfig, JlsState};
use rustls_jls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls_jls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxedStream;

#[derive(Debug, thiserror::Error)]
pub enum JlsError {
    #[error("jls configuration is invalid: {0}")]
    Configuration(String),
    #[error("jls handshake failed: {0}")]
    Handshake(#[from] io::Error),
    #[error("jls authentication failed")]
    AuthenticationFailed,
}

pub struct JlsConnectOptions<'a> {
    pub host: &'a str,
    pub username: &'a str,
    pub password: &'a str,
    pub alpn: &'a [String],
}

/// Completes a JLS TLS handshake, then returns the cleartext application stream.
///
/// # Errors
///
/// Returns [`JlsError`] when configuration is invalid, the handshake fails, or
/// JLS authentication does not succeed.
pub async fn connect_jls(
    stream: BoxedStream,
    options: JlsConnectOptions<'_>,
) -> Result<BoxedStream, JlsError> {
    if options.username.is_empty() || options.password.is_empty() {
        return Err(JlsError::Configuration(
            "jls username and password are required".to_owned(),
        ));
    }
    let server_name = ServerName::try_from(options.host.to_owned()).map_err(|error| {
        JlsError::Configuration(format!("invalid jls server name {}: {error}", options.host))
    })?;

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
        .with_no_client_auth();
    // Go maps username → rustls-jls user_iv and password → user_pwd.
    config.jls_config = JlsClientConfig::new(options.password, options.username);
    config.alpn_protocols = if options.alpn.is_empty() {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        options
            .alpn
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect()
    };

    let session = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|error| JlsError::Configuration(error.to_string()))?;
    let mut tls = JlsTlsStream {
        io: stream,
        session,
        eof: false,
        need_flush: false,
    };
    std::future::poll_fn(|cx| tls.poll_handshake(cx)).await?;
    if !matches!(tls.session.jls_state(), JlsState::AuthSuccess(_)) {
        return Err(JlsError::AuthenticationFailed);
    }
    Ok(Box::new(tls))
}

#[derive(Debug)]
struct SkipServerVerification {
    algorithms: rustls_jls::crypto::WebPkiSupportedAlgorithms,
}

impl SkipServerVerification {
    fn new() -> Self {
        Self {
            algorithms: rustls_jls::crypto::aws_lc_rs::default_provider()
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
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls_jls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls_jls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

struct JlsTlsStream {
    io: BoxedStream,
    session: ClientConnection,
    eof: bool,
    need_flush: bool,
}

impl JlsTlsStream {
    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut write_would_block = false;
            let mut read_would_block = false;

            while self.session.wants_write() {
                match self.write_tls(cx) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    Poll::Ready(Ok(_)) => self.need_flush = true,
                    Poll::Pending => {
                        write_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                }
            }

            if self.need_flush {
                match Pin::new(&mut self.io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => self.need_flush = false,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => write_would_block = true,
                }
            }

            while !self.eof && self.session.wants_read() {
                match self.read_tls(cx) {
                    Poll::Ready(Ok(0)) => self.eof = true,
                    Poll::Ready(Ok(_)) => {}
                    Poll::Pending => {
                        read_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                }
            }

            return match (self.eof, self.session.is_handshaking()) {
                (true, true) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "jls handshake eof",
                ))),
                (_, false) => Poll::Ready(Ok(())),
                (_, true) if write_would_block || read_would_block => Poll::Pending,
                (..) => continue,
            };
        }
    }

    fn read_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut reader = SyncReadAdapter {
            io: &mut self.io,
            cx,
        };
        match self.session.read_tls(&mut reader) {
            Ok(n) => {
                self.session
                    .process_new_packets()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                Poll::Ready(Ok(n))
            }
            Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn write_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut writer = SyncWriteAdapter {
            io: &mut self.io,
            cx,
        };
        match self.session.write_tls(&mut writer) {
            Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }
}

impl AsyncRead for JlsTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut plaintext = [0_u8; 16_384];
            let take = plaintext.len().min(buf.remaining());
            if take == 0 {
                return Poll::Ready(Ok(()));
            }
            match self.session.reader().read(&mut plaintext[..take]) {
                Ok(0) => return Poll::Ready(Ok(())),
                Ok(n) => {
                    buf.put_slice(&plaintext[..n]);
                    return Poll::Ready(Ok(()));
                }
                Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
            if ready!(self.read_tls(cx))? == 0 {
                self.eof = true;
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl AsyncWrite for JlsTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = self.session.writer().write(buf)?;
        while self.session.wants_write() {
            ready!(self.write_tls(cx))?;
        }
        self.need_flush = true;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            ready!(self.write_tls(cx))?;
        }
        self.need_flush = false;
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            ready!(self.write_tls(cx))?;
        }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

struct SyncReadAdapter<'a, 'b> {
    io: &'a mut BoxedStream,
    cx: &'a mut Context<'b>,
}

impl Read for SyncReadAdapter<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut *self.io).poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

struct SyncWriteAdapter<'a, 'b> {
    io: &'a mut BoxedStream,
    cx: &'a mut Context<'b>,
}

impl Write for SyncWriteAdapter<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut *self.io).poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

use std::io::{self, Read as _};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use rewrite_io::{BoxedStream, VisionDirectControl};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::tls::TlsClientError;

const TLS_RECORD_HEADER_LEN: usize = 5;
const COPY_BUFFER_LEN: usize = 8 * 1024;

/// Prevents rustls from reading beyond one outer TLS record.
///
/// Vision changes the byte interpretation immediately after a framed DIRECT command. Limiting
/// each rustls read to the current record leaves any coalesced raw inner-TLS bytes in the socket,
/// where the promoted stream can consume them without attempting outer-TLS decryption.
struct TlsRecordStream {
    inner: BoxedStream,
    header: [u8; TLS_RECORD_HEADER_LEN],
    header_filled: usize,
    header_emitted: usize,
    body_remaining: usize,
}

impl TlsRecordStream {
    fn new(inner: BoxedStream) -> Self {
        Self {
            inner,
            header: [0; TLS_RECORD_HEADER_LEN],
            header_filled: 0,
            header_emitted: 0,
            body_remaining: 0,
        }
    }

    fn at_record_boundary(&self) -> bool {
        self.header_filled == 0 && self.header_emitted == 0 && self.body_remaining == 0
    }

    fn reset_record(&mut self) {
        self.header_filled = 0;
        self.header_emitted = 0;
        self.body_remaining = 0;
    }

    fn poll_raw_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.at_record_boundary() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XTLS Vision attempted raw read inside an outer TLS record",
            )));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncRead for TlsRecordStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            while self.header_filled < TLS_RECORD_HEADER_LEN {
                let start = self.header_filled;
                let missing = TLS_RECORD_HEADER_LEN - start;
                let mut header = [0_u8; TLS_RECORD_HEADER_LEN];
                let mut header_buf = ReadBuf::new(&mut header[..missing]);
                ready!(Pin::new(&mut self.inner).poll_read(cx, &mut header_buf))?;
                let read = header_buf.filled().len();
                if read == 0 {
                    if self.header_filled == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "outer TLS record ended inside its header",
                    )));
                }
                self.header[start..start + read].copy_from_slice(header_buf.filled());
                self.header_filled += read;
            }

            if self.header_emitted < TLS_RECORD_HEADER_LEN {
                let amount = (TLS_RECORD_HEADER_LEN - self.header_emitted).min(buf.remaining());
                let start = self.header_emitted;
                buf.put_slice(&self.header[start..start + amount]);
                self.header_emitted += amount;
                if self.header_emitted == TLS_RECORD_HEADER_LEN {
                    self.body_remaining = usize::from(u16::from_be_bytes([
                        self.header[TLS_RECORD_HEADER_LEN - 2],
                        self.header[TLS_RECORD_HEADER_LEN - 1],
                    ]));
                    if self.body_remaining == 0 {
                        self.reset_record();
                    }
                }
                return Poll::Ready(Ok(()));
            }

            if self.body_remaining == 0 {
                self.reset_record();
                continue;
            }

            let amount = self
                .body_remaining
                .min(buf.remaining())
                .min(COPY_BUFFER_LEN);
            let mut copy = [0_u8; COPY_BUFFER_LEN];
            let mut body_buf = ReadBuf::new(&mut copy[..amount]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut body_buf))?;
            let read = body_buf.filled().len();
            if read == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "outer TLS record ended inside its payload",
                )));
            }
            buf.put_slice(body_buf.filled());
            self.body_remaining -= read;
            if self.body_remaining == 0 {
                self.reset_record();
            }
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for TlsRecordStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct VisionTlsStream {
    inner: TlsStream<TlsRecordStream>,
    control: VisionDirectControl,
}

impl AsyncRead for VisionTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.control.read_is_direct() {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut plaintext = [0_u8; COPY_BUFFER_LEN];
        let amount = plaintext.len().min(buf.remaining());
        let plaintext_result = self
            .inner
            .get_mut()
            .1
            .reader()
            .read(&mut plaintext[..amount]);
        match plaintext_result {
            Ok(0) => {}
            Ok(read) => {
                buf.put_slice(&plaintext[..read]);
                return Poll::Ready(Ok(()));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Poll::Ready(Err(error)),
        }

        self.inner.get_mut().0.poll_raw_read(cx, buf)
    }
}

impl AsyncWrite for VisionTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.control.write_is_direct() {
            return Pin::new(&mut self.inner.get_mut().0).poll_write(cx, buf);
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.control.write_is_direct() {
            return Pin::new(&mut self.inner.get_mut().0).poll_flush(cx);
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.control.any_is_direct() {
            return Pin::new(&mut self.inner.get_mut().0).poll_shutdown(cx);
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Performs outer TLS and returns a stream that can safely promote each direction to raw TCP.
///
/// # Errors
///
/// Returns an error when the server name is invalid or the TLS handshake fails.
pub async fn connect_vision_tls(
    stream: BoxedStream,
    server_name: &str,
    config: ClientConfig,
    control: VisionDirectControl,
) -> Result<BoxedStream, TlsClientError> {
    let server_name = ServerName::try_from(server_name.to_owned())
        .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(server_name, TlsRecordStream::new(stream))
        .await
        .map_err(TlsClientError::Handshake)?;
    Ok(Box::new(VisionTlsStream {
        inner: stream,
        control,
    }))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use super::*;
    use crate::tls::{ClientTlsOptions, client_config};

    const ROOT: &str = include_str!("../../../../compat/fixtures/phase4/phase4e2-root.pem");
    const CERTIFICATE: &[u8] =
        include_bytes!("../../../../compat/fixtures/phase4/phase4e2-server.pem");
    const PRIVATE_KEY: &[u8] =
        include_bytes!("../../../../compat/fixtures/phase4/phase4e2-server-key.pem");

    fn server_config() -> ServerConfig {
        let certificates = rustls_pemfile::certs(&mut Cursor::new(CERTIFICATE))
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .expect("server certificate");
        let private_key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY))
                .expect("server key PEM")
                .expect("server private key");
        ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .expect("TLS 1.3 provider")
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .expect("server identity")
    }

    fn client_config_for_test() -> ClientConfig {
        let roots = vec![ROOT.to_owned()];
        client_config(
            ClientTlsOptions {
                server_name: "dot.phase4.test",
                verification_name: None,
                skip_certificate_verification: false,
                fingerprint: None,
                certificate: None,
                private_key: None,
                custom_roots: &roots,
                ech_config: None,
                alpn_protocols: &[],
                tls12_only: false,
                tls13_only: true,
            },
            None,
        )
        .expect("client config")
    }

    #[tokio::test]
    async fn direct_mode_drains_outer_plaintext_then_uses_raw_stream() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (server_promoted, client_may_promote) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut tls = TlsAcceptor::from(Arc::new(server_config()))
                .accept(server)
                .await
                .expect("server handshake");
            tls.write_all(b"outertail").await.expect("outer response");
            tls.flush().await.expect("outer response flush");

            let mut request = [0_u8; 5];
            tls.read_exact(&mut request).await.expect("outer request");
            assert_eq!(&request, b"hello");

            let (mut raw, _) = tls.into_inner();
            server_promoted.send(()).expect("promotion signal");
            raw.write_all(b"raw").await.expect("raw response");
            raw.flush().await.expect("raw response flush");
            let mut direct_request = [0_u8; 5];
            raw.read_exact(&mut direct_request)
                .await
                .expect("raw request");
            assert_eq!(&direct_request, b"world");
            raw.shutdown().await.expect("server shutdown");
        });

        let control = VisionDirectControl::default();
        let mut stream = connect_vision_tls(
            Box::new(client),
            "dot.phase4.test",
            client_config_for_test(),
            control.clone(),
        )
        .await
        .expect("client handshake");

        let mut outer = [0_u8; 5];
        stream.read_exact(&mut outer).await.expect("outer response");
        assert_eq!(&outer, b"outer");
        control.request_read_direct();

        stream.write_all(b"hello").await.expect("outer request");
        stream.flush().await.expect("outer request flush");
        client_may_promote.await.expect("server promoted");
        control.request_write_direct();
        stream.write_all(b"world").await.expect("raw request");
        stream.flush().await.expect("raw request flush");

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("direct response");
        assert_eq!(response, b"tailraw");
        server_task.await.expect("server task");
    }
}

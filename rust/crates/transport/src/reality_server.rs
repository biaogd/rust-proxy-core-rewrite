//! VLESS REALITY server Accept using shadow-rustls server APIs.

use std::io::Read as _;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rewrite_io::{BoxedStream, VisionDirectControl};
use shadow_rustls::ServerConfig;
use shadow_rustls::server::{RealityServerCertResolver, RealityServerConfig};
use shadow_tokio_rustls::TlsAcceptor;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tls::TlsClientError;
use crate::vision_tls::{COPY_BUFFER_LEN, TlsRecordStream};

/// Cloneable REALITY TLS acceptor (shadow-tokio-rustls).
pub type RealityTlsAcceptor = TlsAcceptor;

/// Options for a REALITY TLS server Accept.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealityAcceptOptions {
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub server_names: Vec<String>,
    pub max_time_difference: Option<Duration>,
}

/// Build a reusable shadow-tokio-rustls acceptor for REALITY.
///
/// Authentication failure returns `None` from the cert resolver and aborts the
/// handshake (dest camouflage fallback is intentionally deferred).
///
/// # Errors
///
/// Returns [`TlsClientError::Configuration`] when the REALITY server config is invalid.
pub fn reality_acceptor(options: &RealityAcceptOptions) -> Result<TlsAcceptor, TlsClientError> {
    // shadow-rustls enables both aws-lc-rs and ring for fingerprint/REALITY;
    // the server Accept path consults the process default provider.
    let _ = shadow_rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut config = RealityServerConfig::new(options.private_key);
    config = config
        .with_short_ids(options.short_ids.iter().copied())
        .map_err(|error| TlsClientError::Configuration(error.to_string()))?
        .with_server_names(options.server_names.iter().cloned())
        .with_max_time_diff(options.max_time_difference);
    let resolver = Arc::new(RealityServerCertResolver::new(config));
    let provider = Arc::new(shadow_rustls::crypto::aws_lc_rs::default_provider());
    let time_provider = Arc::new(shadow_rustls::time_provider::DefaultTimeProvider);
    let server = ServerConfig::builder_with_details(provider, time_provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| TlsClientError::Configuration(error.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    Ok(TlsAcceptor::from(Arc::new(server)))
}

/// Accept a REALITY TLS client over `stream`.
///
/// # Errors
///
/// Returns [`TlsClientError`] when the handshake fails or times out.
pub async fn accept_reality<S>(
    acceptor: &TlsAcceptor,
    stream: S,
) -> Result<BoxedStream, TlsClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::time::timeout(Duration::from_secs(15), acceptor.accept(stream))
        .await
        .map_err(|_| TlsClientError::Timeout)?
        .map(|tls| Box::new(tls) as BoxedStream)
        .map_err(|error| TlsClientError::Handshake(std::io::Error::other(error)))
}

struct ServerRealityVisionStream {
    inner: shadow_tokio_rustls::server::TlsStream<TlsRecordStream>,
    control: VisionDirectControl,
}

impl AsyncRead for ServerRealityVisionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.control.read_is_direct() {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut plaintext = [0_u8; COPY_BUFFER_LEN];
        let amount = plaintext.len().min(buf.remaining());
        match self
            .inner
            .get_mut()
            .1
            .reader()
            .read(&mut plaintext[..amount])
        {
            Ok(0) => {}
            Ok(read) => {
                buf.put_slice(&plaintext[..read]);
                return Poll::Ready(Ok(()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Poll::Ready(Err(error)),
        }
        self.inner.get_mut().0.poll_raw_read(cx, buf)
    }
}

impl AsyncWrite for ServerRealityVisionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.control.write_is_direct() {
            return Pin::new(&mut self.inner.get_mut().0).poll_write(cx, buf);
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.control.write_is_direct() {
            return Pin::new(&mut self.inner.get_mut().0).poll_flush(cx);
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.control.any_is_direct() {
            return Pin::new(&mut self.inner.get_mut().0).poll_shutdown(cx);
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Accept REALITY and return a stream that can promote XTLS Vision to raw TCP.
///
/// # Errors
///
/// Returns [`TlsClientError`] when the handshake fails or times out.
pub async fn accept_reality_vision(
    acceptor: &TlsAcceptor,
    stream: BoxedStream,
    control: VisionDirectControl,
) -> Result<BoxedStream, TlsClientError> {
    tokio::time::timeout(
        Duration::from_secs(15),
        acceptor.accept(TlsRecordStream::new(stream)),
    )
    .await
    .map_err(|_| TlsClientError::Timeout)?
    .map(|tls| {
        Box::new(ServerRealityVisionStream {
            inner: tls,
            control,
        }) as BoxedStream
    })
    .map_err(|error| TlsClientError::Handshake(std::io::Error::other(error)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::{RealityConnectOptions, connect_reality};
    use tokio::net::{TcpListener, TcpStream};

    fn phase6e_keys() -> ([u8; 32], [u8; 32], [u8; 8]) {
        use base64::Engine;
        let private_key = {
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode("yMqyglp3FKXPpjcrwNfBYCQS-UrXduKhlDVqqlnMrWw")
                .expect("priv");
            let key: [u8; 32] = decoded.try_into().expect("32");
            key
        };
        let public_key = {
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode("Cu7X8PtrU22DHCW46oyZfgEEFLoWMxJYWhHOpBIokhc")
                .expect("pub");
            let key: [u8; 32] = decoded.try_into().expect("32");
            key
        };
        let short_id = hex::decode("10f897e26c4b9478").expect("short");
        let short_id: [u8; 8] = short_id.try_into().expect("8");
        (private_key, public_key, short_id)
    }

    #[tokio::test]
    async fn reality_accept_roundtrip() {
        let _ = shadow_rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (private_key, public_key, short_id) = phase6e_keys();
        let acceptor = reality_acceptor(&RealityAcceptOptions {
            private_key,
            short_ids: vec![short_id],
            server_names: vec!["itunes.apple.com".into()],
            max_time_difference: None,
        })
        .expect("acceptor");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept tcp");
            match accept_reality(&acceptor, tcp).await {
                Ok(_) => Ok(()),
                Err(error) => Err(error.to_string()),
            }
        });

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let client = connect_reality(
            tcp,
            RealityConnectOptions {
                server_name: "itunes.apple.com",
                public_key,
                short_id: &short_id,
                tls13_only: true,
                support_x25519mlkem768: false,
            },
        )
        .await;
        let server_result = server.await.expect("join");
        match (client, server_result) {
            (Ok(_), Ok(())) => {}
            (client, server) => {
                panic!("client={client:?} server={server:?}");
            }
        }
    }

    #[tokio::test]
    async fn reality_vision_accept_roundtrip() {
        use crate::reality::connect_reality_vision;
        use rewrite_io::VisionDirectControl;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let _ = shadow_rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (private_key, public_key, short_id) = phase6e_keys();
        let acceptor = reality_acceptor(&RealityAcceptOptions {
            private_key,
            short_ids: vec![short_id],
            server_names: vec!["itunes.apple.com".into()],
            max_time_difference: None,
        })
        .expect("acceptor");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_control = VisionDirectControl::default();
        let server = tokio::spawn({
            let server_control = server_control.clone();
            async move {
                let (tcp, _) = listener.accept().await.expect("accept tcp");
                let mut stream = accept_reality_vision(&acceptor, Box::new(tcp), server_control)
                    .await
                    .map_err(|error| error.to_string())?;
                let mut request = [0_u8; 5];
                stream
                    .read_exact(&mut request)
                    .await
                    .map_err(|error| error.to_string())?;
                if &request != b"hello" {
                    return Err(format!("unexpected request {request:?}"));
                }
                stream
                    .write_all(b"world")
                    .await
                    .map_err(|error| error.to_string())?;
                stream.flush().await.map_err(|error| error.to_string())?;
                Ok(())
            }
        });

        let client_control = VisionDirectControl::default();
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let mut client = connect_reality_vision(
            Box::new(tcp),
            RealityConnectOptions {
                server_name: "itunes.apple.com",
                public_key,
                short_id: &short_id,
                tls13_only: true,
                support_x25519mlkem768: false,
            },
            client_control,
        )
        .await
        .expect("client handshake");
        client.write_all(b"hello").await.expect("client write");
        client.flush().await.expect("client flush");
        let mut response = [0_u8; 5];
        client
            .read_exact(&mut response)
            .await
            .expect("client read");
        assert_eq!(&response, b"world");
        let server_result = server.await.expect("join");
        assert!(server_result.is_ok(), "{server_result:?}");
    }
}

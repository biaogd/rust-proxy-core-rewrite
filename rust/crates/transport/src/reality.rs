use std::io::{Cursor, Read as _};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rewrite_io::{BoxedStream, VisionDirectControl};
use shadow_rustls::client::RealityConfig;
use shadow_rustls::pki_types::ServerName;
use shadow_rustls::{ClientConfig, RootCertStore};
use shadow_tokio_rustls::TlsConnector;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tls::TlsClientError;
use crate::vision_tls::{COPY_BUFFER_LEN, TlsRecordStream};

#[derive(Clone, Copy, Debug)]
pub struct RealityConnectOptions<'a> {
    pub server_name: &'a str,
    pub public_key: [u8; 32],
    pub short_id: &'a [u8],
    pub tls13_only: bool,
    pub support_x25519mlkem768: bool,
}

fn load_root_store() -> Result<RootCertStore, TlsClientError> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for certificate in native.certs {
        roots
            .add(certificate)
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
    }
    let embedded = rustls_pemfile::certs(&mut Cursor::new(include_bytes!(
        "../../../../component/ca/ca-certificates.crt"
    )))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
    for certificate in embedded {
        roots
            .add(certificate)
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
    }
    Ok(roots)
}

fn reality_client_config(
    options: RealityConnectOptions<'_>,
) -> Result<ClientConfig, TlsClientError> {
    let reality = RealityConfig::new(options.public_key, options.short_id.to_vec())
        .map_err(|error| TlsClientError::Configuration(error.to_string()))?
        .with_client_version([1, 8, 2]);
    let roots = load_root_store()?;
    let provider = Arc::new(shadow_rustls::crypto::aws_lc_rs::default_provider());
    let time_provider = Arc::new(shadow_rustls::time_provider::DefaultTimeProvider);
    let builder = if options.tls13_only {
        ClientConfig::builder_with_details(provider, time_provider)
            .with_protocol_versions(&[&shadow_rustls::version::TLS13])
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?
    } else {
        ClientConfig::builder_with_details(provider, time_provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?
    };
    let mut config = builder
        .with_root_certificates(roots)
        .with_reality(reality)
        .with_no_client_auth();
    config.client_hello_fingerprint = Some(shadow_rustls::ClientHelloFingerprint::Chrome);
    config.client_hello_fingerprint_mlkem = options.support_x25519mlkem768;
    Ok(config)
}

/// Performs a VLESS REALITY client handshake over an established TCP stream.
///
/// # Errors
///
/// Returns [`TlsClientError`] when configuration or the handshake fails.
pub async fn connect_reality<S>(
    stream: S,
    options: RealityConnectOptions<'_>,
) -> Result<shadow_tokio_rustls::client::TlsStream<S>, TlsClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let server_name = ServerName::try_from(options.server_name.to_owned())
        .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
    let config = Arc::new(reality_client_config(options)?);
    let connector = TlsConnector::from(config);
    tokio::time::timeout(
        Duration::from_secs(15),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| TlsClientError::Timeout)?
    .map_err(|error| TlsClientError::Handshake(std::io::Error::other(error)))
}

struct RealityVisionStream {
    inner: shadow_tokio_rustls::client::TlsStream<TlsRecordStream>,
    control: VisionDirectControl,
}

impl AsyncRead for RealityVisionStream {
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

impl AsyncWrite for RealityVisionStream {
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

/// Performs REALITY and returns a stream that can promote XTLS Vision to raw TCP.
///
/// # Errors
///
/// Returns [`TlsClientError`] when configuration or the REALITY handshake fails.
pub async fn connect_reality_vision(
    stream: BoxedStream,
    options: RealityConnectOptions<'_>,
    control: VisionDirectControl,
) -> Result<BoxedStream, TlsClientError> {
    let server_name = ServerName::try_from(options.server_name.to_owned())
        .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
    let config = Arc::new(reality_client_config(options)?);
    let tls = tokio::time::timeout(
        Duration::from_secs(15),
        TlsConnector::from(config).connect(server_name, TlsRecordStream::new(stream)),
    )
    .await
    .map_err(|_| TlsClientError::Timeout)?
    .map_err(|error| TlsClientError::Handshake(std::io::Error::other(error)))?;
    Ok(Box::new(RealityVisionStream {
        inner: tls,
        control,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_enables_declared_chrome_profile() {
        let config = reality_client_config(RealityConnectOptions {
            server_name: "reality.example",
            public_key: [7; 32],
            short_id: &[],
            tls13_only: false,
            support_x25519mlkem768: false,
        })
        .expect("REALITY client config");
        assert_eq!(
            config.client_hello_fingerprint,
            Some(shadow_rustls::ClientHelloFingerprint::Chrome)
        );
        assert!(!config.client_hello_fingerprint_mlkem);

        let hybrid = reality_client_config(RealityConnectOptions {
            server_name: "reality.example",
            public_key: [7; 32],
            short_id: &[],
            tls13_only: false,
            support_x25519mlkem768: true,
        })
        .expect("hybrid REALITY client config");
        assert!(hybrid.client_hello_fingerprint_mlkem);
    }
}

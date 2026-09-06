//! Transport-independent `AnyTLS` client framing shared by outbound adapters.

mod client;
mod frame;
mod padding;
mod session;

use rewrite_io::BoxedStream;
use rewrite_model::Destination;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::AsyncWriteExt;

pub use client::{Client, ClientOptions, DialOut};
pub use padding::{DEFAULT_PADDING_SCHEME, PaddingFactory};
pub use session::{AnyTlsStream, Session, SessionCloseHook, StreamCloseHook};

#[derive(Debug, Error)]
pub enum AnyTlsProtocolError {
    #[error("AnyTLS destination domain exceeds 255 bytes")]
    DomainTooLong,
    #[error("AnyTLS I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("AnyTLS protocol failed: {0}")]
    Protocol(String),
}

/// Options for opening an `AnyTLS` proxy stream on an established TLS carrier.
#[derive(Clone, Debug, Default)]
pub struct AnyTlsConnectOptions<'a> {
    pub client_metadata: &'a str,
    pub padding: Option<Arc<PaddingFactory>>,
}

/// Builds the post-handshake authentication blob: `sha256(password) || len || zeros`.
#[must_use]
pub fn authentication_blob(password: &str, padding: &PaddingFactory) -> Vec<u8> {
    let digest = Sha256::digest(password.as_bytes());
    let mut padding_len = 0_u16;
    if let Some(size) = padding.generate_record_payload_sizes(0).first()
        && *size > 0
    {
        padding_len = u16::try_from(*size).unwrap_or(u16::MAX);
    }
    let mut out = Vec::with_capacity(32 + 2 + usize::from(padding_len));
    out.extend_from_slice(&digest);
    out.extend_from_slice(&padding_len.to_be_bytes());
    out.resize(out.len() + usize::from(padding_len), 0);
    out
}

/// Opens an `AnyTLS` TCP proxy stream over an established TLS carrier.
///
/// # Errors
///
/// Returns protocol or I/O errors when authentication, session setup or the
/// destination address cannot be encoded or written.
pub async fn connect_anytls_on_stream(
    mut remote: BoxedStream,
    destination: &Destination,
    password: &str,
    options: &AnyTlsConnectOptions<'_>,
) -> Result<BoxedStream, AnyTlsProtocolError> {
    let padding = options
        .padding
        .clone()
        .unwrap_or_else(PaddingFactory::default_factory);
    let auth = authentication_blob(password, &padding);
    remote.write_all(&auth).await?;
    remote.flush().await?;
    let mut options = options.clone();
    options.padding = Some(padding);
    session::open_proxy_stream(remote, destination, &options).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_blob_matches_go_layout() {
        let padding = PaddingFactory::default_factory();
        let blob = authentication_blob("phase6g-password", &padding);
        assert_eq!(blob.len(), 32 + 2 + 30);
        assert_eq!(&blob[32..34], &30_u16.to_be_bytes());
        assert!(blob[34..].iter().all(|byte| *byte == 0));
        let expected = Sha256::digest(b"phase6g-password");
        assert_eq!(&blob[..32], expected.as_slice());
    }
}

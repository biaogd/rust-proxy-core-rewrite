use rewrite_config::RealityProxyConfig;
use rewrite_transport::{RealityConnectOptions, TlsClientError, connect_reality};

use crate::BoxedOutboundStream;

/// Wraps an established TCP stream with a VLESS REALITY client handshake.
///
/// # Errors
///
/// Returns [`TlsClientError`] when configuration or the handshake fails.
pub async fn wrap_client_reality(
    stream: BoxedOutboundStream,
    server_name: &str,
    reality: &RealityProxyConfig,
    tls13_only: bool,
) -> Result<BoxedOutboundStream, TlsClientError> {
    let tls = connect_reality(
        stream,
        RealityConnectOptions {
            server_name,
            public_key: reality.public_key,
            short_id: &reality.short_id,
            tls13_only,
            support_x25519mlkem768: reality.support_x25519mlkem768,
        },
    )
    .await?;
    Ok(Box::new(tls))
}

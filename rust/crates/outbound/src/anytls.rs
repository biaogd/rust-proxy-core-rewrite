//! `AnyTLS` outbound adapter with optional session pooling.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rewrite_model::Destination;
use thiserror::Error;

use crate::BoxedOutboundStream;

#[derive(Debug, Error)]
pub enum AnyTlsProxyError {
    #[error(transparent)]
    Protocol(#[from] rewrite_protocol_anytls::AnyTlsProtocolError),
    #[error("AnyTLS dial failed: {0}")]
    Dial(String),
}

/// Dialer used by a pooled `AnyTLS` client to create an outer TCP+TLS carrier.
pub type AnyTlsDialOut = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<BoxedOutboundStream, AnyTlsProxyError>> + Send>>
        + Send
        + Sync,
>;

/// Long-lived outbound client matching Go `transport/anytls.Client`.
#[derive(Clone)]
pub struct AnyTlsClient {
    inner: rewrite_protocol_anytls::Client,
}

impl std::fmt::Debug for AnyTlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AnyTlsClient")
    }
}

/// Pool / session options for [`AnyTlsClient`].
#[derive(Clone, Debug)]
pub struct AnyTlsClientOptions {
    pub password: String,
    pub client_metadata: String,
    pub idle_session_check_interval: Duration,
    pub idle_session_timeout: Duration,
    pub min_idle_session: usize,
    pub disable_reuse: bool,
}

impl AnyTlsClient {
    #[must_use]
    pub fn new(dial_out: AnyTlsDialOut, options: AnyTlsClientOptions) -> Self {
        let protocol_dial: rewrite_protocol_anytls::DialOut = Arc::new(move || {
            let dial_out = Arc::clone(&dial_out);
            Box::pin(async move {
                dial_out().await.map_err(|error| {
                    rewrite_protocol_anytls::AnyTlsProtocolError::Protocol(error.to_string())
                })
            })
        });
        let inner = rewrite_protocol_anytls::Client::new(
            protocol_dial,
            rewrite_protocol_anytls::ClientOptions {
                client_metadata: options.client_metadata,
                idle_session_check_interval: options.idle_session_check_interval,
                idle_session_timeout: options.idle_session_timeout,
                min_idle_session: options.min_idle_session,
                disable_reuse: options.disable_reuse,
                password: options.password,
            },
        );
        Self { inner }
    }

    /// Opens a proxied TCP stream to `destination`.
    ///
    /// # Errors
    ///
    /// Returns dial or protocol errors from the underlying client.
    pub async fn create_proxy(
        &self,
        destination: &Destination,
    ) -> Result<BoxedOutboundStream, AnyTlsProxyError> {
        self.inner
            .create_proxy(destination)
            .await
            .map_err(Into::into)
    }

    pub async fn retire(&self) {
        self.inner.close().await;
    }
}

/// Starts an `AnyTLS` TCP request over an established TLS carrier (one-shot).
///
/// # Errors
///
/// Returns a protocol error when authentication, session setup or destination
/// encoding fails.
pub async fn connect_anytls_on_stream(
    remote: BoxedOutboundStream,
    destination: &Destination,
    password: &str,
    client_metadata: &str,
) -> Result<BoxedOutboundStream, AnyTlsProxyError> {
    let options = rewrite_protocol_anytls::AnyTlsConnectOptions {
        client_metadata,
        padding: None,
    };
    rewrite_protocol_anytls::connect_anytls_on_stream(remote, destination, password, &options)
        .await
        .map_err(Into::into)
}

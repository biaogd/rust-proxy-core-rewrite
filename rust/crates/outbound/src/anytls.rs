//! `AnyTLS` outbound adapter with optional session pooling.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rewrite_config::{AnyTlsCarrier, ProxyConfig};
use rewrite_model::Destination;
use rewrite_services::AdjustedClock;
use thiserror::Error;

use crate::{
    BoxedOutboundStream, DirectTcpOptions, HttpProxyTls, JlsConnectOptions,
    ShadowTlsConnectOptions, connect_jls, connect_shadow_tls, connect_with_options,
    wrap_client_tls_with_options,
};

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

/// Opens Go-compatible UDP-over-TCP (`UoT`) v2 over a pooled `AnyTLS` stream.
///
/// Matches `CreateProxy(uot.RequestDestination(2))` plus
/// `uot.NewLazyConn(..., Request{Destination})` with `IsConnect == false`, so
/// one association can carry packets to multiple destinations.
///
/// # Errors
///
/// Returns dial or protocol errors from the underlying client, or a framing
/// error when `UoT` v2 cannot be constructed.
pub async fn associate_anytls_udp(
    client: &AnyTlsClient,
) -> Result<crate::ShadowsocksUotAssociation, AnyTlsProxyError> {
    let destination = rewrite_protocol_shadowsocks::uot_destination(2).map_err(|error| {
        AnyTlsProxyError::Protocol(rewrite_protocol_anytls::AnyTlsProtocolError::Protocol(
            error.to_string(),
        ))
    })?;
    let stream = client.create_proxy(&destination).await?;
    rewrite_protocol_shadowsocks::ShadowsocksUotAssociation::new(stream, 2).map_err(|error| {
        AnyTlsProxyError::Protocol(rewrite_protocol_anytls::AnyTlsProtocolError::Protocol(
            error.to_string(),
        ))
    })
}

/// Dials the `AnyTLS` security carrier (native TLS / `ShadowTLS` / JLS / Restls gate).
///
/// Shared by runtime traffic dials and controller healthcheck / url-test so
/// carriers match Go `vmess.StreamTLSConn` before AUTH.
///
/// # Errors
///
/// Returns dial errors from TCP, TLS, `ShadowTLS`, or JLS, or an explicit Restls gate.
pub async fn connect_anytls_carrier(
    proxy: &ProxyConfig,
    server: &Destination,
    allow_ipv6: bool,
    custom_roots: &[String],
    socket_options: DirectTcpOptions<'_>,
    clock: Option<Arc<AdjustedClock>>,
) -> Result<BoxedOutboundStream, AnyTlsProxyError> {
    let anytls = proxy.anytls.as_ref().ok_or_else(|| {
        AnyTlsProxyError::Dial("AnyTLS proxy configuration is missing".to_owned())
    })?;
    let outer = connect_with_options(server, allow_ipv6, socket_options)
        .await
        .map_err(|error| {
            AnyTlsProxyError::Dial(format!("AnyTLS outer TCP connection failed: {error}"))
        })?;
    match &anytls.carrier {
        AnyTlsCarrier::NativeTls => {
            let alpn: Vec<&[u8]> = anytls.alpn.iter().map(String::as_bytes).collect();
            let server_name = proxy.sni.as_deref().unwrap_or(&proxy.server);
            let tls = HttpProxyTls {
                server_name,
                verification_name: proxy.name_cert_verify.as_deref(),
                skip_certificate_verification: proxy.skip_cert_verify,
                fingerprint: proxy.fingerprint.as_deref(),
                certificate: proxy.certificate.as_deref(),
                private_key: proxy.private_key.as_deref(),
                custom_roots,
                ech_config: None,
                alpn_protocols: &alpn,
                tls12_only: false,
                tls13_only: false,
            };
            wrap_client_tls_with_options(Box::new(outer), tls, clock)
                .await
                .map_err(|error| {
                    AnyTlsProxyError::Dial(format!("AnyTLS outer TLS connection failed: {error}"))
                })
        }
        AnyTlsCarrier::ShadowTls { password, version } => {
            // Go StreamTLSConn(ShadowTLS) replaces native TLS; AnyTLS AUTH rides the
            // post-handshake ShadowTLS stream directly.
            connect_shadow_tls(
                Box::new(outer),
                ShadowTlsConnectOptions {
                    host: proxy.sni.as_deref().unwrap_or(&proxy.server),
                    password,
                    version: *version,
                    skip_certificate_verification: proxy.skip_cert_verify,
                    verification_name: proxy.name_cert_verify.as_deref(),
                    certificate_fingerprint: proxy.fingerprint.as_deref(),
                    certificate: proxy.certificate.as_deref(),
                    private_key: proxy.private_key.as_deref(),
                    custom_roots,
                    alpn: &anytls.alpn,
                    client_fingerprint: proxy.client_fingerprint.as_deref(),
                },
                clock,
            )
            .await
            .map_err(|error| {
                AnyTlsProxyError::Dial(format!("AnyTLS ShadowTLS carrier failed: {error}"))
            })
        }
        AnyTlsCarrier::Restls { .. } => Err(AnyTlsProxyError::Dial(
            "AnyTLS Restls carrier dial is blocked on a shared Restls TLS client transport \
             (Go uses metacubex/restls-client-go, a utls fork; no Rust Restls client exists in-tree \
             or on crates.io — only the 3andne/restls server binary). Phase 6G-E leftover."
                .to_owned(),
        )),
        AnyTlsCarrier::Jls { username, password } => {
            // Go StreamTLSConn(JLS) replaces native TLS; AnyTLS AUTH rides the
            // post-handshake JLS stream directly (no second TLS).
            connect_jls(
                Box::new(outer),
                JlsConnectOptions {
                    host: proxy.sni.as_deref().unwrap_or(&proxy.server),
                    username,
                    password,
                    alpn: &anytls.alpn,
                },
            )
            .await
            .map_err(|error| AnyTlsProxyError::Dial(format!("AnyTLS JLS carrier failed: {error}")))
        }
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

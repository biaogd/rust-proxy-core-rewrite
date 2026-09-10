//! Shared rustls client helpers for TUIC QUIC (not Hysteria2 auth).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::congestion::{BbrConfig, CubicConfig};
use quinn::crypto::rustls::QuicClientConfig;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{
    WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};

use crate::{ClientOptions, CongestionController, TuicProtocolError};

pub(crate) const DEFAULT_STREAM_RECEIVE_WINDOW: u64 = 15_728_640;
pub(crate) const DEFAULT_CONNECTION_RECEIVE_WINDOW: u64 = 67_108_864;
pub(crate) const DEFAULT_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn build_rustls_client_config(options: &ClientOptions) -> ClientConfig {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let skip = options.tls.skip_certificate_verification || options.tls.disable_sni;
    let builder = ClientConfig::builder();
    let mut crypto = if skip {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        for pem in &options.tls.custom_roots {
            let mut cursor = std::io::Cursor::new(pem.as_bytes());
            for cert in rustls_pemfile::certs(&mut cursor).flatten() {
                let _ = roots.add(cert);
            }
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    crypto.alpn_protocols = options
        .tls
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    crypto.enable_sni = !options.tls.disable_sni;
    crypto.enable_early_data = false;
    crypto.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    crypto
}

pub(crate) fn build_endpoint(
    options: &ClientOptions,
    bind: SocketAddr,
) -> Result<quinn::Endpoint, TuicProtocolError> {
    let crypto = build_rustls_client_config(options);
    let quic_crypto = QuicClientConfig::try_from(crypto)
        .map_err(|error| TuicProtocolError::Quinn(error.to_string()))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    let idle = DEFAULT_MAX_IDLE_TIMEOUT;
    transport.max_idle_timeout(Some(
        idle.try_into()
            .map_err(|error| TuicProtocolError::Quinn(format!("{error}")))?,
    ));
    if !options.heartbeat_interval.is_zero() {
        transport.keep_alive_interval(Some(options.heartbeat_interval));
    }
    let stream_window = options
        .stream_receive_window
        .unwrap_or(DEFAULT_STREAM_RECEIVE_WINDOW);
    let conn_window = options
        .connection_receive_window
        .unwrap_or(DEFAULT_CONNECTION_RECEIVE_WINDOW);
    transport.stream_receive_window(
        quinn::VarInt::from_u64(stream_window)
            .map_err(|error| TuicProtocolError::Quinn(error.to_string()))?,
    );
    transport.receive_window(
        quinn::VarInt::from_u64(conn_window)
            .map_err(|error| TuicProtocolError::Quinn(error.to_string()))?,
    );
    let incoming = options.max_open_streams.saturating_add(
        options
            .max_open_streams
            .saturating_add(9)
            .saturating_div(10),
    );
    let incoming = incoming.max(1);
    transport.max_concurrent_bidi_streams(
        quinn::VarInt::from_u64(incoming)
            .map_err(|error| TuicProtocolError::Quinn(error.to_string()))?,
    );
    transport.max_concurrent_uni_streams(
        quinn::VarInt::from_u64(incoming)
            .map_err(|error| TuicProtocolError::Quinn(error.to_string()))?,
    );
    transport.datagram_receive_buffer_size(Some(65_535));
    transport.datagram_send_buffer_size(65_535);
    match options.congestion {
        CongestionController::Cubic | CongestionController::NewReno => {
            transport.congestion_controller_factory(Arc::new(CubicConfig::default()));
        }
        CongestionController::Bbr => {
            transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
        }
    }
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

#[derive(Debug)]
struct SkipServerVerification {
    algorithms: WebPkiSupportedAlgorithms,
}

impl SkipServerVerification {
    fn new() -> Self {
        Self {
            algorithms: tokio_rustls::rustls::crypto::ring::default_provider()
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
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientOptions;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    #[test]
    fn disable_sni_clears_enable_sni() {
        let mut options = ClientOptions::default();
        options.tls.disable_sni = true;
        options.tls.skip_certificate_verification = false;
        let crypto = build_rustls_client_config(&options);
        assert!(!crypto.enable_sni);
    }

    #[test]
    fn explicit_empty_alpn_is_not_rewritten_to_h3() {
        let mut options = ClientOptions::default();
        options.tls.alpn.clear();
        let crypto = build_rustls_client_config(&options);
        assert!(crypto.alpn_protocols.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn raw_quinn_loopback_handshake_completes() {
        let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("cert");
        let cert = CertificateDer::from(certified.cert.der().to_vec());
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let _ = (*provider).clone().install_default();
        let mut rustls_server = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server identity");
        rustls_server.alpn_protocols = vec![b"h3".to_vec()];
        rustls_server.max_early_data_size = u32::MAX;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server).expect("quic server"),
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().expect("idle")));
        server.transport_config(Arc::new(transport));
        let endpoint =
            quinn::Endpoint::server(server, "127.0.0.1:0".parse().expect("bind")).expect("ep");
        let addr = endpoint.local_addr().expect("addr");
        let mut options = ClientOptions::default();
        options.tls.server_name = "localhost".to_owned();
        options.tls.skip_certificate_verification = true;
        options.tls.alpn = vec!["h3".to_owned()];
        let client_ep = build_endpoint(&options, "127.0.0.1:0".parse().expect("client bind"))
            .expect("client endpoint");
        let connecting = client_ep.connect(addr, "localhost").expect("connect");
        let handshake = async {
            let incoming = endpoint.accept().await.expect("incoming");
            let (server_conn, client_conn) = tokio::join!(incoming, connecting);
            (
                server_conn.expect("server handshake"),
                client_conn.expect("client handshake"),
            )
        };
        tokio::time::timeout(Duration::from_secs(5), handshake)
            .await
            .expect("loopback QUIC handshake");
    }
}

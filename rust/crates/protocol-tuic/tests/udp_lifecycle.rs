//! UDP association lifecycle fixtures that echo/soak cannot cover:
//! QUIC still alive with blocked uni-stream send, and recv ending on peer close.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rewrite_model::{Destination, Host};
use rewrite_protocol_tuic::{Client, ClientOptions, TlsOptions, UdpRelayMode};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use uuid::Uuid;

fn dest() -> Destination {
    Destination {
        host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: 9,
    }
}

fn tls_pair() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("cert");
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    (cert, key)
}

fn server_config(max_uni: u32) -> quinn::ServerConfig {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let _ = (*provider).clone().install_default();
    let (cert, key) = tls_pair();
    let mut crypto = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server cert");
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    crypto.max_early_data_size = u32::MAX;
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("quic server");
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(max_uni.into());
    transport.max_idle_timeout(Some(Duration::from_mins(1).try_into().expect("idle")));
    config.transport_config(Arc::new(transport));
    config
}

fn bind_server(max_uni: u32) -> quinn::Endpoint {
    quinn::Endpoint::server(server_config(max_uni), "127.0.0.1:0".parse().expect("bind"))
        .expect("endpoint")
}

fn client_for(addr: SocketAddr, mode: UdpRelayMode) -> Client {
    Client::new(ClientOptions {
        server: addr.ip().to_string(),
        port: addr.port(),
        uuid: Uuid::nil(),
        password: "secret".to_owned(),
        tls: TlsOptions {
            server_name: "localhost".to_owned(),
            skip_certificate_verification: true,
            disable_sni: false,
            alpn: vec!["h3".to_owned()],
            custom_roots: Vec::new(),
        },
        udp_relay_mode: mode,
        heartbeat_interval: Duration::ZERO,
        ..ClientOptions::default()
    })
    .expect("client")
}

async fn handshake(
    endpoint: &quinn::Endpoint,
    client: &Client,
) -> (quinn::Connection, rewrite_protocol_tuic::UdpSession) {
    let accept = async {
        let incoming = endpoint.accept().await.expect("incoming QUIC connection");
        incoming.await.expect("QUIC server handshake")
    };
    let (connection, session) = tokio::join!(accept, client.open_udp());
    (
        connection,
        session.expect("TUIC UDP association after handshake"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_udp_send_is_cancellable_when_uni_credit_is_exhausted() {
    let endpoint = bind_server(1);
    let addr = endpoint.local_addr().expect("addr");
    let client = client_for(addr, UdpRelayMode::Quic);
    let (_connection, session) =
        tokio::time::timeout(Duration::from_secs(15), handshake(&endpoint, &client))
            .await
            .expect("handshake should complete");
    let destination = dest();
    let started = Instant::now();
    let send = tokio::time::timeout(
        Duration::from_millis(400),
        session.send(&destination, b"ping"),
    );
    match send.await {
        Err(_) => {}
        Ok(Ok(())) => panic!("QUIC UDP send completed despite exhausted uni streams"),
        Ok(Err(error)) => panic!("QUIC UDP send failed instead of blocking: {error}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "blocked send must be cancellable by timeout"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_recv_returns_promptly_after_quic_peer_close() {
    let endpoint = bind_server(16);
    let addr = endpoint.local_addr().expect("addr");
    let client = client_for(addr, UdpRelayMode::Native);
    let (connection, mut session) =
        tokio::time::timeout(Duration::from_secs(15), handshake(&endpoint, &client))
            .await
            .expect("handshake should complete");
    connection.close(0_u32.into(), b"gone");
    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(2), session.recv())
        .await
        .expect("recv should finish after QUIC close");
    assert!(
        result.is_err(),
        "recv should surface QUIC close: {result:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "recv should observe QUIC close without the mixed-port idle timeout"
    );
}

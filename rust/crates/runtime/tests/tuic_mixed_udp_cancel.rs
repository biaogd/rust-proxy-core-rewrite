//! Mixed-port TUIC UDP: blocked QUIC uni send / setup must yield to shutdown.
//!
//! Wrapping `session.send()` in `timeout` does not prove the runtime path;
//! this drives SOCKS UDP ASSOCIATE through `run_tuic_udp_session`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rewrite_config::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_util::sync::CancellationToken;

fn tls_pair() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("cert");
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    (cert, key)
}

fn bind_stub(max_uni: u32) -> quinn::Endpoint {
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
    quinn::Endpoint::server(config, "127.0.0.1:0".parse().expect("bind")).expect("endpoint")
}

fn socks_udp_ipv4(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

async fn socks_udp_associate(mixed_port: u16) -> (TcpStream, UdpSocket, u16) {
    let mut control = TcpStream::connect(("127.0.0.1", mixed_port))
        .await
        .expect("mixed TCP");
    control
        .write_all(b"\x05\x01\x00")
        .await
        .expect("socks greeting");
    let mut auth = [0_u8; 2];
    control.read_exact(&mut auth).await.expect("auth");
    assert_eq!(auth, [5, 0]);
    control
        .write_all(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        .await
        .expect("associate");
    let mut reply = [0_u8; 10];
    control
        .read_exact(&mut reply)
        .await
        .expect("associate reply");
    assert_eq!(reply[0], 5);
    assert_eq!(reply[1], 0);
    let mut bind_port = u16::from_be_bytes([reply[8], reply[9]]);
    if bind_port == 0 {
        bind_port = mixed_port;
    }
    let datagram = UdpSocket::bind("127.0.0.1:0").await.expect("udp");
    (control, datagram, bind_port)
}

async fn wait_mixed(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "mixed-port {port} did not become ready"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn run_mixed_against_stub(max_uni: u32) {
    rewrite_services::install_default_crypto_provider();
    let stub = bind_stub(max_uni);
    let stub_port = stub.local_addr().expect("stub addr").port();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let stub_task = tokio::spawn(async move {
        let incoming = stub.accept().await.expect("incoming");
        let connection = incoming.await.expect("handshake");
        // Keep the authentication stream alive without consuming FIN: otherwise
        // dropping it returns uni-stream credit and the UDP send need not block.
        let auth = if max_uni == 1 {
            let mut auth = connection.accept_uni().await.expect("auth stream");
            // Leave the UUID/token unread too: reading the final bytes can
            // consume FIN and return credit even while RecvStream is retained.
            let mut header = [0_u8; 2];
            auth.read_exact(&mut header).await.expect("auth header");
            assert_eq!(header, [5, 0]);
            Some(auth)
        } else {
            None
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(150), connection.accept_uni())
                .await
                .is_err(),
            "no uni credit may be returned before cancellation"
        );
        ready_tx.send(()).expect("test still waiting");
        connection.closed().await;
        drop(auth);
    });

    let mixed = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve mixed");
    let mixed_port = mixed.local_addr().expect("mixed addr").port();
    drop(mixed);
    let config = Config::from_yaml(&format!(
        "mixed-port: {mixed_port}\nmode: rule\nipv6: false\nproxies:\n  - name: tuic-quic\n    type: tuic\n    server: 127.0.0.1\n    port: {stub_port}\n    uuid: b831381d-6324-4d53-ad4f-8cda48b30811\n    password: secret\n    sni: localhost\n    alpn: [h3]\n    skip-cert-verify: true\n    udp-relay-mode: quic\nrules:\n  - MATCH,tuic-quic\n"
    ))
    .expect("config");
    let shutdown = CancellationToken::new();
    let runtime = tokio::spawn(rewrite_runtime::run(config, shutdown.clone()));
    wait_mixed(mixed_port).await;

    let (_control, datagram, bind_port) = socks_udp_associate(mixed_port).await;
    let dest: SocketAddr = format!("127.0.0.1:{bind_port}").parse().expect("bind dest");
    datagram
        .send_to(&socks_udp_ipv4(9, b"ping"), dest)
        .await
        .expect("udp send");
    tokio::time::timeout(Duration::from_secs(3), ready_rx)
        .await
        .expect("stub reached blocked-I/O state")
        .expect("stub ready");

    let started = Instant::now();
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), runtime)
        .await
        .expect("runtime must stop without the 1m UDP idle timeout")
        .expect("runtime task")
        .expect("runtime ok");
    tokio::time::timeout(Duration::from_secs(2), stub_task)
        .await
        .expect("stub closes with runtime")
        .expect("stub task");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "mixed UDP shutdown stuck after blocked TUIC QUIC I/O"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_udp_shutdown_cancels_blocked_quic_send() {
    run_mixed_against_stub(1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_udp_shutdown_cancels_blocked_authenticate() {
    run_mixed_against_stub(0).await;
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_cold_udp_associations_share_one_connection() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let endpoint = bind_server(16);
        let client = Arc::new(client_for(
            endpoint.local_addr().expect("addr"),
            UdpRelayMode::Native,
        ));
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&count);
        let server_endpoint = endpoint.clone();
        let server = tokio::spawn(async move {
            let mut workers = tokio::task::JoinSet::new();
            while let Some(incoming) = server_endpoint.accept().await {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                workers.spawn(async move {
                    let connection = incoming.await.expect("handshake");
                    connection.closed().await;
                });
            }
            while let Some(result) = workers.join_next().await {
                result.expect("server worker");
            }
        });
        let barrier = Arc::new(tokio::sync::Barrier::new(33));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let client = Arc::clone(&client);
            let barrier = Arc::clone(&barrier);
            tasks.spawn(async move {
                barrier.wait().await;
                client.open_udp().await.expect("association")
            });
        }
        barrier.wait().await;
        let mut sessions = Vec::new();
        while let Some(result) = tasks.join_next().await {
            sessions.push(result.expect("join"));
        }
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "concurrent cold requests must reuse the completed dial"
        );
        client.close().await;
        drop(sessions);
        endpoint.close(0_u32.into(), b"done");
        server.await.expect("server");
    })
    .await
    .expect("bounded cold pool test");
}

fn tls_pair() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("cert");
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    (cert, key)
}

fn server_config(max_uni: u32) -> quinn::ServerConfig {
    server_config_with_datagrams(max_uni, 65_535)
}

fn server_config_with_datagrams(max_uni: u32, datagram_limit: usize) -> quinn::ServerConfig {
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
    transport.datagram_receive_buffer_size(Some(datagram_limit));
    transport.max_idle_timeout(Some(Duration::from_mins(1).try_into().expect("idle")));
    config.transport_config(Arc::new(transport));
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_fragmentation_retries_smaller_peer_limit() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut endpoint_config = quinn::EndpointConfig::default();
        endpoint_config
            .max_udp_payload_size(1200)
            .expect("minimum QUIC packet size");
        let endpoint = quinn::Endpoint::new(
            endpoint_config,
            Some(server_config(16)),
            std::net::UdpSocket::bind("127.0.0.1:0").expect("bind"),
            Arc::new(quinn::TokioRuntime),
        )
        .expect("endpoint");
        let client = client_for(endpoint.local_addr().expect("addr"), UdpRelayMode::Native);
        let (connection, session) = handshake(&endpoint, &client).await;
        let payload = vec![42_u8; 2400];
        let receive = async {
            let mut packets = Vec::new();
            loop {
                let bytes = connection.read_datagram().await.expect("fragment");
                assert!(bytes.len() < 1200);
                let packet = rewrite_protocol_tuic::decode_packet(&bytes).expect("packet");
                let total = usize::from(packet.frag_total);
                packets.push(packet);
                if packets.len() == total {
                    break;
                }
            }
            packets.sort_by_key(|packet| packet.frag_id);
            let data: Vec<_> = packets.into_iter().flat_map(|packet| packet.data).collect();
            assert_eq!(data, payload);
        };
        let destination = Destination {
            host: rewrite_model::Host::Ip(std::net::Ipv6Addr::LOCALHOST.into()),
            port: 9,
        };
        let send = session.send(&destination, &payload);
        let (outcome, ()) = tokio::join!(send, receive);
        outcome.expect("retry fragmented send");
        client.close().await;
        connection.closed().await;
        drop(session);
    })
    .await
    .expect("bounded small datagram test");
}

fn bind_server(max_uni: u32) -> quinn::Endpoint {
    quinn::Endpoint::server(server_config(max_uni), "127.0.0.1:0".parse().expect("bind"))
        .expect("endpoint")
}

fn client_for(addr: SocketAddr, mode: UdpRelayMode) -> Client {
    client_for_limit(addr, mode, 90)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dissociate_expires_when_uni_credit_is_exhausted() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let endpoint = bind_server(1);
        let client = client_for(endpoint.local_addr().expect("addr"), UdpRelayMode::Native);
        let (connection, session) = handshake(&endpoint, &client).await;
        let mut auth = connection.accept_uni().await.expect("auth");
        let mut header = [0_u8; 2];
        auth.read_exact(&mut header).await.expect("auth header");
        assert_eq!(header, [5, 0]);
        drop(session);
        tokio::time::sleep(Duration::from_millis(1300)).await;
        // Return credit only after the bounded cleanup attempt has expired.
        drop(auth);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), connection.accept_uni())
                .await
                .is_err(),
            "expired Dissociate must not remain waiting for credit"
        );
        client.close().await;
        connection.closed().await;
    })
    .await
    .expect("bounded dissociate test");
}

fn client_for_limit(addr: SocketAddr, mode: UdpRelayMode, max_open_streams: u64) -> Client {
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
        max_open_streams,
        ..ClientOptions::default()
    })
    .expect("client")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthy_pool_reuse_bypasses_blocked_expansion() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let endpoint = bind_server(16);
        let client = Arc::new(client_for_limit(
            endpoint.local_addr().expect("addr"),
            UdpRelayMode::Native,
            2,
        ));
        let (first_connection, first) = handshake(&endpoint, &client).await;
        endpoint.set_server_config(Some(server_config(0)));
        let opening = {
            let client = Arc::clone(&client);
            tokio::spawn(async move { client.open_udp().await })
        };
        let second_connection = endpoint
            .accept()
            .await
            .expect("expansion")
            .await
            .expect("handshake");
        assert!(
            !opening.is_finished(),
            "expansion must wait for authentication credit"
        );
        drop(first);
        // Go-compatible lease accounting releases the old slot after five seconds.
        tokio::time::sleep(Duration::from_millis(5200)).await;
        let reused = tokio::time::timeout(Duration::from_secs(1), client.open_udp())
            .await
            .expect("healthy pool must bypass blocked expansion")
            .expect("reuse");
        assert!(!opening.is_finished());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), endpoint.accept())
                .await
                .is_err(),
            "reuse must not dial another connection"
        );
        client.close().await;
        assert!(opening.await.expect("join").is_err());
        first_connection.closed().await;
        second_connection.closed().await;
        drop(reused);
    })
    .await
    .expect("bounded pool reuse test");
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

/// Timeout around `send()` only proves the future is cancel-safe. Mixed-port
/// shutdown coverage is `rewrite-runtime` `tuic_mixed_udp_cancel`.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_unblocks_authenticate_waiting_for_uni_credit() {
    let endpoint = bind_server(0);
    let addr = endpoint.local_addr().expect("addr");
    let client = Arc::new(client_for(addr, UdpRelayMode::Native));
    let opening = {
        let client = Arc::clone(&client);
        tokio::spawn(async move { client.open_udp().await })
    };
    let incoming = tokio::time::timeout(Duration::from_secs(5), endpoint.accept())
        .await
        .expect("incoming")
        .expect("server accepted");
    let _connection = incoming.await.expect("handshake");
    tokio::time::sleep(Duration::from_millis(80)).await;
    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(1), client.close())
        .await
        .expect("close must not wait on authenticate");
    let opened = tokio::time::timeout(Duration::from_secs(1), opening)
        .await
        .expect("open_udp must finish after close");
    assert!(opened.expect("join").is_err());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "retire/close must interrupt a blocked TUIC dial"
    );
}

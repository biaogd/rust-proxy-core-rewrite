//! 6I-C lifecycle: persistent keepalive, rehandshake after peer restart, endpoint move.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use defguard_boringtun::x25519::{PublicKey, StaticSecret};
use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use rewrite_model::{Destination, Host};
use rewrite_protocol_wireguard::{
    Client, ClientOptions, NoiseTunnel, PeerResolveHook, TunnelAction,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

fn pair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::from([seed; 32]);
    let public = PublicKey::from(&secret);
    (*secret.as_bytes(), *public.as_bytes())
}

fn client_options(
    port: u16,
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    persistent_keepalive: Option<u16>,
) -> ClientOptions {
    ClientOptions {
        server: "127.0.0.1".to_owned(),
        port,
        private_key,
        peer_public_key,
        persistent_keepalive,
        ..ClientOptions::default()
    }
}

fn echo_destination(port: u16) -> Destination {
    Destination {
        host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port,
    }
}

async fn spawn_echo() -> u16 {
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let port = echo.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 4096];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

async fn spawn_udp_echo() -> u16 {
    let echo = UdpSocket::bind("127.0.0.1:0").await.expect("udp echo bind");
    let port = echo.local_addr().expect("udp echo addr").port();
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 65_535];
        loop {
            let Ok((n, from)) = echo.recv_from(&mut buf).await else {
                break;
            };
            if echo.send_to(&buf[..n], from).await.is_err() {
                break;
            }
        }
    });
    port
}

async fn spawn_delayed_reader() -> (u16, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("delayed reader bind");
    let port = listener.local_addr().expect("delayed reader addr").port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        tokio::time::sleep(Duration::from_millis(400)).await;
        let mut buf = Vec::new();
        if stream.read_to_end(&mut buf).await.is_ok() {
            let _ = tx.send(buf);
        }
    });
    (port, rx)
}

async fn tcp_echo(client: &Client, port: u16, payload: &[u8]) {
    let mut stream = client
        .open_tcp(&echo_destination(port))
        .await
        .expect("open tcp");
    stream.write_all(payload).await.expect("write");
    let mut got = vec![0_u8; payload.len()];
    stream.read_exact(&mut got).await.expect("read");
    assert_eq!(got, payload);
}

#[tokio::test]
async fn persistent_keepalive_sends_after_idle() {
    let (client_priv, client_pub) = pair(21);
    let (server_priv, server_pub) = pair(23);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub, 2);

    let client = Client::new(client_options(
        endpoint.port(),
        client_priv,
        server_pub,
        Some(1),
    ))
    .await
    .expect("client");
    let _ = client.open_udp().await.expect("handshake via udp");
    let before = client.datagrams_sent();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let after = client.datagrams_sent();
    assert!(
        after > before,
        "persistent keepalive should send datagrams while idle (before={before} after={after})"
    );
    client.close().await;
}

#[tokio::test]
async fn tcp_retries_handshake_after_peer_restart() {
    let echo_port = spawn_echo().await;
    let (client_priv, client_pub) = pair(25);
    let (server_priv, server_pub) = pair(27);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    let responder = spawn_swappable_responder(listen, server_priv, client_pub, 2);

    let client = Client::new(client_options(
        endpoint.port(),
        client_priv,
        server_pub,
        None,
    ))
    .await
    .expect("client");
    tcp_echo(&client, echo_port, b"before-restart").await;

    *responder.tunnel.lock().expect("swap") = Arc::new(
        NoiseTunnel::new(server_priv, client_pub, None, None, [0; 3], 4).expect("new peer"),
    );

    tokio::time::timeout(
        Duration::from_secs(8),
        tcp_echo(&client, echo_port, b"after-restart"),
    )
    .await
    .expect("silent peer restart must rekey without the peer initiating");
    client.close().await;
}

#[tokio::test]
async fn graceful_tcp_shutdown_delivers_bytes_to_delayed_reader() {
    let (port, received) = spawn_delayed_reader().await;
    let (client_priv, client_pub) = pair(73);
    let (server_priv, server_pub) = pair(75);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub, 2);
    let client = Client::new(client_options(
        endpoint.port(),
        client_priv,
        server_pub,
        None,
    ))
    .await
    .expect("client");
    let payload: Vec<u8> = (0_u8..=250).cycle().take(4096).collect();
    let mut stream = client
        .open_tcp(&echo_destination(port))
        .await
        .expect("open tcp");
    stream.write_all(&payload).await.expect("write");
    stream.shutdown().await.expect("shutdown");
    drop(stream);
    let got = tokio::time::timeout(Duration::from_secs(5), received)
        .await
        .expect("delayed reader should finish")
        .expect("reader channel");
    assert_eq!(got, payload, "graceful close must not drop queued bytes");
    client.close().await;
}

#[tokio::test]
async fn tcp_flush_errors_after_rst_with_unacked_data() {
    let hold = TcpListener::bind("127.0.0.1:0").await.expect("hold bind");
    let rst_port = hold.local_addr().expect("hold addr").port();
    tokio::spawn(async move {
        let Ok((stream, _)) = hold.accept().await else {
            return;
        };
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(stream);
    });
    let (client_priv, client_pub) = pair(85);
    let (server_priv, server_pub) = pair(87);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder_with_hooks(
        listen,
        server_priv,
        client_pub,
        2,
        InnerTcpHooks {
            data_reset: Some(rst_port),
            ..InnerTcpHooks::default()
        },
    );
    let client = Client::new(client_options(
        endpoint.port(),
        client_priv,
        server_pub,
        None,
    ))
    .await
    .expect("client");
    let mut stream = client
        .open_tcp(&echo_destination(rst_port))
        .await
        .expect("open tcp");
    let payload = vec![0x5a_u8; 64];
    stream.write_all(&payload).await.expect("write");
    let flush = tokio::time::timeout(Duration::from_secs(2), stream.flush()).await;
    assert!(
        matches!(flush, Ok(Err(_)) | Err(_)),
        "flush must not hang after RST with unacked data, got {flush:?}"
    );
    let shutdown = tokio::time::timeout(Duration::from_secs(2), stream.shutdown()).await;
    assert!(
        matches!(shutdown, Ok(Err(_) | Ok(())) | Err(_)),
        "shutdown after RST must finish, got {shutdown:?}"
    );
    client.close().await;
}

#[tokio::test]
async fn released_fin_wait_is_reaped_when_peer_holds_close_wait() {
    let hold = TcpListener::bind("127.0.0.1:0").await.expect("hold bind");
    let port = hold.local_addr().expect("hold addr").port();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = hold.accept().await else {
            return;
        };
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf).await;
        tokio::time::sleep(Duration::from_secs(10)).await;
        drop(stream);
    });
    let (client_priv, client_pub) = pair(89);
    let (server_priv, server_pub) = pair(91);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub, 2);
    let client = Client::new(client_options(
        endpoint.port(),
        client_priv,
        server_pub,
        None,
    ))
    .await
    .expect("client");
    let mut stream = client
        .open_tcp(&echo_destination(port))
        .await
        .expect("open tcp");
    stream.write_all(b"fin-wait").await.expect("write");
    stream.shutdown().await.expect("shutdown");
    drop(stream);
    wait_live_sockets(&client, 0).await;
    client.close().await;
}

#[tokio::test]
async fn held_half_close_is_not_reaped_with_released_sockets() {
    let hold = TcpListener::bind("127.0.0.1:0").await.expect("hold bind");
    let port = hold.local_addr().expect("hold addr").port();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = hold.accept().await else {
            return;
        };
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf).await;
        tokio::time::sleep(Duration::from_secs(10)).await;
        drop(stream);
    });
    let (client_priv, client_pub) = pair(93);
    let (server_priv, server_pub) = pair(95);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub, 2);
    let client = Client::new(client_options(
        endpoint.port(),
        client_priv,
        server_pub,
        None,
    ))
    .await
    .expect("client");
    let mut stream = client
        .open_tcp(&echo_destination(port))
        .await
        .expect("held tcp");
    stream.write_all(b"keep-half").await.expect("write");
    stream.shutdown().await.expect("shutdown");
    tokio::time::sleep(Duration::from_millis(3500)).await;
    assert_eq!(
        client.live_socket_count(),
        1,
        "application-held half-close must outlive the released-socket reap timer"
    );
    drop(stream);
    wait_live_sockets(&client, 0).await;
    client.close().await;
}

#[tokio::test]
async fn idle_tunnel_survives_syn_reset_and_blackhole() {
    let echo_port = spawn_echo().await;
    let udp_port = spawn_udp_echo().await;
    let syn_reset = 9_u16;
    let (client_priv, client_pub) = pair(77);
    let (server_priv, server_pub) = pair(79);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder_with_hooks(
        listen,
        server_priv,
        client_pub,
        2,
        InnerTcpHooks {
            syn_reset: Some(syn_reset),
            blackhole: Some(Ipv4Addr::new(192, 0, 2, 1)),
            ..InnerTcpHooks::default()
        },
    );
    let client = Client::new(client_options(
        endpoint.port(),
        client_priv,
        server_pub,
        None,
    ))
    .await
    .expect("client");

    let mut live_tcp = client
        .open_tcp(&echo_destination(echo_port))
        .await
        .expect("live tcp");
    live_tcp.write_all(b"pin").await.expect("pin write");
    let mut pin = [0_u8; 3];
    live_tcp.read_exact(&mut pin).await.expect("pin read");
    assert_eq!(&pin, b"pin");

    let udp = client.open_udp().await.expect("udp");
    let udp_dest = SocketAddr::from((Ipv4Addr::LOCALHOST, udp_port));
    udp.send(udp_dest, b"keep-udp").await.expect("udp pin");
    let (_, udp_pin) = tokio::time::timeout(Duration::from_secs(5), udp.recv())
        .await
        .expect("udp pin timeout")
        .expect("udp pin recv");
    assert_eq!(udp_pin, b"keep-udp");

    tokio::time::sleep(Duration::from_millis(2500)).await;

    for _ in 0..8 {
        let result = client.open_tcp(&echo_destination(syn_reset)).await;
        assert!(result.is_err(), "SYN RST must fail before establish");
        let message = result.err().expect("syn rst error").to_string();
        assert!(
            message.contains("closed before establish"),
            "expected SYN reject, got {message}"
        );
    }
    let blackhole = Destination {
        host: Host::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        port: 81,
    };
    let blackhole_result =
        tokio::time::timeout(Duration::from_secs(2), client.open_tcp(&blackhole)).await;
    assert!(
        matches!(blackhole_result, Err(_) | Ok(Err(_))),
        "blackhole SYN should not establish"
    );

    live_tcp.write_all(b"still").await.expect("idle tcp write");
    let mut still = [0_u8; 5];
    live_tcp
        .read_exact(&mut still)
        .await
        .expect("idle tcp read");
    assert_eq!(&still, b"still");
    udp.send(udp_dest, b"still-udp")
        .await
        .expect("idle udp send");
    let (_, got) = tokio::time::timeout(Duration::from_secs(5), udp.recv())
        .await
        .expect("idle udp timeout")
        .expect("idle udp recv");
    assert_eq!(got, b"still-udp");
    tcp_echo(&client, echo_port, b"after-idle-failures").await;
    client.close().await;
}

#[tokio::test]
async fn failed_endpoint_update_keeps_previous_peer() {
    let echo_port = spawn_echo().await;
    let (client_priv, client_pub) = pair(81);
    let (server_priv, server_pub) = pair(83);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub, 2);
    let client = Client::new(client_options(
        endpoint.port(),
        client_priv,
        server_pub,
        None,
    ))
    .await
    .expect("client");
    tcp_echo(&client, echo_port, b"before-bad-endpoint").await;
    let broadcast = SocketAddr::from((Ipv4Addr::BROADCAST, 1));
    client
        .replace_endpoint(broadcast)
        .await
        .expect_err("broadcast endpoint must not commit");
    tcp_echo(&client, echo_port, b"after-broadcast-endpoint").await;
    let link_local = SocketAddr::from((std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 1));
    client
        .replace_endpoint(link_local)
        .await
        .expect_err("IPv6 link-local without scope must not replace IPv4 peer");
    tcp_echo(&client, echo_port, b"after-family-fail").await;
    client.close().await;
}

#[tokio::test]
async fn traffic_follows_replaced_endpoint() {
    let echo_port = spawn_echo().await;
    let (client_priv, client_pub) = pair(29);
    let (server_priv, server_pub) = pair(31);
    let first = UdpSocket::bind("127.0.0.1:0").await.expect("first bind");
    let second = UdpSocket::bind("127.0.0.1:0").await.expect("second bind");
    let first_addr = first.local_addr().expect("first addr");
    let second_addr = second.local_addr().expect("second addr");
    let tunnel = Arc::new(
        NoiseTunnel::new(server_priv, client_pub, None, None, [0; 3], 2).expect("shared tunn"),
    );
    spawn_shared_responder(vec![first, second], Arc::clone(&tunnel));

    let client = Client::new(client_options(
        first_addr.port(),
        client_priv,
        server_pub,
        None,
    ))
    .await
    .expect("client");
    tcp_echo(&client, echo_port, b"via-first").await;
    client
        .replace_endpoint(second_addr)
        .await
        .expect("replace endpoint");
    tcp_echo(&client, echo_port, b"via-second").await;
    client.close().await;
}

#[tokio::test]
async fn endpoint_swap_to_unbound_port_keeps_reactor() {
    let echo_port = spawn_echo().await;
    let (client_priv, client_pub) = pair(33);
    let (server_priv, server_pub) = pair(35);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub, 2);
    let client = Client::new(client_options(
        endpoint.port(),
        client_priv,
        server_pub,
        None,
    ))
    .await
    .expect("client");
    tcp_echo(&client, echo_port, b"before-dead-endpoint").await;
    let unused = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("unused bind")
        .local_addr()
        .expect("unused addr");
    client
        .replace_endpoint(unused)
        .await
        .expect("unconnected socket can move to an unbound port");
    let _ = tokio::time::timeout(
        Duration::from_millis(400),
        client.open_tcp(&echo_destination(echo_port)),
    )
    .await;
    client
        .replace_endpoint(endpoint)
        .await
        .expect("restore endpoint");
    tokio::time::timeout(
        Duration::from_secs(5),
        tcp_echo(&client, echo_port, b"after-dead-endpoint"),
    )
    .await
    .expect("reactor must survive ICMP/recv_from errors after endpoint swap");
    client.close().await;
}

async fn wait_live_sockets(client: &Client, expected: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if client.live_socket_count() == expected {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "live sockets {} != {expected}",
            client.live_socket_count()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn failed_and_cancelled_dials_release_sockets() {
    let echo_port = spawn_echo().await;
    let (client_priv, client_pub) = pair(37);
    let (server_priv, server_pub) = pair(39);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub, 2);
    let client = Client::new(client_options(
        endpoint.port(),
        client_priv,
        server_pub,
        None,
    ))
    .await
    .expect("client");
    tcp_echo(&client, echo_port, b"cleanup-ready").await;
    wait_live_sockets(&client, 0).await;

    let unused = TcpListener::bind("127.0.0.1:0").await.expect("unused bind");
    let unused_port = unused.local_addr().expect("unused addr").port();
    drop(unused);
    let _ = client.open_tcp(&echo_destination(unused_port)).await;
    wait_live_sockets(&client, 0).await;

    let hanging = Destination {
        host: Host::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        port: 81,
    };
    {
        let mut dial = std::pin::pin!(client.open_tcp(&hanging));
        let _ = tokio::time::timeout(Duration::from_millis(200), &mut dial).await;
    }
    wait_live_sockets(&client, 0).await;
    client.close().await;
}

#[tokio::test]
async fn close_unblocks_pending_udp_recv() {
    let (client_priv, client_pub) = pair(41);
    let (server_priv, server_pub) = pair(43);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub, 2);
    let client = Client::new(client_options(
        endpoint.port(),
        client_priv,
        server_pub,
        None,
    ))
    .await
    .expect("client");
    let socket = client.open_udp().await.expect("udp");
    let recv = tokio::spawn(async move { socket.recv().await });
    client.close().await;
    let result = tokio::time::timeout(Duration::from_secs(1), recv)
        .await
        .expect("pending UDP recv should finish after close")
        .expect("join");
    assert!(
        result.is_err(),
        "closed UDP recv should error, got {result:?}"
    );
}

#[tokio::test]
async fn close_unblocks_pending_tcp_read() {
    let echo_port = spawn_echo().await;
    let (client_priv, client_pub) = pair(49);
    let (server_priv, server_pub) = pair(51);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub, 2);
    let client = Client::new(client_options(
        endpoint.port(),
        client_priv,
        server_pub,
        None,
    ))
    .await
    .expect("client");
    let mut stream = client
        .open_tcp(&echo_destination(echo_port))
        .await
        .expect("tcp");
    let read = tokio::spawn(async move {
        let mut buf = [0_u8; 8];
        tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await
    });
    client.close().await;
    let result = tokio::time::timeout(Duration::from_secs(1), read)
        .await
        .expect("pending TCP read should finish after close")
        .expect("join");
    assert!(
        result.is_err(),
        "closed TCP read should error, got {result:?}"
    );
}

#[tokio::test]
async fn refresh_resolves_original_hostname() {
    let echo_port = spawn_echo().await;
    let (client_priv, client_pub) = pair(45);
    let (server_priv, server_pub) = pair(47);
    let first = UdpSocket::bind("127.0.0.1:0").await.expect("first bind");
    let second = UdpSocket::bind("127.0.0.1:0").await.expect("second bind");
    let first_addr = first.local_addr().expect("first addr");
    let second_addr = second.local_addr().expect("second addr");
    let tunnel = Arc::new(
        NoiseTunnel::new(server_priv, client_pub, None, None, [0; 3], 2).expect("shared tunn"),
    );
    spawn_shared_responder(vec![first, second], Arc::clone(&tunnel));

    let current = Arc::new(std::sync::Mutex::new(first_addr));
    let hook = {
        let current = Arc::clone(&current);
        PeerResolveHook::new(move |host, _port| {
            let current = Arc::clone(&current);
            async move {
                assert_eq!(host, "wg-refresh.test");
                Some(
                    *current
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                )
            }
        })
    };
    let client = Client::new(ClientOptions {
        server: "wg-refresh.test".to_owned(),
        port: first_addr.port(),
        private_key: client_priv,
        peer_public_key: server_pub,
        initial_endpoint: Some(first_addr),
        resolve_peer: Some(hook),
        refresh_server_ip_interval: Duration::from_millis(150),
        ..ClientOptions::default()
    })
    .await
    .expect("client");
    tcp_echo(&client, echo_port, b"via-hostname-first").await;
    *current
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = second_addr;
    tokio::time::sleep(Duration::from_millis(400)).await;
    tcp_echo(&client, echo_port, b"via-hostname-second").await;
    client.close().await;
}

#[tokio::test]
async fn endpoint_refresh_does_not_block_reactor() {
    let echo_port = spawn_echo().await;
    let (client_priv, client_pub) = pair(53);
    let (server_priv, server_pub) = pair(55);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub, 2);
    let hook = PeerResolveHook::new(move |_host, _port| async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        Some(endpoint)
    });
    let client = Client::new(ClientOptions {
        server: "wg-slow-refresh.test".to_owned(),
        port: endpoint.port(),
        private_key: client_priv,
        peer_public_key: server_pub,
        initial_endpoint: Some(endpoint),
        resolve_peer: Some(hook),
        refresh_server_ip_interval: Duration::from_millis(50),
        ..ClientOptions::default()
    })
    .await
    .expect("client");
    tokio::time::sleep(Duration::from_millis(80)).await;
    tokio::time::timeout(
        Duration::from_secs(1),
        tcp_echo(&client, echo_port, b"during-slow-dns"),
    )
    .await
    .expect("reactor should keep forwarding while DNS refresh is in flight");
    client.close().await;
}

#[tokio::test]
async fn failed_refresh_backs_off_instead_of_retrying_every_tick() {
    let (client_priv, client_pub) = pair(57);
    let (server_priv, server_pub) = pair(59);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub, 2);
    let attempts = Arc::new(AtomicUsize::new(0));
    let hook = {
        let attempts = Arc::clone(&attempts);
        PeerResolveHook::new(move |_host, _port| {
            attempts.fetch_add(1, Ordering::Relaxed);
            async move { None }
        })
    };
    let client = Client::new(ClientOptions {
        server: "wg-backoff.test".to_owned(),
        port: endpoint.port(),
        private_key: client_priv,
        peer_public_key: server_pub,
        initial_endpoint: Some(endpoint),
        resolve_peer: Some(hook),
        refresh_server_ip_interval: Duration::from_millis(50),
        ..ClientOptions::default()
    })
    .await
    .expect("client");
    tokio::time::sleep(Duration::from_millis(800)).await;
    let calls = attempts.load(Ordering::Relaxed);
    assert_eq!(
        calls, 1,
        "failed refresh should back off instead of retrying every 100ms tick, got {calls}"
    );
    client.close().await;
}

#[tokio::test]
async fn drop_during_refresh_stops_reactor() {
    let (client_priv, client_pub) = pair(69);
    let (server_priv, server_pub) = pair(71);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub, 2);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
    let hook = {
        let started_tx = Arc::clone(&started_tx);
        PeerResolveHook::new(move |_host, _port| {
            let started = started_tx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            async move {
                if let Some(started) = started {
                    let _ = started.send(());
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                Some(endpoint)
            }
        })
    };
    let client = Client::new(ClientOptions {
        server: "wg-drop-during-refresh.test".to_owned(),
        port: endpoint.port(),
        private_key: client_priv,
        peer_public_key: server_pub,
        initial_endpoint: Some(endpoint),
        resolve_peer: Some(hook),
        refresh_server_ip_interval: Duration::from_millis(50),
        ..ClientOptions::default()
    })
    .await
    .expect("client");
    let socket = client.open_udp().await.expect("udp");
    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .expect("refresh hook should start")
        .expect("refresh started signal");
    let recv = tokio::spawn(async move { socket.recv().await });
    drop(client);
    let result = tokio::time::timeout(Duration::from_secs(1), recv)
        .await
        .expect("pending UDP recv should finish after dropping the last client during refresh")
        .expect("join");
    assert!(
        result.is_err(),
        "drop during refresh should cancel the reactor, got {result:?}"
    );
}

#[tokio::test]
async fn refresh_keeps_configured_endpoint_when_system_dns_differs() {
    let echo_port = spawn_echo().await;
    let (client_priv, client_pub) = pair(61);
    let (server_priv, server_pub) = pair(63);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let decoy = UdpSocket::bind("127.0.0.1:0").await.expect("decoy bind");
    let endpoint = listen.local_addr().expect("wg addr");
    let decoy_addr = decoy.local_addr().expect("decoy addr");
    spawn_responder(listen, server_priv, client_pub, 2);
    let system = tokio::net::lookup_host(("localhost", decoy_addr.port()))
        .await
        .expect("system localhost")
        .next()
        .expect("localhost address");
    assert_ne!(
        system,
        endpoint,
        "system localhost:{decoy} must differ from the WireGuard bind",
        decoy = decoy_addr.port()
    );
    let hook = PeerResolveHook::new(move |host, _port| async move {
        assert_eq!(host, "localhost");
        Some(endpoint)
    });
    let client = Client::new(ClientOptions {
        server: "localhost".to_owned(),
        port: decoy_addr.port(),
        private_key: client_priv,
        peer_public_key: server_pub,
        initial_endpoint: Some(endpoint),
        resolve_peer: Some(hook),
        refresh_server_ip_interval: Duration::from_millis(80),
        ..ClientOptions::default()
    })
    .await
    .expect("client");
    tokio::time::sleep(Duration::from_millis(250)).await;
    tcp_echo(&client, echo_port, b"configured-not-system").await;
    client.close().await;
    drop(decoy);
}

#[tokio::test]
async fn failed_configured_refresh_does_not_fall_back_to_system_dns() {
    let echo_port = spawn_echo().await;
    let (client_priv, client_pub) = pair(65);
    let (server_priv, server_pub) = pair(67);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let decoy = UdpSocket::bind("127.0.0.1:0").await.expect("decoy bind");
    let endpoint = listen.local_addr().expect("wg addr");
    let decoy_addr = decoy.local_addr().expect("decoy addr");
    spawn_responder(listen, server_priv, client_pub, 2);
    let hook = PeerResolveHook::new(|_host, _port| async move { None });
    let client = Client::new(ClientOptions {
        server: "localhost".to_owned(),
        port: decoy_addr.port(),
        private_key: client_priv,
        peer_public_key: server_pub,
        initial_endpoint: Some(endpoint),
        resolve_peer: Some(hook),
        refresh_server_ip_interval: Duration::from_millis(80),
        ..ClientOptions::default()
    })
    .await
    .expect("client");
    tokio::time::sleep(Duration::from_millis(250)).await;
    tcp_echo(&client, echo_port, b"keep-configured-on-fail").await;
    client.close().await;
    drop(decoy);
}

fn spawn_responder(udp: UdpSocket, private_key: [u8; 32], peer_public_key: [u8; 32], index: u32) {
    spawn_responder_with_hooks(
        udp,
        private_key,
        peer_public_key,
        index,
        InnerTcpHooks::default(),
    );
}

fn spawn_responder_with_hooks(
    udp: UdpSocket,
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    index: u32,
    hooks: InnerTcpHooks,
) {
    let tunnel = Arc::new(
        NoiseTunnel::new(private_key, peer_public_key, None, None, [0; 3], index)
            .expect("server tunn"),
    );
    spawn_shared_responder_with_slot(vec![udp], &Arc::new(std::sync::Mutex::new(tunnel)), hooks);
}

fn spawn_swappable_responder(
    udp: UdpSocket,
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    index: u32,
) -> SwappableResponder {
    let tunnel = Arc::new(
        NoiseTunnel::new(private_key, peer_public_key, None, None, [0; 3], index)
            .expect("server tunn"),
    );
    let slot = Arc::new(std::sync::Mutex::new(Arc::clone(&tunnel)));
    let _peer = spawn_shared_responder_with_slot(vec![udp], &slot, InnerTcpHooks::default());
    SwappableResponder { tunnel: slot }
}

fn spawn_shared_responder(sockets: Vec<UdpSocket>, tunnel: Arc<NoiseTunnel>) {
    let slot = Arc::new(std::sync::Mutex::new(tunnel));
    spawn_shared_responder_with_slot(sockets, &slot, InnerTcpHooks::default());
}

type PeerEndpoint = Arc<Mutex<Option<(SocketAddr, Arc<UdpSocket>)>>>;

#[derive(Clone, Copy, Default)]
struct InnerTcpHooks {
    syn_reset: Option<u16>,
    data_reset: Option<u16>,
    blackhole: Option<Ipv4Addr>,
}

struct SwappableResponder {
    tunnel: Arc<std::sync::Mutex<Arc<NoiseTunnel>>>,
}

#[allow(clippy::too_many_lines)]
fn spawn_shared_responder_with_slot(
    sockets: Vec<UdpSocket>,
    tunnel: &Arc<std::sync::Mutex<Arc<NoiseTunnel>>>,
    hooks: InnerTcpHooks,
) -> PeerEndpoint {
    let (stack, runner, stack_udp, tcp) = StackBuilder::default()
        .stack_buffer_size(1024)
        .tcp_buffer_size(1024)
        .udp_buffer_size(1024)
        .enable_udp(true)
        .enable_tcp(true)
        .enable_icmp(true)
        .mtu(1408)
        .build()
        .expect("stack");
    if let Some(runner) = runner {
        tokio::spawn(runner);
    }
    let tcp = tcp.expect("tcp");
    let stack_udp = stack_udp.expect("udp");
    let (mut stack_sink, mut stack_stream) = stack.split();
    let peer = Arc::new(Mutex::new(None::<(SocketAddr, Arc<UdpSocket>)>));
    let sockets: Vec<Arc<UdpSocket>> = sockets.into_iter().map(Arc::new).collect();
    let (ip_tx, mut ip_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    tokio::spawn(async move {
        while let Some(ip) = ip_rx.recv().await {
            if stack_sink.send(ip).await.is_err() {
                break;
            }
        }
    });

    for udp in sockets {
        let recv_udp = Arc::clone(&udp);
        let recv_tunnel = Arc::clone(tunnel);
        let recv_peer = Arc::clone(&peer);
        let ip_tx = ip_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0_u8; 65_535];
            loop {
                let Ok((n, from)) = recv_udp.recv_from(&mut buf).await else {
                    break;
                };
                *recv_peer.lock().await = Some((from, Arc::clone(&recv_udp)));
                let current = recv_tunnel
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                let mut packet: &[u8] = &buf[..n];
                loop {
                    match current.decapsulate(Some(from), packet) {
                        TunnelAction::Done | TunnelAction::Expired => break,
                        TunnelAction::SendUdp(reply) => {
                            let _ = recv_udp.send_to(&reply, from).await;
                            packet = &[];
                        }
                        TunnelAction::RecvIp(ip) => {
                            match classify_inner(&ip, &hooks) {
                                InnerAction::Drop => {}
                                InnerAction::Reply(rst) => {
                                    if let TunnelAction::SendUdp(datagram) =
                                        current.encapsulate(&rst)
                                    {
                                        let _ = recv_udp.send_to(&datagram, from).await;
                                    }
                                }
                                InnerAction::Forward => {
                                    if ip_tx.send(ip).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            packet = &[];
                        }
                    }
                }
            }
        });
    }

    let send_tunnel = Arc::clone(tunnel);
    let send_peer = Arc::clone(&peer);
    tokio::spawn(async move {
        while let Some(frame) = stack_stream.next().await {
            let Ok(packet) = frame else { break };
            let current = send_tunnel
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let TunnelAction::SendUdp(datagram) = current.encapsulate(&packet)
                && let Some((endpoint, udp)) = send_peer.lock().await.clone()
            {
                let _ = udp.send_to(&datagram, endpoint).await;
            }
        }
    });

    tokio::spawn(async move {
        let mut listener = tcp;
        loop {
            let Some((mut inbound, _, remote)) = listener.next().await else {
                break;
            };
            tokio::spawn(async move {
                let Ok(mut outbound) = TcpStream::connect(remote).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    });

    let (mut reader, writer) = stack_udp.split();
    let writer = Arc::new(Mutex::new(writer));
    tokio::spawn(async move {
        while let Some((payload, local, remote)) = reader.next().await {
            if payload.is_empty() {
                continue;
            }
            let writer = Arc::clone(&writer);
            tokio::spawn(async move {
                let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
                    return;
                };
                if socket.send_to(&payload, remote).await.is_err() {
                    return;
                }
                let mut buf = vec![0_u8; 65_535];
                let Ok(Ok((n, _))) =
                    tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await
                else {
                    return;
                };
                let mut writer = writer.lock().await;
                let _ = writer.send((buf[..n].to_vec(), remote, local)).await;
            });
        }
    });
    peer
}

enum InnerAction {
    Forward,
    Drop,
    Reply(Vec<u8>),
}

fn classify_inner(packet: &[u8], hooks: &InnerTcpHooks) -> InnerAction {
    let Ok(ipv4) = smoltcp::wire::Ipv4Packet::new_checked(packet) else {
        return InnerAction::Forward;
    };
    let dest = Ipv4Addr::from(ipv4.dst_addr().octets());
    if hooks.blackhole == Some(dest) {
        return InnerAction::Drop;
    }
    if ipv4.next_header() != smoltcp::wire::IpProtocol::Tcp {
        return InnerAction::Forward;
    }
    let Ok(tcp) = smoltcp::wire::TcpPacket::new_checked(ipv4.payload()) else {
        return InnerAction::Forward;
    };
    let dport = tcp.dst_port();
    let syn_only = tcp.syn() && !tcp.ack();
    if hooks.syn_reset == Some(dport) && syn_only {
        return tcp_rst_reply(packet).map_or(InnerAction::Drop, InnerAction::Reply);
    }
    if hooks.data_reset == Some(dport) && !syn_only {
        return tcp_rst_reply(packet).map_or(InnerAction::Drop, InnerAction::Reply);
    }
    InnerAction::Forward
}

fn tcp_rst_reply(packet: &[u8]) -> Option<Vec<u8>> {
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
    };
    let caps = ChecksumCapabilities::ignored();
    let ipv4 = Ipv4Packet::new_checked(packet).ok()?;
    let ipv4_repr = Ipv4Repr::parse(&ipv4, &caps).ok()?;
    if ipv4_repr.next_header != IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(ipv4.payload()).ok()?;
    let tcp_repr = TcpRepr::parse(
        &tcp,
        &IpAddress::Ipv4(ipv4_repr.src_addr),
        &IpAddress::Ipv4(ipv4_repr.dst_addr),
        &caps,
    )
    .ok()?;
    let ack = tcp_repr.seq_number + tcp_repr.segment_len();
    let reply_tcp = TcpRepr {
        src_port: tcp_repr.dst_port,
        dst_port: tcp_repr.src_port,
        control: TcpControl::Rst,
        seq_number: tcp_repr
            .ack_number
            .unwrap_or(smoltcp::wire::TcpSeqNumber(0)),
        ack_number: Some(ack),
        window_len: 0,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    let reply_ipv4 = Ipv4Repr {
        src_addr: ipv4_repr.dst_addr,
        dst_addr: ipv4_repr.src_addr,
        next_header: IpProtocol::Tcp,
        payload_len: reply_tcp.header_len(),
        hop_limit: 64,
    };
    let emit = ChecksumCapabilities::default();
    let mut out = vec![0_u8; reply_ipv4.buffer_len() + reply_tcp.header_len()];
    let mut ipv4_out = Ipv4Packet::new_unchecked(&mut out);
    reply_ipv4.emit(&mut ipv4_out, &emit);
    reply_tcp.emit(
        &mut TcpPacket::new_unchecked(ipv4_out.payload_mut()),
        &IpAddress::Ipv4(reply_ipv4.src_addr),
        &IpAddress::Ipv4(reply_ipv4.dst_addr),
        &emit,
    );
    Some(out)
}

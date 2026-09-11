//! 6I-C lifecycle: persistent keepalive, rehandshake after peer restart, endpoint move.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use defguard_boringtun::x25519::{PublicKey, StaticSecret};
use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use rewrite_model::{Destination, Host};
use rewrite_protocol_wireguard::{Client, ClientOptions, NoiseTunnel, TunnelAction};
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
    let tunnel = spawn_swappable_responder(listen, server_priv, client_pub, 2);

    let client = Client::new(client_options(
        endpoint.port(),
        client_priv,
        server_pub,
        None,
    ))
    .await
    .expect("client");
    tcp_echo(&client, echo_port, b"before-restart").await;

    *tunnel.lock().expect("swap") = Arc::new(
        NoiseTunnel::new(server_priv, client_pub, None, None, [0; 3], 4).expect("new peer"),
    );

    tcp_echo(&client, echo_port, b"after-restart").await;
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

fn spawn_responder(udp: UdpSocket, private_key: [u8; 32], peer_public_key: [u8; 32], index: u32) {
    let tunnel = Arc::new(
        NoiseTunnel::new(private_key, peer_public_key, None, None, [0; 3], index)
            .expect("server tunn"),
    );
    spawn_shared_responder(vec![udp], tunnel);
}

fn spawn_swappable_responder(
    udp: UdpSocket,
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    index: u32,
) -> Arc<std::sync::Mutex<Arc<NoiseTunnel>>> {
    let tunnel = Arc::new(
        NoiseTunnel::new(private_key, peer_public_key, None, None, [0; 3], index)
            .expect("server tunn"),
    );
    let slot = Arc::new(std::sync::Mutex::new(Arc::clone(&tunnel)));
    spawn_shared_responder_with_slot(vec![udp], Arc::clone(&slot));
    slot
}

fn spawn_shared_responder(sockets: Vec<UdpSocket>, tunnel: Arc<NoiseTunnel>) {
    let slot = Arc::new(std::sync::Mutex::new(tunnel));
    spawn_shared_responder_with_slot(sockets, slot);
}

#[allow(clippy::too_many_lines)]
fn spawn_shared_responder_with_slot(
    sockets: Vec<UdpSocket>,
    tunnel: Arc<std::sync::Mutex<Arc<NoiseTunnel>>>,
) {
    let (stack, runner, _udp, tcp) = StackBuilder::default()
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
        let recv_tunnel = Arc::clone(&tunnel);
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
                            if ip_tx.send(ip).await.is_err() {
                                return;
                            }
                            packet = &[];
                        }
                    }
                }
            }
        });
    }

    let send_tunnel = Arc::clone(&tunnel);
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
}

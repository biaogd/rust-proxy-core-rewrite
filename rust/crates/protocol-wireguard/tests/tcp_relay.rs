//! In-process 6I-A TCP relay: userspace client → `WireGuard` → netstack → echo.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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

#[tokio::test]
async fn userspace_tcp_relays_echo() {
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let echo_addr = echo.local_addr().expect("echo addr");
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

    let (client_priv, client_pub) = pair(7);
    let (server_priv, server_pub) = pair(9);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub);

    let client = Client::new(ClientOptions {
        server: "127.0.0.1".to_owned(),
        port: endpoint.port(),
        private_key: client_priv,
        peer_public_key: server_pub,
        preshared_key: None,
        local_v4: Some((Ipv4Addr::new(10, 0, 0, 2), 32)),
        local_v6: None,
        mtu: 1408,
        persistent_keepalive: None,
        reserved: [0; 3],
        bind_interface: String::new(),
        routing_mark: 0,
        refresh_server_ip_interval: Duration::ZERO,
        initial_endpoint: None,
        resolve_peer: None,
    })
    .await
    .expect("client");

    let destination = Destination {
        host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: echo_addr.port(),
    };
    let mut stream = client.open_tcp(&destination).await.expect("open tcp");
    stream.write_all(b"wg-echo").await.expect("write");
    let mut got = [0_u8; 7];
    stream.read_exact(&mut got).await.expect("read");
    assert_eq!(&got, b"wg-echo");
    client.close().await;
}

#[tokio::test]
async fn userspace_tcp_relays_echo_ipv6() {
    let echo = TcpListener::bind("[::1]:0").await.expect("echo bind");
    let echo_addr = echo.local_addr().expect("echo addr");
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

    let (client_priv, client_pub) = pair(11);
    let (server_priv, server_pub) = pair(13);
    let listen = UdpSocket::bind("127.0.0.1:0").await.expect("wg bind");
    let endpoint = listen.local_addr().expect("wg addr");
    spawn_responder(listen, server_priv, client_pub);

    let client = Client::new(ClientOptions {
        server: "127.0.0.1".to_owned(),
        port: endpoint.port(),
        private_key: client_priv,
        peer_public_key: server_pub,
        preshared_key: None,
        local_v4: None,
        local_v6: Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 128)),
        mtu: 1408,
        persistent_keepalive: None,
        reserved: [0; 3],
        bind_interface: String::new(),
        routing_mark: 0,
        refresh_server_ip_interval: Duration::ZERO,
        initial_endpoint: None,
        resolve_peer: None,
    })
    .await
    .expect("client");

    let destination = Destination {
        host: Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        port: echo_addr.port(),
    };
    let mut stream = client.open_tcp(&destination).await.expect("open ipv6 tcp");
    stream.write_all(b"wg-v6").await.expect("write");
    let mut got = [0_u8; 5];
    stream.read_exact(&mut got).await.expect("read");
    assert_eq!(&got, b"wg-v6");
    client.close().await;
}

fn spawn_responder(udp: UdpSocket, private_key: [u8; 32], peer_public_key: [u8; 32]) {
    let tunnel = Arc::new(
        NoiseTunnel::new(private_key, peer_public_key, None, None, [0; 3], 2).expect("server tunn"),
    );
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
    let peer = Arc::new(Mutex::new(None::<SocketAddr>));
    let udp = Arc::new(udp);

    let recv_udp = Arc::clone(&udp);
    let recv_tunnel = Arc::clone(&tunnel);
    let recv_peer = Arc::clone(&peer);
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 65_535];
        loop {
            let Ok((n, from)) = recv_udp.recv_from(&mut buf).await else {
                break;
            };
            *recv_peer.lock().await = Some(from);
            let mut packet: &[u8] = &buf[..n];
            loop {
                match recv_tunnel.decapsulate(Some(from), packet) {
                    TunnelAction::Done | TunnelAction::Expired => break,
                    TunnelAction::SendUdp(reply) => {
                        let _ = recv_udp.send_to(&reply, from).await;
                        packet = &[];
                    }
                    TunnelAction::RecvIp(ip) => {
                        if stack_sink.send(ip).await.is_err() {
                            return;
                        }
                        packet = &[];
                    }
                }
            }
        }
    });

    let send_udp = Arc::clone(&udp);
    let send_tunnel = Arc::clone(&tunnel);
    let send_peer = Arc::clone(&peer);
    tokio::spawn(async move {
        while let Some(frame) = stack_stream.next().await {
            let Ok(packet) = frame else { break };
            if let TunnelAction::SendUdp(datagram) = send_tunnel.encapsulate(&packet)
                && let Some(endpoint) = *send_peer.lock().await
            {
                let _ = send_udp.send_to(&datagram, endpoint).await;
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

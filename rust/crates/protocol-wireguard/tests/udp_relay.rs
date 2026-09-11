//! In-process 6I-B UDP relay: userspace client → `WireGuard` → netstack → echo.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use defguard_boringtun::x25519::{PublicKey, StaticSecret};
use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use rewrite_protocol_wireguard::{Client, ClientOptions, NoiseTunnel, TunnelAction};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

fn pair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::from([seed; 32]);
    let public = PublicKey::from(&secret);
    (*secret.as_bytes(), *public.as_bytes())
}

#[tokio::test]
async fn userspace_udp_relays_echo() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.expect("echo bind");
    let echo_addr = echo.local_addr().expect("echo addr");
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

    let socket = client.open_udp().await.expect("open udp");
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), echo_addr.port());
    socket.send(dest, b"wg-udp").await.expect("send");
    let (from, payload) = tokio::time::timeout(Duration::from_secs(5), socket.recv())
        .await
        .expect("recv timeout")
        .expect("recv");
    assert_eq!(from, dest);
    assert_eq!(payload, b"wg-udp");

    let large = vec![0x5a_u8; 1024];
    socket.send(dest, &large).await.expect("large send");
    let (_, got) = tokio::time::timeout(Duration::from_secs(5), socket.recv())
        .await
        .expect("large timeout")
        .expect("large recv");
    assert_eq!(got, large);
    client.close().await;
}

#[allow(clippy::too_many_lines)]
fn spawn_responder(udp: UdpSocket, private_key: [u8; 32], peer_public_key: [u8; 32]) {
    let tunnel = Arc::new(
        NoiseTunnel::new(private_key, peer_public_key, None, None, [0; 3], 2).expect("server tunn"),
    );
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
}

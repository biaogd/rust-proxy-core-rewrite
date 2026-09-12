//! Userspace `WireGuard` TCP/UDP relay authority for 6I Go/Rust differentials.
//!
//! This is not a Clash inbound. It decrypts a single peer, feeds inner IP
//! into `netstack-smoltcp`, and splices accepted TCP/UDP to the packet destination.

use std::error::Error;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use rand::RngExt as _;
use rewrite_protocol_wireguard::{NoiseTunnel, TunnelAction, decode_key};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let listen = arguments
        .next()
        .ok_or("missing listen address")?
        .parse::<SocketAddr>()?;
    let private_key = decode_key(&arguments.next().ok_or("missing private key")?)?;
    let peer_public_key = decode_key(&arguments.next().ok_or("missing peer public key")?)?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }

    let udp = UdpSocket::bind(listen).await?;
    let local = udp.local_addr()?;
    let tunnel = Arc::new(
        NoiseTunnel::new(
            private_key,
            peer_public_key,
            None,
            None,
            [0; 3],
            rand::rng().random::<u32>(),
        )
        .map_err(|error| io::Error::other(error.to_string()))?,
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
        .map_err(|error| io::Error::other(error.to_string()))?;
    if let Some(runner) = runner {
        tokio::spawn(runner);
    }
    let tcp = tcp.ok_or("TCP disabled unexpectedly")?;
    let stack_udp = stack_udp.ok_or("UDP disabled unexpectedly")?;
    let (stack_sink, stack_stream) = stack.split();
    let peer = Arc::new(Mutex::new(None::<SocketAddr>));
    let udp = Arc::new(udp);

    spawn_udp_recv(
        Arc::clone(&udp),
        Arc::clone(&tunnel),
        Arc::clone(&peer),
        stack_sink,
    );
    spawn_stack_send(udp, Arc::clone(&tunnel), Arc::clone(&peer), stack_stream);
    spawn_tcp_splice(tcp);
    spawn_udp_splice(stack_udp);

    println!("READY {local}");
    io::stdout().flush()?;
    std::future::pending::<()>().await;
    Ok(())
}

fn spawn_udp_recv<S>(
    udp: Arc<UdpSocket>,
    tunnel: Arc<NoiseTunnel>,
    peer: Arc<Mutex<Option<SocketAddr>>>,
    mut stack_sink: S,
) where
    S: futures_util::Sink<Vec<u8>> + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 65_535];
        loop {
            let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                break;
            };
            {
                let mut guard = peer.lock().await;
                *guard = Some(from);
            }
            let mut packet: &[u8] = &buf[..n];
            loop {
                match tunnel.decapsulate(Some(from), packet) {
                    TunnelAction::Done | TunnelAction::Expired => break,
                    TunnelAction::SendUdp(reply) => {
                        let _ = udp.send_to(&reply, from).await;
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
}

fn spawn_stack_send<S>(
    udp: Arc<UdpSocket>,
    tunnel: Arc<NoiseTunnel>,
    peer: Arc<Mutex<Option<SocketAddr>>>,
    mut stack_stream: S,
) where
    S: futures_util::Stream<Item = Result<Vec<u8>, std::io::Error>> + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        while let Some(frame) = stack_stream.next().await {
            let Ok(packet) = frame else { break };
            if let TunnelAction::SendUdp(datagram) = tunnel.encapsulate(&packet)
                && let Some(endpoint) = *peer.lock().await
            {
                let _ = udp.send_to(&datagram, endpoint).await;
            }
            while let TunnelAction::SendUdp(extra) = tunnel.decapsulate(None, &[]) {
                let Some(endpoint) = *peer.lock().await else {
                    break;
                };
                let _ = udp.send_to(&extra, endpoint).await;
            }
        }
    });
}

fn spawn_tcp_splice<S, T>(mut listener: S)
where
    S: futures_util::Stream<Item = (T, SocketAddr, SocketAddr)> + Unpin + Send + 'static,
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let Some((mut inbound, _local, remote)) = listener.next().await else {
                break;
            };
            tokio::spawn(async move {
                let Ok(mut outbound) = TcpStream::connect(remote).await else {
                    return;
                };
                let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    });
}

fn spawn_udp_splice(udp: netstack_smoltcp::UdpSocket) {
    let (mut reader, writer) = udp.split();
    let writer = Arc::new(Mutex::new(writer));
    tokio::spawn(async move {
        while let Some((payload, local, remote)) = reader.next().await {
            if payload.is_empty() {
                continue;
            }
            let writer = Arc::clone(&writer);
            tokio::spawn(async move {
                let bind = SocketAddr::new(
                    match remote {
                        SocketAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.into(),
                        SocketAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.into(),
                    },
                    0,
                );
                let Ok(socket) = UdpSocket::bind(bind).await else {
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

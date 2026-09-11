use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::udp::UdpMsg;
use netstack_smoltcp::{TcpListener, TcpStream, UdpSocket};
use rewrite_model::{Destination, Host, InboundProtocol, Metadata, Network};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// TCP stream accepted from the userspace stack with fixed local/remote addrs.
pub struct TunInboundStream {
    inner: TcpStream,
    local: SocketAddr,
    peer: SocketAddr,
}

impl TunInboundStream {
    #[must_use]
    pub fn new(inner: TcpStream, local: SocketAddr, peer: SocketAddr) -> Self {
        Self { inner, local, peer }
    }

    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
}

impl AsyncRead for TunInboundStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunInboundStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct InboundTcpSession {
    pub stream: TunInboundStream,
    pub metadata: Metadata,
}

#[derive(Clone, Debug)]
pub struct InboundUdpDatagram {
    pub metadata: Metadata,
    pub payload: Vec<u8>,
    /// Original client address observed on the TUN side.
    pub session_peer: SocketAddr,
    /// Destination address from the IP/UDP headers.
    pub remote: SocketAddr,
}

/// Sender used by the runtime UDP reply sink to emit datagrams back into the stack.
pub type TunUdpReplyTx = mpsc::Sender<UdpMsg>;
/// Bounded TUN UDP write-back queue. Full replies are dropped (congestion).
pub const TUN_UDP_REPLY_CAP: usize = 1024;

pub struct TunSessionHub {
    tcp_rx: mpsc::Receiver<InboundTcpSession>,
    udp_rx: mpsc::Receiver<InboundUdpDatagram>,
    reply_tx: TunUdpReplyTx,
}

impl TunSessionHub {
    #[must_use]
    pub fn reply_tx(&self) -> TunUdpReplyTx {
        self.reply_tx.clone()
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        mpsc::Receiver<InboundTcpSession>,
        mpsc::Receiver<InboundUdpDatagram>,
        TunUdpReplyTx,
    ) {
        (self.tcp_rx, self.udp_rx, self.reply_tx)
    }
}

/// Spawns accept loops that turn stack TCP/UDP into inbound sessions.
#[must_use]
pub fn spawn_session_hub(
    tcp_listener: TcpListener,
    udp_socket: UdpSocket,
    shutdown: CancellationToken,
) -> TunSessionHub {
    let (tcp_tx, tcp_rx) = mpsc::channel(256);
    let (udp_tx, udp_rx) = mpsc::channel(512);
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpMsg>(TUN_UDP_REPLY_CAP);
    let (mut udp_read, mut udp_write) = udp_socket.split();

    let tcp_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let mut listener = tcp_listener;
        loop {
            tokio::select! {
                () = tcp_shutdown.cancelled() => break,
                accepted = listener.next() => {
                    let Some((stream, local, remote)) = accepted else { break };
                    // netstack-smoltcp 0.2.4 TcpStream::local_addr is the packet
                    // source (TUN client); remote_addr is the packet destination.
                    let metadata = tun_tcp_metadata(local, remote);
                    let session = InboundTcpSession {
                        stream: TunInboundStream::new(stream, remote, local),
                        metadata,
                    };
                    if tcp_tx.send(session).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let udp_shutdown = shutdown.clone();
    let udp_forward = udp_tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = udp_shutdown.cancelled() => break,
                datagram = udp_read.next() => {
                    let Some((payload, local, remote)) = datagram else { break };
                    // UDP stream items are (payload, src=client, dst=server).
                    let metadata = tun_udp_metadata(local, remote);
                    let packet = InboundUdpDatagram {
                        metadata,
                        payload,
                        session_peer: local,
                        remote,
                    };
                    if udp_forward.send(packet).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let reply_shutdown = shutdown;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = reply_shutdown.cancelled() => break,
                reply = reply_rx.recv() => {
                    let Some((payload, src, dst)) = reply else { break };
                    // Reply toward the TUN client: stack write uses (payload, src=server, dst=client).
                    if udp_write.send((payload, src, dst)).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = udp_write.close().await;
    });

    TunSessionHub {
        tcp_rx,
        udp_rx,
        reply_tx,
    }
}

fn tun_tcp_metadata(client: SocketAddr, destination: SocketAddr) -> Metadata {
    let mut metadata = Metadata::new(
        Destination {
            host: Host::Ip(destination.ip()),
            port: destination.port(),
        },
        InboundProtocol::Tun,
    );
    metadata.network = Network::Tcp;
    metadata.source_ip = Some(client.ip());
    metadata.source_port = client.port();
    metadata.destination_ip = Some(destination.ip());
    metadata.inbound_port = destination.port();
    "DEFAULT-TUN".clone_into(&mut metadata.inbound_name);
    metadata
}

fn tun_udp_metadata(client: SocketAddr, destination: SocketAddr) -> Metadata {
    let mut metadata = Metadata::new(
        Destination {
            host: Host::Ip(destination.ip()),
            port: destination.port(),
        },
        InboundProtocol::Tun,
    );
    metadata.network = Network::Udp;
    metadata.source_ip = Some(client.ip());
    metadata.source_port = client.port();
    metadata.destination_ip = Some(destination.ip());
    metadata.inbound_port = destination.port();
    "DEFAULT-TUN".clone_into(&mut metadata.inbound_name);
    metadata
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_reply_queue_is_bounded() {
        assert_eq!(TUN_UDP_REPLY_CAP, 1024);
    }

    #[test]
    fn tcp_metadata_marks_tun_inbound() {
        let client = "10.0.0.2:12345".parse().expect("client");
        let destination = "1.2.3.4:443".parse().expect("dest");
        let metadata = tun_tcp_metadata(client, destination);
        assert_eq!(metadata.inbound, InboundProtocol::Tun);
        assert_eq!(metadata.network, Network::Tcp);
        assert_eq!(metadata.inbound_name, "DEFAULT-TUN");
        assert_eq!(metadata.source_ip, Some(client.ip()));
        assert_eq!(metadata.destination.port, 443);
    }

    #[test]
    fn udp_metadata_uses_packet_destination() {
        let client = "10.0.0.2:12345".parse().expect("client");
        let destination = "8.8.8.8:53".parse().expect("dest");
        let metadata = tun_udp_metadata(client, destination);
        assert_eq!(metadata.inbound, InboundProtocol::Tun);
        assert_eq!(metadata.network, Network::Udp);
        assert_eq!(metadata.destination.port, 53);
        assert_eq!(metadata.destination_ip, Some(destination.ip()));
        assert_eq!(metadata.source_ip, Some(client.ip()));
    }
}

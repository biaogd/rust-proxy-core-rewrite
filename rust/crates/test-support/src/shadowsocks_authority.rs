use std::error::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use shadowsocks::ProxyListener;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::udprelay::ProxySocket;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpStream, UdpSocket};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let listen = arguments
        .next()
        .ok_or("missing listen address")?
        .parse::<SocketAddr>()?;
    let password = arguments.next().ok_or("missing password")?;
    let cipher = arguments.next().ok_or("missing cipher")?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }

    let method = CipherKind::from_str(&cipher).map_err(|_| "unsupported cipher")?;
    let server = ServerConfig::new(listen, password, method)?;
    let context = Context::new_shared(ServerType::Server);
    let listener = ProxyListener::bind(Arc::clone(&context), &server).await?;
    let udp = Arc::new(ProxySocket::bind(context, &server).await?);
    println!("READY {}", listener.local_addr()?);

    tokio::spawn(async move {
        loop {
            let accepted = listener.accept().await;
            let Ok((mut inbound, _)) = accepted else {
                break;
            };
            tokio::spawn(async move {
                let result = async {
                    let destination = inbound.handshake().await?;
                    let mut outbound = connect_destination(&destination).await?;
                    copy_bidirectional(&mut inbound, &mut outbound).await?;
                    Ok::<(), std::io::Error>(())
                }
                .await;
                if let Err(error) = result {
                    eprintln!("TCP connection failed: {error}");
                }
            });
        }
    });

    let mut buffer = vec![0_u8; 65_536];
    loop {
        let (length, peer, destination, _) = udp.recv_from(&mut buffer).await?;
        let payload = buffer[..length].to_vec();
        let udp = Arc::clone(&udp);
        tokio::spawn(async move {
            let result = relay_udp(&udp, peer, &destination, &payload).await;
            if let Err(error) = result {
                eprintln!("UDP relay failed: {error}");
            }
        });
    }
}

async fn relay_udp(
    server: &ProxySocket<shadowsocks::net::UdpSocket>,
    peer: SocketAddr,
    destination: &Address,
    payload: &[u8],
) -> std::io::Result<()> {
    let destination = resolve_udp_destination(destination).await?;
    let bind = if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let outbound = UdpSocket::bind(bind).await?;
    outbound.send_to(payload, destination).await?;
    let mut response = vec![0_u8; 65_536];
    let (length, source) =
        tokio::time::timeout(Duration::from_secs(5), outbound.recv_from(&mut response))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    server
        .send_to(peer, &Address::SocketAddress(source), &response[..length])
        .await
        .map_err(std::io::Error::from)?;
    Ok(())
}

async fn resolve_udp_destination(destination: &Address) -> std::io::Result<SocketAddr> {
    match destination {
        Address::SocketAddress(address) => Ok(*address),
        Address::DomainNameAddress(domain, port) => {
            tokio::net::lookup_host((domain.as_str(), *port))
                .await?
                .find(SocketAddr::is_ipv4)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "no IPv4 UDP authority destination resolved",
                    )
                })
        }
    }
}

async fn connect_destination(destination: &Address) -> std::io::Result<TcpStream> {
    match destination {
        Address::SocketAddress(address) => TcpStream::connect(address).await,
        Address::DomainNameAddress(domain, port) => {
            TcpStream::connect((domain.as_str(), *port)).await
        }
    }
}

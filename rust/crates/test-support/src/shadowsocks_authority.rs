use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use shadowsocks::ProxyListener;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::udprelay::ProxySocket;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
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
                    if let Address::DomainNameAddress(domain, 0) = &destination {
                        let version = match domain.as_str() {
                            "sp.udp-over-tcp.arpa" => Some(1),
                            "sp.v2.udp-over-tcp.arpa" => Some(2),
                            _ => None,
                        };
                        if let Some(version) = version {
                            println!("UOT {version}");
                            serve_uot(&mut inbound, version).await?;
                            return Ok::<(), std::io::Error>(());
                        }
                    }
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

async fn serve_uot<S>(stream: &mut S, version: u8) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if version == 2 {
        let is_connect = stream.read_u8().await?;
        if is_connect != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "test authority only accepts non-connect UoT v2",
            ));
        }
        Address::read_from(stream)
            .await
            .map_err(std::io::Error::other)?;
    }
    let outbound = UdpSocket::bind("0.0.0.0:0").await?;
    loop {
        let destination = read_uot_address(stream).await?;
        let length = stream.read_u16().await? as usize;
        let mut payload = vec![0_u8; length];
        stream.read_exact(&mut payload).await?;
        let destination = resolve_uot_destination(&destination).await?;
        outbound.send_to(&payload, destination).await?;
        let mut response = vec![0_u8; 65_536];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(5), outbound.recv_from(&mut response))
                .await
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
        write_uot_address(stream, source).await?;
        stream
            .write_u16(u16::try_from(length).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "UoT response too large")
            })?)
            .await?;
        stream.write_all(&response[..length]).await?;
        stream.flush().await?;
    }
}

async fn read_uot_address<S>(stream: &mut S) -> std::io::Result<UotDestination>
where
    S: AsyncRead + Unpin,
{
    let host = match stream.read_u8().await? {
        0 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            UotHost::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        1 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            UotHost::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        2 => {
            let length = stream.read_u8().await? as usize;
            let mut domain = vec![0_u8; length];
            stream.read_exact(&mut domain).await?;
            UotHost::Domain(String::from_utf8(domain).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid UoT domain")
            })?)
        }
        kind => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid UoT address type {kind}"),
            ));
        }
    };
    let port = stream.read_u16().await?;
    Ok(UotDestination { host, port })
}

async fn write_uot_address<S>(stream: &mut S, address: SocketAddr) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    match address.ip() {
        IpAddr::V4(address) => {
            stream.write_u8(0).await?;
            stream.write_all(&address.octets()).await?;
        }
        IpAddr::V6(address) => {
            stream.write_u8(1).await?;
            stream.write_all(&address.octets()).await?;
        }
    }
    stream.write_u16(address.port()).await
}

async fn resolve_uot_destination(destination: &UotDestination) -> std::io::Result<SocketAddr> {
    match &destination.host {
        UotHost::Ip(address) => Ok(SocketAddr::new(*address, destination.port)),
        UotHost::Domain(domain) => tokio::net::lookup_host((domain.as_str(), destination.port))
            .await?
            .find(SocketAddr::is_ipv4)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "no IPv4 UoT authority destination resolved",
                )
            }),
    }
}

struct UotDestination {
    host: UotHost,
    port: u16,
}

enum UotHost {
    Ip(IpAddr),
    Domain(String),
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

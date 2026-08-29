use std::error::Error;
use std::net::SocketAddr;
use std::str::FromStr;

use shadowsocks::ProxyListener;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

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
    let listener = ProxyListener::bind(Context::new_shared(ServerType::Server), &server).await?;
    println!("READY {}", listener.local_addr()?);

    loop {
        let (mut inbound, _) = listener.accept().await?;
        tokio::spawn(async move {
            let result = async {
                let destination = inbound.handshake().await?;
                let mut outbound = connect_destination(&destination).await?;
                copy_bidirectional(&mut inbound, &mut outbound).await?;
                Ok::<(), std::io::Error>(())
            }
            .await;
            if let Err(error) = result {
                eprintln!("connection failed: {error}");
            }
        });
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

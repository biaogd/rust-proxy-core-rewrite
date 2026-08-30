use std::error::Error;
use std::net::{IpAddr, SocketAddr};

use rewrite_model::{Destination, Host};
use rewrite_outbound::{DirectTcpOptions, connect_shadowsocks_with_options};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let server = arguments
        .next()
        .ok_or("missing server address")?
        .parse::<SocketAddr>()?;
    let password = arguments.next().ok_or("missing password")?;
    let cipher = arguments.next().ok_or("missing cipher")?;
    let target_host = arguments.next().ok_or("missing target host")?;
    let target_port = arguments
        .next()
        .ok_or("missing target port")?
        .parse::<u16>()?;
    let payload = arguments.next().ok_or("missing payload")?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }

    let server = Destination {
        host: Host::Ip(server.ip()),
        port: server.port(),
    };
    let target = Destination {
        host: if let Ok(address) = target_host.parse::<IpAddr>() {
            Host::Ip(address)
        } else {
            Host::Domain(target_host)
        },
        port: target_port,
    };
    let mut stream = connect_shadowsocks_with_options(
        &server,
        &target,
        false,
        &password,
        &cipher,
        DirectTcpOptions::default(),
    )
    .await?;
    stream.write_all(payload.as_bytes()).await?;
    let mut response = vec![0_u8; payload.len()];
    stream.read_exact(&mut response).await?;
    if response != payload.as_bytes() {
        return Err("payload mismatch".into());
    }
    Ok(())
}

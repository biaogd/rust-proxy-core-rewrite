use std::error::Error;
use std::net::{IpAddr, SocketAddr};

use rewrite_model::{Destination, Host};
use rewrite_outbound::{DirectTcpOptions, associate_shadowsocks_udp_with_options};

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
    let reuse_payload = arguments.next();
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
    let association = associate_shadowsocks_udp_with_options(
        &server,
        false,
        &password,
        &cipher,
        DirectTcpOptions::default(),
    )
    .await?;
    exchange(&association, &target, payload.as_bytes()).await?;
    if let Some(reuse_payload) = reuse_payload {
        exchange(&association, &target, reuse_payload.as_bytes()).await?;
    }
    Ok(())
}

async fn exchange(
    association: &rewrite_outbound::ShadowsocksUdpAssociation,
    target: &Destination,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    association.send(target, payload).await?;
    let (_, response) = association.recv().await?;
    if response != payload {
        return Err("payload mismatch".into());
    }
    Ok(())
}

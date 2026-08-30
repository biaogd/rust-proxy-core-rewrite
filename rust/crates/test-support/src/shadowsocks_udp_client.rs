use std::error::Error;
use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
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
    let payload = decode_payload(&arguments.next().ok_or("missing payload")?)?;
    let follow_up = arguments.next();
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let (reuse_payload, verify_dns) = match follow_up.as_deref() {
        None => (None, false),
        Some("verify-dns") => (None, true),
        Some(value) => (Some(decode_payload(value)?), false),
    };

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
    exchange(&association, &target, &payload, verify_dns).await?;
    if let Some(reuse_payload) = reuse_payload {
        exchange(&association, &target, &reuse_payload, false).await?;
    }
    Ok(())
}

fn decode_payload(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if let Some(encoded) = value.strip_prefix("b64:") {
        return Ok(STANDARD.decode(encoded)?);
    }
    Ok(value.as_bytes().to_vec())
}

async fn exchange(
    association: &rewrite_outbound::ShadowsocksUdpAssociation,
    target: &Destination,
    payload: &[u8],
    verify_dns: bool,
) -> Result<(), Box<dyn Error>> {
    association.send(target, payload).await?;
    let (_, response) = association.recv().await?;
    if verify_dns {
        if response.len() < 4
            || response[0..2] != payload[0..2]
            || response[3] & 0x0F != 0
        {
            return Err("invalid dns response".into());
        }
        return Ok(());
    }
    if response != payload {
        return Err("payload mismatch".into());
    }
    Ok(())
}

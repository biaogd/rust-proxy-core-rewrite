use std::error::Error;
use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rewrite_model::{Destination, Host};
use rewrite_outbound::{DirectTcpOptions, associate_shadowsocks_uot_with_options};
use tokio::time::{Duration, timeout};

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
    let version = arguments
        .next()
        .unwrap_or_else(|| "1".to_owned())
        .parse::<u8>()?;
    let verify_dns = match arguments.next().as_deref() {
        None => false,
        Some("verify-dns") => true,
        Some(other) => return Err(format!("unexpected argument: {other}").into()),
    };
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
    let mut association = associate_shadowsocks_uot_with_options(
        &server,
        false,
        &password,
        &cipher,
        version,
        DirectTcpOptions::default(),
    )
    .await?;
    association.send(&target, &payload).await?;
    let (_, response) = timeout(Duration::from_secs(5), association.recv()).await??;
    if verify_dns {
        if response.len() < 4 || response[0..2] != payload[0..2] || response[3] & 0x0F != 0 {
            return Err("invalid dns response".into());
        }
        return Ok(());
    }
    if response != payload {
        return Err("payload mismatch".into());
    }
    Ok(())
}

fn decode_payload(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if let Some(encoded) = value.strip_prefix("b64:") {
        return Ok(STANDARD.decode(encoded)?);
    }
    Ok(value.as_bytes().to_vec())
}

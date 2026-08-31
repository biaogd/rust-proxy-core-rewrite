use std::error::Error;
use std::net::{IpAddr, SocketAddr};

use rewrite_model::{Destination, Host, ShadowsocksPluginConfig};
use rewrite_outbound::{
    DirectTcpOptions, ShadowsocksTcpOptions, connect_shadowsocks_with_plugin_options,
};
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
    let plugin_mode = arguments.next();
    let plugin_host = arguments.next();
    let plugin_password = arguments.next();
    let plugin_version = arguments.next();
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
    let plugin = match plugin_mode.as_deref() {
        Some("http") => Some(ShadowsocksPluginConfig::SimpleObfsHttp {
            host: plugin_host.unwrap_or_else(|| "bing.com".to_owned()),
        }),
        Some("tls") => Some(ShadowsocksPluginConfig::SimpleObfsTls {
            host: plugin_host.unwrap_or_else(|| "bing.com".to_owned()),
        }),
        Some("shadow-tls") => Some(ShadowsocksPluginConfig::ShadowTls {
            host: plugin_host.ok_or("missing shadow-tls host")?,
            password: plugin_password.ok_or("missing shadow-tls password")?,
            version: match plugin_version.as_deref() {
                Some(value) => value
                    .parse()
                    .map_err(|error: std::num::ParseIntError| -> Box<dyn Error> { error.into() })?,
                None => 3,
            },
            skip_certificate_verification: true,
            verification_name: None,
            certificate_fingerprint: None,
            certificate: None,
            private_key: None,
            alpn: Vec::new(),
        }),
        None => None,
        Some(value) => return Err(format!("unsupported plugin mode: {value}").into()),
    };
    let mut stream = connect_shadowsocks_with_plugin_options(
        &server,
        &target,
        false,
        &password,
        &cipher,
        ShadowsocksTcpOptions {
            plugin: plugin.as_ref(),
            socket: DirectTcpOptions::default(),
            ..ShadowsocksTcpOptions::default()
        },
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

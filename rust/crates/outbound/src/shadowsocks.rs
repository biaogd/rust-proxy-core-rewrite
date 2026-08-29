use std::net::SocketAddr;
use std::str::FromStr;

use rewrite_model::{Destination, Host};
use shadowsocks::ProxyClientStream;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use thiserror::Error;

use crate::{BoxedOutboundStream, DirectError, DirectTcpOptions, connect_with_options};

#[derive(Debug, Error)]
pub enum ShadowsocksProxyError {
    #[error(transparent)]
    Direct(#[from] DirectError),
    #[error("unsupported Shadowsocks cipher: {0}")]
    Cipher(String),
    #[error("invalid Shadowsocks server configuration: {0}")]
    Configuration(String),
}

/// Opens the upstream TCP socket with the rewrite's platform policy, then
/// delegates SIP004 encryption and framing to the official Shadowsocks core.
///
/// # Errors
///
/// Returns [`ShadowsocksProxyError`] for cipher/configuration errors or when
/// the upstream TCP connection cannot be established.
pub async fn connect_shadowsocks_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    password: &str,
    cipher: &str,
    options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, ShadowsocksProxyError> {
    let method = CipherKind::from_str(cipher)
        .map_err(|_| ShadowsocksProxyError::Cipher(cipher.to_owned()))?;
    let server_config = ServerConfig::new(destination_address(server), password, method)
        .map_err(|error| ShadowsocksProxyError::Configuration(error.to_string()))?;
    let stream = connect_with_options(server, allow_ipv6, options).await?;
    let context = Context::new_shared(ServerType::Local);
    let stream = ProxyClientStream::from_stream(
        context,
        stream,
        &server_config,
        destination_address(destination),
    );
    Ok(Box::new(stream))
}

fn destination_address(destination: &Destination) -> Address {
    match &destination.host {
        Host::Ip(address) => Address::from(SocketAddr::new(*address, destination.port)),
        Host::Domain(domain) => Address::from((domain.clone(), destination.port)),
    }
}

use std::sync::Arc;

use rewrite_model::{Destination, Host};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;
use thiserror::Error;
use tokio::io::AsyncWriteExt;

use crate::BoxedOutboundStream;
use crate::direct::{DirectError, DirectTcpOptions, connect_with_options};

#[derive(Debug, Error)]
pub enum ShadowsocksError {
    #[error(transparent)]
    Direct(#[from] DirectError),
    #[error("shadowsocks configuration is invalid: {0}")]
    Configuration(String),
    #[error("shadowsocks cipher is invalid: {0}")]
    Cipher(String),
    #[error("shadowsocks tunnel failed: {0}")]
    Tunnel(std::io::Error),
}

#[allow(clippy::missing_errors_doc)]
pub async fn connect_shadowsocks_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    cipher: &str,
    password: &str,
    _clock: Option<Arc<rewrite_services::AdjustedClock>>,
    options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, ShadowsocksError> {
    let method = parse_cipher_kind(cipher)?;
    let server_config = server_config(server, password, method)?;
    let tcp = connect_with_options(server, allow_ipv6, options).await?;
    let context = Context::new_shared(ServerType::Local);
    let target = destination_address(destination);
    let mut stream = ProxyClientStream::from_stream(context, tcp, &server_config, target);
    stream.write(&[]).await.map_err(ShadowsocksError::Tunnel)?;
    Ok(Box::new(stream))
}

fn server_config(
    server: &Destination,
    password: &str,
    method: CipherKind,
) -> Result<ServerConfig, ShadowsocksError> {
    match &server.host {
        Host::Domain(domain) => ServerConfig::new((domain.as_str(), server.port), password, method),
        Host::Ip(address) => ServerConfig::new(
            std::net::SocketAddr::new(*address, server.port),
            password,
            method,
        ),
    }
    .map_err(|error| ShadowsocksError::Configuration(error.to_string()))
}

fn parse_cipher_kind(cipher: &str) -> Result<CipherKind, ShadowsocksError> {
    cipher
        .parse::<CipherKind>()
        .map_err(|_| ShadowsocksError::Cipher(cipher.to_owned()))
}

fn destination_address(destination: &Destination) -> Address {
    match &destination.host {
        Host::Domain(domain) => Address::DomainNameAddress(domain.clone(), destination.port),
        Host::Ip(address) => {
            Address::SocketAddress(std::net::SocketAddr::new(*address, destination.port))
        }
    }
}

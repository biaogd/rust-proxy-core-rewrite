use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use rewrite_model::{Destination, Host};
use shadowsocks::ProxyClientStream;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::net::UdpSocket as ShadowUdpSocket;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::udprelay::ProxySocket;
use shadowsocks::relay::udprelay::proxy_socket::UdpSocketType;
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
    #[error("Shadowsocks UDP I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Shadowsocks UDP protocol failed: {0}")]
    Protocol(String),
}

pub struct ShadowsocksUdpAssociation {
    socket: ProxySocket<ShadowUdpSocket>,
}

impl ShadowsocksUdpAssociation {
    /// Sends one SIP004 UDP payload through the configured server.
    ///
    /// # Errors
    ///
    /// Returns a protocol or socket error when the datagram cannot be encoded
    /// or sent.
    pub async fn send(
        &self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), ShadowsocksProxyError> {
        self.socket
            .send(&destination_address(destination), payload)
            .await
            .map(|_| ())
            .map_err(|error| ShadowsocksProxyError::Protocol(error.to_string()))
    }

    /// Receives and decodes one SIP004 UDP payload from the server.
    ///
    /// # Errors
    ///
    /// Returns a protocol or socket error when the datagram cannot be received
    /// or authenticated.
    pub async fn recv(&self) -> Result<(Destination, Vec<u8>), ShadowsocksProxyError> {
        let mut buffer = vec![0_u8; 65_536];
        let (length, address, _) = self
            .socket
            .recv(&mut buffer)
            .await
            .map_err(|error| ShadowsocksProxyError::Protocol(error.to_string()))?;
        buffer.truncate(length);
        Ok((address_destination(address), buffer))
    }
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

/// Opens a SIP004 UDP association while preserving the rewrite's platform
/// interface and routing-mark policy.
///
/// # Errors
///
/// Returns [`ShadowsocksProxyError`] for cipher/configuration errors, name
/// resolution failures, disabled IPv6, or UDP socket/protocol failures.
pub async fn associate_shadowsocks_udp_with_options(
    server: &Destination,
    allow_ipv6: bool,
    password: &str,
    cipher: &str,
    options: DirectTcpOptions<'_>,
) -> Result<ShadowsocksUdpAssociation, ShadowsocksProxyError> {
    let method = CipherKind::from_str(cipher)
        .map_err(|_| ShadowsocksProxyError::Cipher(cipher.to_owned()))?;
    let server_config = ServerConfig::new(destination_address(server), password, method)
        .map_err(|error| ShadowsocksProxyError::Configuration(error.to_string()))?;
    let server_address = resolve_server(server, allow_ipv6).await?;
    let bind_address = if server_address.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket =
        rewrite_platform::bind_outbound_udp(bind_address, options.interface, options.routing_mark)?;
    let socket = tokio::net::UdpSocket::from_std(socket)?;
    socket.connect(server_address).await?;
    let socket = ProxySocket::from_socket(
        UdpSocketType::Client,
        Context::new_shared(ServerType::Local),
        &server_config,
        ShadowUdpSocket::from(socket),
    );
    Ok(ShadowsocksUdpAssociation { socket })
}

async fn resolve_server(
    server: &Destination,
    allow_ipv6: bool,
) -> Result<SocketAddr, ShadowsocksProxyError> {
    match &server.host {
        Host::Ip(address) => {
            if address.is_ipv6() && !allow_ipv6 {
                return Err(ShadowsocksProxyError::Direct(DirectError::Ipv6Disabled));
            }
            Ok(SocketAddr::new(*address, server.port))
        }
        Host::Domain(domain) => tokio::net::lookup_host((domain.as_str(), server.port))
            .await?
            .find(|address| allow_ipv6 || address.is_ipv4())
            .ok_or_else(|| {
                ShadowsocksProxyError::Io(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "no permitted Shadowsocks UDP server address resolved",
                ))
            }),
    }
}

fn destination_address(destination: &Destination) -> Address {
    match &destination.host {
        Host::Ip(address) => Address::from(SocketAddr::new(*address, destination.port)),
        Host::Domain(domain) => Address::from((domain.clone(), destination.port)),
    }
}

fn address_destination(address: Address) -> Destination {
    match address {
        Address::SocketAddress(address) => Destination {
            host: Host::Ip(address.ip()),
            port: address.port(),
        },
        Address::DomainNameAddress(domain, port) => Destination {
            host: Host::Domain(domain),
            port,
        },
    }
}

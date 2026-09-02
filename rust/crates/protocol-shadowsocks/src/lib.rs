//! Transport-independent Shadowsocks protocol boundary.
//!
//! The maintained `shadowsocks` crate owns SIP004/SIP022 crypto and framing.
//! This crate adapts those primitives to the rewrite's shared destination and
//! stream types, and owns Mihomo's sing-style UDP-over-TCP envelope.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr as _;

use bytes::BufMut as _;
use rewrite_io::BoxedStream;
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
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Debug, Error)]
pub enum ShadowsocksProtocolError {
    #[error("unsupported Shadowsocks cipher: {0}")]
    Cipher(String),
    #[error("invalid Shadowsocks server configuration: {0}")]
    Configuration(String),
    #[error("Shadowsocks I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Shadowsocks protocol failed: {0}")]
    Protocol(String),
}

/// Parses a Shadowsocks cipher at the shared client/server boundary.
///
/// # Errors
///
/// Returns an error for a cipher unsupported by the maintained core.
pub fn cipher_kind(cipher: &str) -> Result<CipherKind, ShadowsocksProtocolError> {
    CipherKind::from_str(cipher).map_err(|_| ShadowsocksProtocolError::Cipher(cipher.to_owned()))
}

/// Builds a client server configuration shared by TCP and UDP adapters.
///
/// # Errors
///
/// Returns an error for invalid address, password, cipher or key material.
pub fn client_server_config(
    server: &Destination,
    password: &str,
    cipher: &str,
) -> Result<ServerConfig, ShadowsocksProtocolError> {
    ServerConfig::new(destination_address(server), password, cipher_kind(cipher)?)
        .map_err(|error| ShadowsocksProtocolError::Configuration(error.to_string()))
}

/// Wraps an established carrier in a Shadowsocks TCP client session.
///
/// # Errors
///
/// Returns an error when server configuration is invalid.
pub fn connect_tcp_on_stream(
    stream: BoxedStream,
    server: &Destination,
    destination: &Destination,
    password: &str,
    cipher: &str,
) -> Result<BoxedStream, ShadowsocksProtocolError> {
    let server = client_server_config(server, password, cipher)?;
    let context = Context::new_shared(ServerType::Local);
    Ok(Box::new(ProxyClientStream::from_stream(
        context,
        stream,
        &server,
        destination_address(destination),
    )))
}

pub struct ShadowsocksUdpAssociation {
    socket: ProxySocket<ShadowUdpSocket>,
}

impl ShadowsocksUdpAssociation {
    /// Wraps a connected UDP socket in the SIP004/SIP022 packet codec.
    ///
    /// # Errors
    ///
    /// Returns an error when server configuration is invalid.
    pub fn from_connected_socket(
        socket: tokio::net::UdpSocket,
        server: &Destination,
        password: &str,
        cipher: &str,
    ) -> Result<Self, ShadowsocksProtocolError> {
        let server = client_server_config(server, password, cipher)?;
        let socket = ProxySocket::from_socket(
            UdpSocketType::Client,
            Context::new_shared(ServerType::Local),
            &server,
            ShadowUdpSocket::from(socket),
        );
        Ok(Self { socket })
    }

    /// Sends one encrypted Shadowsocks datagram.
    ///
    /// # Errors
    ///
    /// Returns an authentication, framing or socket error.
    pub async fn send(
        &self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), ShadowsocksProtocolError> {
        self.socket
            .send(&destination_address(destination), payload)
            .await
            .map(|_| ())
            .map_err(|error| ShadowsocksProtocolError::Protocol(error.to_string()))
    }

    /// Receives one authenticated Shadowsocks datagram.
    ///
    /// # Errors
    ///
    /// Returns an authentication, framing or socket error.
    pub async fn recv(&self) -> Result<(Destination, Vec<u8>), ShadowsocksProtocolError> {
        let mut buffer = vec![0_u8; 65_536];
        let (length, address, _) = self
            .socket
            .recv(&mut buffer)
            .await
            .map_err(|error| ShadowsocksProtocolError::Protocol(error.to_string()))?;
        buffer.truncate(length);
        Ok((address_destination(address), buffer))
    }
}

pub struct ShadowsocksUotAssociation {
    stream: BoxedStream,
    version: u8,
    request_written: bool,
}

impl ShadowsocksUotAssociation {
    /// Creates a `UoT` codec over an already encrypted Shadowsocks stream.
    ///
    /// # Errors
    ///
    /// Returns an error unless `version` is one or two.
    pub fn new(stream: BoxedStream, version: u8) -> Result<Self, ShadowsocksProtocolError> {
        uot_destination(version)?;
        Ok(Self {
            stream,
            version,
            request_written: false,
        })
    }

    /// Sends one sing-style UDP-over-TCP frame.
    ///
    /// # Errors
    ///
    /// Returns an address, size, framing or I/O error.
    pub async fn send(
        &mut self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), ShadowsocksProtocolError> {
        let length = u16::try_from(payload.len()).map_err(|_| {
            ShadowsocksProtocolError::Protocol("UoT payload exceeds 65535 bytes".to_owned())
        })?;
        let mut frame = Vec::with_capacity(payload.len() + 32);
        if self.version == 2 && !self.request_written {
            frame.put_u8(0);
            destination_address(destination).write_to_buf(&mut frame);
            self.request_written = true;
        }
        write_uot_address(&mut frame, destination)?;
        frame.put_u16(length);
        frame.extend_from_slice(payload);
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    /// Receives one sing-style UDP-over-TCP frame.
    ///
    /// # Errors
    ///
    /// Returns an address, framing or I/O error.
    pub async fn recv(&mut self) -> Result<(Destination, Vec<u8>), ShadowsocksProtocolError> {
        let destination = read_uot_address(&mut self.stream).await?;
        let length = self.stream.read_u16().await? as usize;
        let mut payload = vec![0_u8; length];
        self.stream.read_exact(&mut payload).await?;
        Ok((destination, payload))
    }
}

/// Returns the synthetic destination that starts a `UoT` session.
///
/// # Errors
///
/// Returns an error unless `version` is one or two.
pub fn uot_destination(version: u8) -> Result<Destination, ShadowsocksProtocolError> {
    let domain = match version {
        1 => "sp.udp-over-tcp.arpa",
        2 => "sp.v2.udp-over-tcp.arpa",
        _ => {
            return Err(ShadowsocksProtocolError::Configuration(format!(
                "unsupported UoT version {version}"
            )));
        }
    };
    Ok(Destination {
        host: Host::Domain(domain.to_owned()),
        port: 0,
    })
}

/// Splits a Mihomo inbound EIH password into server and user keys.
#[must_use]
pub fn split_inbound_password(password: &str) -> (String, Vec<String>) {
    let mut parts = password.split(':').map(str::to_owned).collect::<Vec<_>>();
    if parts.len() <= 1 {
        return (password.to_owned(), Vec::new());
    }
    let server_password = parts.remove(0);
    (server_password, parts)
}

/// Converts a Mihomo destination to the maintained Shadowsocks address type.
#[must_use]
pub fn destination_address(destination: &Destination) -> Address {
    match &destination.host {
        Host::Ip(address) => Address::from(SocketAddr::new(*address, destination.port)),
        Host::Domain(domain) => Address::from((domain.clone(), destination.port)),
    }
}

/// Converts the maintained Shadowsocks address type to a Mihomo destination.
#[must_use]
pub fn address_destination(address: Address) -> Destination {
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

fn write_uot_address(
    buffer: &mut Vec<u8>,
    destination: &Destination,
) -> Result<(), ShadowsocksProtocolError> {
    match &destination.host {
        Host::Ip(IpAddr::V4(address)) => {
            buffer.put_u8(0);
            buffer.extend_from_slice(&address.octets());
        }
        Host::Ip(IpAddr::V6(address)) => {
            buffer.put_u8(1);
            buffer.extend_from_slice(&address.octets());
        }
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                ShadowsocksProtocolError::Protocol("UoT domain exceeds 255 bytes".to_owned())
            })?;
            buffer.put_u8(2);
            buffer.put_u8(length);
            buffer.extend_from_slice(domain.as_bytes());
        }
    }
    buffer.put_u16(destination.port);
    Ok(())
}

async fn read_uot_address(
    stream: &mut BoxedStream,
) -> Result<Destination, ShadowsocksProtocolError> {
    let host = match stream.read_u8().await? {
        0 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        1 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            Host::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        2 => {
            let length = stream.read_u8().await? as usize;
            let mut domain = vec![0_u8; length];
            stream.read_exact(&mut domain).await?;
            Host::Domain(String::from_utf8(domain).map_err(|_| {
                ShadowsocksProtocolError::Protocol("UoT domain is not UTF-8".to_owned())
            })?)
        }
        kind => {
            return Err(ShadowsocksProtocolError::Protocol(format!(
                "unsupported UoT address type {kind}"
            )));
        }
    };
    let port = stream.read_u16().await?;
    Ok(Destination { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_inbound_eih_passwords() {
        assert_eq!(
            split_inbound_password("server:user-a:user-b"),
            (
                "server".to_owned(),
                vec!["user-a".to_owned(), "user-b".to_owned()]
            )
        );
        assert_eq!(
            split_inbound_password("single"),
            ("single".to_owned(), Vec::new())
        );
    }

    #[test]
    fn shadowsocks_addresses_round_trip() {
        for destination in [
            Destination {
                host: Host::Ip("192.0.2.30".parse().unwrap()),
                port: 53,
            },
            Destination {
                host: Host::Domain("example.test".to_owned()),
                port: 443,
            },
        ] {
            assert_eq!(
                address_destination(destination_address(&destination)),
                destination
            );
        }
    }
}

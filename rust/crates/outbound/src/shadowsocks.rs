use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use bytes::BufMut;
use rewrite_model::{Destination, Host, ShadowsocksPluginConfig};
use shadowsocks::ProxyClientStream;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::net::UdpSocket as ShadowUdpSocket;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::udprelay::ProxySocket;
use shadowsocks::relay::udprelay::proxy_socket::UdpSocketType;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    BoxedOutboundStream, DirectError, DirectTcpOptions, HttpObfsClient, TlsObfsClient,
    connect_with_options,
};

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
    #[error("Shadowsocks plugin failed: {0}")]
    Plugin(String),
}

#[derive(Default)]
pub struct ShadowsocksTcpOptions<'a> {
    pub socket: DirectTcpOptions<'a>,
    pub plugin: Option<&'a ShadowsocksPluginConfig>,
    pub clock: Option<Arc<rewrite_services::AdjustedClock>>,
    pub custom_roots: &'a [String],
    pub ech_config: Option<&'a [u8]>,
}

pub struct ShadowsocksUdpAssociation {
    socket: ProxySocket<ShadowUdpSocket>,
}

pub struct ShadowsocksUotAssociation {
    stream: BoxedOutboundStream,
    version: u8,
    request_written: bool,
}

impl ShadowsocksUotAssociation {
    /// Sends one UDP-over-TCP frame over the encrypted Shadowsocks stream.
    ///
    /// # Errors
    ///
    /// Returns a protocol or I/O error when the destination or payload cannot
    /// be encoded, or when the encrypted stream fails.
    pub async fn send(
        &mut self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), ShadowsocksProxyError> {
        let length = u16::try_from(payload.len()).map_err(|_| {
            ShadowsocksProxyError::Protocol("UoT payload exceeds 65535 bytes".to_owned())
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

    /// Receives and decodes one UDP-over-TCP response frame.
    ///
    /// # Errors
    ///
    /// Returns a protocol or I/O error for malformed or truncated frames.
    pub async fn recv(&mut self) -> Result<(Destination, Vec<u8>), ShadowsocksProxyError> {
        let destination = read_uot_address(&mut self.stream).await?;
        let length = self.stream.read_u16().await? as usize;
        let mut payload = vec![0_u8; length];
        self.stream.read_exact(&mut payload).await?;
        Ok((destination, payload))
    }
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
    connect_shadowsocks_with_plugin_options(
        server,
        destination,
        allow_ipv6,
        password,
        cipher,
        ShadowsocksTcpOptions {
            socket: options,
            ..ShadowsocksTcpOptions::default()
        },
    )
    .await
}

/// Opens a Shadowsocks TCP stream with an optional embedded transport plugin.
///
/// # Errors
///
/// Returns [`ShadowsocksProxyError`] when the cipher or plugin configuration
/// is invalid, the upstream cannot be dialed, or the encrypted stream cannot
/// be initialized.
pub async fn connect_shadowsocks_with_plugin_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    password: &str,
    cipher: &str,
    options: ShadowsocksTcpOptions<'_>,
) -> Result<BoxedOutboundStream, ShadowsocksProxyError> {
    let method = CipherKind::from_str(cipher)
        .map_err(|_| ShadowsocksProxyError::Cipher(cipher.to_owned()))?;
    let server_config = ServerConfig::new(destination_address(server), password, method)
        .map_err(|error| ShadowsocksProxyError::Configuration(error.to_string()))?;
    let stream = connect_with_options(server, allow_ipv6, options.socket).await?;
    let stream: BoxedOutboundStream = match options.plugin {
        Some(ShadowsocksPluginConfig::SimpleObfsHttp { host }) => {
            Box::new(HttpObfsClient::new(stream, host.clone(), server.port))
        }
        Some(ShadowsocksPluginConfig::SimpleObfsTls { host }) => {
            Box::new(TlsObfsClient::new(stream, host.clone()))
        }
        Some(ShadowsocksPluginConfig::V2rayWebSocket {
            host,
            path,
            headers,
            tls,
            skip_certificate_verification,
            verification_name,
            certificate_fingerprint,
            certificate,
            private_key,
            mux,
            http_upgrade,
            http_upgrade_fast_open,
            ..
        }) => {
            let stream = if *tls {
                let server_name = headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("host"))
                    .map_or(host.as_str(), |(_, value)| value.as_str());
                crate::wrap_client_tls_with_options(
                    Box::new(stream),
                    crate::HttpProxyTls {
                        server_name,
                        verification_name: verification_name.as_deref(),
                        skip_certificate_verification: *skip_certificate_verification,
                        fingerprint: certificate_fingerprint.as_deref(),
                        certificate: certificate.as_deref(),
                        private_key: private_key.as_deref(),
                        custom_roots: options.custom_roots,
                        ech_config: options.ech_config,
                        alpn_protocols: &[b"http/1.1"],
                        tls12_only: false,
                        tls13_only: false,
                    },
                    options.clock,
                )
                .await
                .map_err(|error| ShadowsocksProxyError::Plugin(error.to_string()))?
            } else {
                Box::new(stream) as BoxedOutboundStream
            };
            let stream = if *http_upgrade {
                crate::connect_v2ray_http_upgrade(
                    stream,
                    host,
                    path,
                    headers,
                    *http_upgrade_fast_open,
                )
                .await
                .map_err(|error| ShadowsocksProxyError::Plugin(error.to_string()))?
            } else {
                crate::connect_v2ray_websocket(stream, host, server.port, path, headers)
                    .await
                    .map_err(|error| ShadowsocksProxyError::Plugin(error.to_string()))?
            };
            if *mux {
                Box::new(
                    crate::V2rayMux::new(
                        stream,
                        &crate::V2rayMuxOptions {
                            id: [0, 0],
                            host: "127.0.0.1".to_owned(),
                            port: 0,
                            network: crate::V2rayMuxNetwork::Tcp,
                        },
                    )
                    .map_err(|error| ShadowsocksProxyError::Plugin(error.to_string()))?,
                )
            } else {
                stream
            }
        }
        Some(ShadowsocksPluginConfig::ShadowTls {
            host,
            password,
            version,
            skip_certificate_verification,
            verification_name,
            certificate_fingerprint,
            certificate,
            private_key,
            alpn,
        }) => crate::connect_shadow_tls(
            Box::new(stream),
            crate::ShadowTlsConnectOptions {
                host,
                password,
                version: *version,
                skip_certificate_verification: *skip_certificate_verification,
                verification_name: verification_name.as_deref(),
                certificate_fingerprint: certificate_fingerprint.as_deref(),
                certificate: certificate.as_deref(),
                private_key: private_key.as_deref(),
                custom_roots: options.custom_roots,
                alpn,
            },
            options.clock,
        )
        .await
        .map_err(|error| ShadowsocksProxyError::Plugin(error.to_string()))?,
        None => Box::new(stream),
    };
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

/// Opens the sing-style Shadowsocks UDP-over-TCP v1 or v2 stream.
///
/// The Shadowsocks crate supplies SIP004 encryption. The small `UoT` envelope
/// is kept here because that crate does not expose sing `UoT` framing.
///
/// # Errors
///
/// Returns [`ShadowsocksProxyError`] for invalid versions, cipher/configuration
/// errors, or when the upstream TCP stream cannot be established.
pub async fn associate_shadowsocks_uot_with_options(
    server: &Destination,
    allow_ipv6: bool,
    password: &str,
    cipher: &str,
    version: u8,
    options: DirectTcpOptions<'_>,
) -> Result<ShadowsocksUotAssociation, ShadowsocksProxyError> {
    let magic_domain = match version {
        1 => "sp.udp-over-tcp.arpa",
        2 => "sp.v2.udp-over-tcp.arpa",
        _ => {
            return Err(ShadowsocksProxyError::Configuration(format!(
                "unsupported UoT version {version}"
            )));
        }
    };
    let destination = Destination {
        host: Host::Domain(magic_domain.to_owned()),
        port: 0,
    };
    let stream = connect_shadowsocks_with_options(
        server,
        &destination,
        allow_ipv6,
        password,
        cipher,
        options,
    )
    .await?;
    Ok(ShadowsocksUotAssociation {
        stream,
        version,
        request_written: false,
    })
}

fn write_uot_address(
    buffer: &mut Vec<u8>,
    destination: &Destination,
) -> Result<(), ShadowsocksProxyError> {
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
                ShadowsocksProxyError::Protocol("UoT domain exceeds 255 bytes".to_owned())
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
    stream: &mut BoxedOutboundStream,
) -> Result<Destination, ShadowsocksProxyError> {
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
                ShadowsocksProxyError::Protocol("UoT domain is not UTF-8".to_owned())
            })?)
        }
        kind => {
            return Err(ShadowsocksProxyError::Protocol(format!(
                "unsupported UoT address type {kind}"
            )));
        }
    };
    let port = stream.read_u16().await?;
    Ok(Destination { host, port })
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

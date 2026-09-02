use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use rewrite_model::{Destination, Host, ShadowsocksPluginConfig};
use thiserror::Error;

use crate::{
    BoxedOutboundStream, DirectError, DirectTcpOptions, HttpObfsClient, TlsObfsClient,
    connect_with_options,
};

#[derive(Debug, Error)]
pub enum ShadowsocksProxyError {
    #[error(transparent)]
    Direct(#[from] DirectError),
    #[error(transparent)]
    ProtocolCore(#[from] rewrite_protocol_shadowsocks::ShadowsocksProtocolError),
    #[error("Shadowsocks UDP I/O failed: {0}")]
    Io(#[from] std::io::Error),
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
    pub client_fingerprint: Option<&'a str>,
}

pub use rewrite_protocol_shadowsocks::{ShadowsocksUdpAssociation, ShadowsocksUotAssociation};

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
    let stream = connect_with_options(server, allow_ipv6, options.socket).await?;
    let stream = apply_shadowsocks_plugin(Box::new(stream), server, options).await?;
    rewrite_protocol_shadowsocks::connect_tcp_on_stream(
        stream,
        server,
        destination,
        password,
        cipher,
    )
    .map_err(Into::into)
}

async fn apply_v2ray_websocket_plugin(
    stream: BoxedOutboundStream,
    server: &Destination,
    plugin: &ShadowsocksPluginConfig,
    options: ShadowsocksTcpOptions<'_>,
) -> Result<BoxedOutboundStream, ShadowsocksProxyError> {
    let ShadowsocksPluginConfig::V2rayWebSocket {
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
    } = plugin
    else {
        unreachable!("apply_v2ray_websocket_plugin called with wrong plugin");
    };
    let stream = if *tls {
        let server_name = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map_or(host.as_str(), |(_, value)| value.as_str());
        crate::wrap_client_tls_with_options(
            stream,
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
        stream
    };
    let stream = if *http_upgrade {
        crate::connect_v2ray_http_upgrade(stream, host, path, headers, *http_upgrade_fast_open)
            .await
            .map_err(|error| ShadowsocksProxyError::Plugin(error.to_string()))?
    } else {
        crate::connect_v2ray_websocket(stream, host, server.port, path, headers)
            .await
            .map_err(|error| ShadowsocksProxyError::Plugin(error.to_string()))?
    };
    Ok(if *mux {
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
    })
}

async fn apply_shadowsocks_plugin(
    stream: BoxedOutboundStream,
    server: &Destination,
    options: ShadowsocksTcpOptions<'_>,
) -> Result<BoxedOutboundStream, ShadowsocksProxyError> {
    match options.plugin {
        Some(ShadowsocksPluginConfig::SimpleObfsHttp { host }) => Ok(Box::new(
            HttpObfsClient::new(stream, host.clone(), server.port),
        )),
        Some(ShadowsocksPluginConfig::SimpleObfsTls { host }) => {
            Ok(Box::new(TlsObfsClient::new(stream, host.clone())))
        }
        Some(plugin @ ShadowsocksPluginConfig::V2rayWebSocket { .. }) => {
            apply_v2ray_websocket_plugin(stream, server, plugin, options).await
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
            stream,
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
                client_fingerprint: options.client_fingerprint,
            },
            options.clock,
        )
        .await
        .map_err(|error| ShadowsocksProxyError::Plugin(error.to_string())),
        None => Ok(stream),
    }
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
    rewrite_protocol_shadowsocks::ShadowsocksUdpAssociation::from_connected_socket(
        socket, server, password, cipher,
    )
    .map_err(Into::into)
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
    let destination = rewrite_protocol_shadowsocks::uot_destination(version)?;
    let stream = connect_shadowsocks_with_options(
        server,
        &destination,
        allow_ipv6,
        password,
        cipher,
        options,
    )
    .await?;
    ShadowsocksUotAssociation::new(stream, version).map_err(Into::into)
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

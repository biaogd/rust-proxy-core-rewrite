use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

pub use rewrite_protocol_shadowsocksr::SsrClientState;

use rewrite_model::{Destination, Host};
use thiserror::Error;

use crate::{BoxedOutboundStream, DirectError, DirectTcpOptions, connect_with_options};

pub use rewrite_protocol_shadowsocksr::SsrUdpAssociation;

#[derive(Debug, Error)]
pub enum SsrProxyError {
    #[error(transparent)]
    Direct(#[from] DirectError),
    #[error(transparent)]
    ProtocolCore(#[from] rewrite_protocol_shadowsocksr::ShadowsocksRProtocolError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("ShadowsocksR dial timed out")]
    Timeout,
}

#[allow(clippy::too_many_arguments)]
fn ssr_client_options(
    server_host: &str,
    server_port: u16,
    password: &str,
    cipher: &str,
    protocol: &str,
    protocol_param: &str,
    obfs: &str,
    obfs_param: &str,
) -> rewrite_protocol_shadowsocksr::SsrClientOptions {
    rewrite_protocol_shadowsocksr::SsrClientOptions {
        password: password.to_owned(),
        cipher: cipher.to_owned(),
        protocol: protocol.to_owned(),
        protocol_param: protocol_param.to_owned(),
        obfs: obfs.to_owned(),
        obfs_param: obfs_param.to_owned(),
        // Camouflage Host/SNI must stay the configured server name even when
        // the TCP/UDP dial target was already resolved to an IP via PSN.
        server_host: server_host.to_owned(),
        server_port,
    }
}

/// Opens the upstream TCP socket, then stacks SSR obfs → cipher → protocol.
///
/// `server` is the dial target (often an IP after proxy-server DNS).
/// `server_host` is the configured hostname used for http/tls camouflage.
///
/// # Errors
///
/// Returns when the dial fails or SSR options are unimplemented.
#[allow(clippy::too_many_arguments)]
pub async fn connect_ssr_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    password: &str,
    cipher: &str,
    protocol: &str,
    protocol_param: &str,
    obfs: &str,
    obfs_param: &str,
    server_host: &str,
    options: DirectTcpOptions<'_>,
    client_state: &SsrClientState,
) -> Result<BoxedOutboundStream, SsrProxyError> {
    let dial = async {
        let stream = connect_with_options(server, allow_ipv6, options).await?;
        let options = ssr_client_options(
            server_host,
            server.port,
            password,
            cipher,
            protocol,
            protocol_param,
            obfs,
            obfs_param,
        );
        rewrite_protocol_shadowsocksr::connect_tcp_on_stream_with_state(
            Box::new(stream),
            destination,
            &options,
            client_state,
        )
        .await
        .map_err(SsrProxyError::from)
    };
    // Match Go tunnel DefaultTCPTimeout (5s) covering TCP + StreamConn setup.
    match tokio::time::timeout(Duration::from_secs(5), dial).await {
        Ok(result) => result,
        Err(_) => Err(SsrProxyError::Timeout),
    }
}

/// Opens an SSR UDP association (cipher → protocol packet layering).
///
/// # Errors
///
/// Returns for cipher/protocol errors, resolution failures, or socket failures.
#[allow(clippy::too_many_arguments)]
pub async fn associate_ssr_udp_with_options(
    server: &Destination,
    allow_ipv6: bool,
    password: &str,
    cipher: &str,
    protocol: &str,
    protocol_param: &str,
    obfs: &str,
    obfs_param: &str,
    server_host: &str,
    options: DirectTcpOptions<'_>,
) -> Result<SsrUdpAssociation, SsrProxyError> {
    let server_address = resolve_server(server, allow_ipv6).await?;
    let bind_address = if server_address.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = rewrite_platform::bind_outbound_udp(
        bind_address,
        server_address,
        options.interface,
        options.routing_mark,
    )?;
    let socket = tokio::net::UdpSocket::from_std(socket)?;
    socket.connect(server_address).await?;
    let client = ssr_client_options(
        server_host,
        server.port,
        password,
        cipher,
        protocol,
        protocol_param,
        obfs,
        obfs_param,
    );
    SsrUdpAssociation::from_connected_socket(socket, &client).map_err(Into::into)
}

async fn resolve_server(
    server: &Destination,
    allow_ipv6: bool,
) -> Result<SocketAddr, SsrProxyError> {
    match &server.host {
        Host::Ip(address) => {
            if address.is_ipv6() && !allow_ipv6 {
                return Err(SsrProxyError::Direct(DirectError::Ipv6Disabled));
            }
            Ok(SocketAddr::new(*address, server.port))
        }
        Host::Domain(domain) => tokio::net::lookup_host((domain.as_str(), server.port))
            .await?
            .find(|address| allow_ipv6 || address.is_ipv4())
            .ok_or_else(|| {
                SsrProxyError::Io(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "no permitted ShadowsocksR UDP server address resolved",
                ))
            }),
    }
}

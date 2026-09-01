use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use rewrite_model::{Destination, Host};
use thiserror::Error;
use tokio::net::{TcpStream, UdpSocket};

#[derive(Debug, Error)]
pub enum DirectError {
    #[error("DIRECT TCP dial timed out")]
    Timeout,
    #[error("DIRECT TCP dial failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("IPv6 is disabled")]
    Ipv6Disabled,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DirectTcpOptions<'a> {
    pub interface: &'a str,
    pub routing_mark: i64,
    pub keep_alive_idle: i64,
    pub keep_alive_interval: i64,
    pub disable_keep_alive: bool,
    pub tcp_concurrent: bool,
}

/// Opens a direct TCP connection with the Phase 1 timeout and IPv6 policy.
///
/// # Errors
///
/// Returns [`DirectError`] when IPv6 is disabled for the destination, name
/// resolution or connection I/O fails, or the five-second deadline expires.
pub async fn connect(
    destination: &Destination,
    allow_ipv6: bool,
) -> Result<TcpStream, DirectError> {
    connect_with_options(destination, allow_ipv6, DirectTcpOptions::default()).await
}

/// Opens a direct TCP connection with global platform socket policy.
///
/// # Errors
///
/// Returns [`DirectError`] for policy, resolution, socket or timeout failures.
pub async fn connect_with_options(
    destination: &Destination,
    allow_ipv6: bool,
    options: DirectTcpOptions<'_>,
) -> Result<TcpStream, DirectError> {
    let connect = async {
        match destination.host {
            Host::Ip(address) => {
                if address.is_ipv6() && !allow_ipv6 {
                    return Err(DirectError::Ipv6Disabled);
                }
                rewrite_platform::connect_tcp(
                    (address, destination.port).into(),
                    platform_options(options),
                )
                .await
                .map_err(DirectError::Io)
            }
            Host::Domain(ref domain) => {
                let addresses = tokio::net::lookup_host((domain.as_str(), destination.port))
                    .await
                    .map_err(DirectError::Io)?;
                let addresses: Vec<_> = addresses
                    .filter(|address| allow_ipv6 || address.is_ipv4())
                    .collect();
                let mut last_error = None;
                if options.tcp_concurrent {
                    let mut attempts = FuturesUnordered::new();
                    for address in addresses {
                        attempts.push(rewrite_platform::connect_tcp(
                            address,
                            platform_options(options),
                        ));
                    }
                    while let Some(result) = attempts.next().await {
                        match result {
                            Ok(stream) => return Ok(stream),
                            Err(error) => last_error = Some(error),
                        }
                    }
                } else {
                    for address in addresses {
                        match rewrite_platform::connect_tcp(address, platform_options(options))
                            .await
                        {
                            Ok(stream) => return Ok(stream),
                            Err(error) => last_error = Some(error),
                        }
                    }
                }
                Err(DirectError::Io(last_error.unwrap_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "no permitted address resolved",
                    )
                })))
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), connect)
        .await
        .map_err(|_| DirectError::Timeout)?
}

/// Opens a connected UDP socket with the same resolution, interface and mark
/// policy used by direct TCP dials.
///
/// # Errors
///
/// Returns policy, resolution, bind, connect or timeout failures.
pub async fn connect_udp_with_options(
    destination: &Destination,
    allow_ipv6: bool,
    options: DirectTcpOptions<'_>,
) -> Result<UdpSocket, DirectError> {
    let connect = async {
        let addresses = match destination.host {
            Host::Ip(address) => vec![(address, destination.port).into()],
            Host::Domain(ref domain) => {
                tokio::net::lookup_host((domain.as_str(), destination.port))
                    .await
                    .map_err(DirectError::Io)?
                    .collect()
            }
        };
        let mut last_error = None;
        for address in addresses
            .into_iter()
            .filter(|address| allow_ipv6 || address.is_ipv4())
        {
            let bind = if address.is_ipv4() {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            };
            let socket = match rewrite_platform::bind_outbound_udp(
                bind,
                options.interface,
                options.routing_mark,
            ) {
                Ok(socket) => socket,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let socket = UdpSocket::from_std(socket).map_err(DirectError::Io)?;
            match socket.connect(address).await {
                Ok(()) => return Ok(socket),
                Err(error) => last_error = Some(error),
            }
        }
        Err(DirectError::Io(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "no permitted UDP address resolved",
            )
        })))
    };
    tokio::time::timeout(Duration::from_secs(5), connect)
        .await
        .map_err(|_| DirectError::Timeout)?
}

fn platform_options(options: DirectTcpOptions<'_>) -> rewrite_platform::OutboundTcpOptions<'_> {
    rewrite_platform::OutboundTcpOptions {
        interface: options.interface,
        routing_mark: options.routing_mark,
        keep_alive_idle: options.keep_alive_idle,
        keep_alive_interval: options.keep_alive_interval,
        disable_keep_alive: options.disable_keep_alive,
    }
}

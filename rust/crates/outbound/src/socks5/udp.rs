use std::sync::Arc;
use std::time::Duration;

use fast_socks5::util::target_addr::{TargetAddr, ToTargetAddr};
use rewrite_model::{Destination, Host};
use tokio::net::UdpSocket;

use crate::BoxedOutboundStream;
use crate::direct::{DirectError, DirectTcpOptions};
use rewrite_transport::ClientTlsOptions as HttpProxyTls;

use super::tcp::command_handshake;
use super::{Socks5ProxyError, connect_control};

pub struct Socks5UdpAssociation {
    _control: tokio::sync::Mutex<BoxedOutboundStream>,
    socket: UdpSocket,
    relay: std::net::SocketAddr,
}

impl Socks5UdpAssociation {
    /// Sends one UDP payload through the negotiated SOCKS5 relay.
    ///
    /// # Errors
    ///
    /// Returns an address-encoding or socket error when the relay datagram
    /// cannot be constructed or sent.
    pub async fn send(
        &self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), Socks5ProxyError> {
        let target = destination.host.to_string();
        let address = (target.as_str(), destination.port)
            .to_target_addr()
            .map_err(DirectError::Io)?
            .to_be_bytes()
            .map_err(|error| Socks5ProxyError::InvalidAddress(error.to_string()))?;
        let mut packet = Vec::with_capacity(address.len() + payload.len() + 3);
        packet.extend_from_slice(&[0, 0, 0]);
        packet.extend_from_slice(&address);
        packet.extend_from_slice(payload);
        self.socket
            .send_to(&packet, self.relay)
            .await
            .map_err(DirectError::Io)?;
        Ok(())
    }

    /// Receives and decodes one UDP payload from the negotiated SOCKS5 relay.
    ///
    /// # Errors
    ///
    /// Returns a socket or framing error for packets that do not come from the
    /// negotiated relay or do not contain a valid SOCKS5 UDP address.
    pub async fn recv(&self) -> Result<(Destination, Vec<u8>), Socks5ProxyError> {
        let mut packet = vec![0_u8; 65_535];
        let (length, source) = self
            .socket
            .recv_from(&mut packet)
            .await
            .map_err(DirectError::Io)?;
        if source != self.relay || length < 4 || packet[..3] != [0, 0, 0] {
            return Err(Socks5ProxyError::InvalidAddress(
                "invalid SOCKS5 UDP relay packet".to_owned(),
            ));
        }
        packet.truncate(length);
        let (destination, payload_offset) = decode_udp_address(&packet[3..])?;
        Ok((destination, packet[(payload_offset + 3)..].to_vec()))
    }
}

/// Opens one RFC 1928 UDP ASSOCIATE session through a configured SOCKS5 proxy.
///
/// # Errors
///
/// Returns a TCP/TLS, authentication, UDP bind or SOCKS5 framing error when
/// the association cannot be established.
#[allow(clippy::too_many_arguments)]
pub async fn associate_socks5_udp_with_options(
    server: &Destination,
    allow_ipv6: bool,
    credentials: Option<(&str, &str)>,
    tls: Option<HttpProxyTls<'_>>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
    options: DirectTcpOptions<'_>,
) -> Result<Socks5UdpAssociation, Socks5ProxyError> {
    let mut control = connect_control(server, allow_ipv6, tls, clock, options).await?;
    let request = Destination {
        host: Host::Ip(std::net::Ipv4Addr::UNSPECIFIED.into()),
        port: 0,
    };
    let relay = tokio::time::timeout(
        Duration::from_secs(5),
        command_handshake(&mut control, &request, 3, credentials),
    )
    .await
    .map_err(|_| Socks5ProxyError::HandshakeTimeout)??;
    let relay = resolve_relay(relay, server, allow_ipv6).await?;
    let bind = if relay.is_ipv4() {
        std::net::SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        std::net::SocketAddr::from(([0_u16; 8], 0))
    };
    let socket = rewrite_platform::bind_outbound_udp(bind, options.interface, options.routing_mark)
        .and_then(UdpSocket::from_std)
        .map_err(DirectError::Io)?;
    Ok(Socks5UdpAssociation {
        _control: tokio::sync::Mutex::new(control),
        socket,
        relay,
    })
}

async fn resolve_relay(
    relay: TargetAddr,
    server: &Destination,
    allow_ipv6: bool,
) -> Result<std::net::SocketAddr, Socks5ProxyError> {
    let (host, port) = relay.into_string_and_port();
    let lookup_host = match host.parse::<std::net::IpAddr>() {
        Ok(address) if !address.is_unspecified() => {
            return Ok(std::net::SocketAddr::new(address, port));
        }
        Ok(_) => server.host.to_string(),
        Err(_) => host,
    };
    let mut addresses = tokio::net::lookup_host((lookup_host.as_str(), port))
        .await
        .map_err(DirectError::Io)?;
    addresses
        .find(|address| allow_ipv6 || address.is_ipv4())
        .ok_or_else(|| {
            Socks5ProxyError::InvalidAddress(
                "SOCKS5 UDP relay resolved to no permitted address".to_owned(),
            )
        })
}

fn decode_udp_address(packet: &[u8]) -> Result<(Destination, usize), Socks5ProxyError> {
    let invalid = || Socks5ProxyError::InvalidAddress("truncated SOCKS5 UDP address".to_owned());
    let (host, port_offset) = match packet.first().copied() {
        Some(1) if packet.len() >= 7 => (
            Host::Ip(std::net::Ipv4Addr::new(packet[1], packet[2], packet[3], packet[4]).into()),
            5,
        ),
        Some(4) if packet.len() >= 19 => {
            let octets: [u8; 16] = packet[1..17].try_into().map_err(|_| invalid())?;
            (Host::Ip(std::net::Ipv6Addr::from(octets).into()), 17)
        }
        Some(3) if packet.len() >= 2 => {
            let length = usize::from(packet[1]);
            if packet.len() < length + 4 {
                return Err(invalid());
            }
            let host = std::str::from_utf8(&packet[2..(2 + length)])
                .map_err(|error| Socks5ProxyError::InvalidAddress(error.to_string()))?;
            (Host::Domain(host.to_owned()), length + 2)
        }
        _ => return Err(invalid()),
    };
    let port = u16::from_be_bytes(
        packet[port_offset..(port_offset + 2)]
            .try_into()
            .map_err(|_| invalid())?,
    );
    Ok((Destination { host, port }, port_offset + 2))
}

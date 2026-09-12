use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rewrite_model::{Destination, Host};

use crate::SnellProtocolError;
use crate::header::COMMAND_UDP_FORWARD;

pub(crate) const MAX_UDP_LENGTH: usize = 0x3FFF;

pub(crate) fn encode_udp_request(
    destination: &Destination,
    payload: &[u8],
) -> Result<Vec<u8>, SnellProtocolError> {
    let header_len = udp_request_header_len(destination)?;
    if header_len + payload.len() > MAX_UDP_LENGTH {
        return Err(SnellProtocolError::Protocol(
            "Snell UDP payload too large".to_owned(),
        ));
    }
    let mut packet = Vec::with_capacity(header_len + payload.len());
    packet.push(COMMAND_UDP_FORWARD);
    match &destination.host {
        Host::Domain(domain) => {
            let host_len = u8::try_from(domain.len()).map_err(|_| {
                SnellProtocolError::Protocol("Snell UDP domain exceeds 255 bytes".to_owned())
            })?;
            packet.push(host_len);
            packet.extend_from_slice(domain.as_bytes());
            packet.extend_from_slice(&destination.port.to_be_bytes());
        }
        Host::Ip(IpAddr::V4(address)) => {
            packet.extend_from_slice(&[0, 0x04]);
            packet.extend_from_slice(&address.octets());
            packet.extend_from_slice(&destination.port.to_be_bytes());
        }
        Host::Ip(IpAddr::V6(address)) => {
            packet.extend_from_slice(&[0, 0x06]);
            packet.extend_from_slice(&address.octets());
            packet.extend_from_slice(&destination.port.to_be_bytes());
        }
    }
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub(crate) fn parse_udp_request(
    packet: &[u8],
) -> Result<(Destination, Vec<u8>), SnellProtocolError> {
    if packet.len() < 2 || packet[0] != COMMAND_UDP_FORWARD {
        return Err(SnellProtocolError::Protocol(
            "Snell invalid UDP request".to_owned(),
        ));
    }
    let host_len = usize::from(packet[1]);
    if host_len != 0 {
        let host_end = 2 + host_len;
        let port_end = host_end + 2;
        if packet.len() < port_end {
            return Err(SnellProtocolError::Protocol(
                "Snell invalid UDP domain request".to_owned(),
            ));
        }
        let host = packet.get(2..host_end).ok_or_else(|| {
            SnellProtocolError::Protocol("Snell UDP domain slice failed".to_owned())
        })?;
        let host = std::str::from_utf8(host)
            .map_err(|_| SnellProtocolError::Protocol("Snell UDP domain was not UTF-8".to_owned()))?
            .to_owned();
        let port_bytes = packet.get(host_end..port_end).ok_or_else(|| {
            SnellProtocolError::Protocol("Snell UDP domain port slice failed".to_owned())
        })?;
        return Ok((
            Destination {
                host: Host::Domain(host),
                port: u16::from_be_bytes([port_bytes[0], port_bytes[1]]),
            },
            packet.get(port_end..).unwrap_or(&[]).to_vec(),
        ));
    }
    if packet.len() < 3 {
        return Err(SnellProtocolError::Protocol(
            "Snell invalid UDP IP request".to_owned(),
        ));
    }
    match packet[2] {
        0x04 => parse_ip_request(packet, 4, |bytes| {
            Host::Ip(IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(bytes).map_err(|_| {
                    SnellProtocolError::Protocol("Snell UDP IPv4 slice failed".to_owned())
                })?,
            )))
        }),
        0x06 => parse_ip_request(packet, 16, |bytes| {
            Host::Ip(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).map_err(|_| {
                    SnellProtocolError::Protocol("Snell UDP IPv6 slice failed".to_owned())
                })?,
            )))
        }),
        other => Err(SnellProtocolError::Protocol(format!(
            "Snell invalid UDP address type {other}"
        ))),
    }
}

pub(crate) fn encode_udp_response(
    address: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, SnellProtocolError> {
    let mut packet = Vec::with_capacity(19 + payload.len());
    match address.ip() {
        IpAddr::V4(ip) => {
            packet.push(0x04);
            packet.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.push(0x06);
            packet.extend_from_slice(&ip.octets());
        }
    }
    packet.extend_from_slice(&address.port().to_be_bytes());
    packet.extend_from_slice(payload);
    if packet.len() > MAX_UDP_LENGTH {
        return Err(SnellProtocolError::Protocol(
            "Snell UDP response too large".to_owned(),
        ));
    }
    Ok(packet)
}

pub(crate) fn parse_udp_response(
    packet: &[u8],
) -> Result<(Destination, Vec<u8>), SnellProtocolError> {
    let Some((&kind, rest)) = packet.split_first() else {
        return Err(SnellProtocolError::Protocol(
            "Snell UDP response was empty".to_owned(),
        ));
    };
    match kind {
        0x04 => parse_ip_response(rest, 4, |bytes| {
            Host::Ip(IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(bytes).map_err(|_| {
                    SnellProtocolError::Protocol("Snell UDP IPv4 response slice failed".to_owned())
                })?,
            )))
        }),
        0x06 => parse_ip_response(rest, 16, |bytes| {
            Host::Ip(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).map_err(|_| {
                    SnellProtocolError::Protocol("Snell UDP IPv6 response slice failed".to_owned())
                })?,
            )))
        }),
        other => Err(SnellProtocolError::Protocol(format!(
            "Snell UDP response address type {other} is invalid"
        ))),
    }
}

fn udp_request_header_len(destination: &Destination) -> Result<usize, SnellProtocolError> {
    Ok(match &destination.host {
        Host::Domain(domain) => 1 + 1 + domain.len() + 2,
        Host::Ip(IpAddr::V4(_)) => 1 + 2 + 4 + 2,
        Host::Ip(IpAddr::V6(_)) => 1 + 2 + 16 + 2,
    })
}

fn parse_ip_request(
    packet: &[u8],
    ip_len: usize,
    host: impl FnOnce(&[u8]) -> Result<Host, SnellProtocolError>,
) -> Result<(Destination, Vec<u8>), SnellProtocolError> {
    let ip_start = 3;
    let ip_end = ip_start + ip_len;
    let port_end = ip_end + 2;
    if packet.len() < port_end {
        return Err(SnellProtocolError::Protocol(
            "Snell invalid UDP IP request".to_owned(),
        ));
    }
    let ip = packet
        .get(ip_start..ip_end)
        .ok_or_else(|| SnellProtocolError::Protocol("Snell UDP IP slice failed".to_owned()))?;
    let port_bytes = packet
        .get(ip_end..port_end)
        .ok_or_else(|| SnellProtocolError::Protocol("Snell UDP IP port slice failed".to_owned()))?;
    Ok((
        Destination {
            host: host(ip)?,
            port: u16::from_be_bytes([port_bytes[0], port_bytes[1]]),
        },
        packet.get(port_end..).unwrap_or(&[]).to_vec(),
    ))
}

fn parse_ip_response(
    rest: &[u8],
    ip_len: usize,
    host: impl FnOnce(&[u8]) -> Result<Host, SnellProtocolError>,
) -> Result<(Destination, Vec<u8>), SnellProtocolError> {
    let port_end = ip_len + 2;
    if rest.len() < port_end {
        return Err(SnellProtocolError::Protocol(
            "Snell UDP response ended early".to_owned(),
        ));
    }
    let ip = rest.get(..ip_len).ok_or_else(|| {
        SnellProtocolError::Protocol("Snell UDP response IP slice failed".to_owned())
    })?;
    let port_bytes = rest.get(ip_len..port_end).ok_or_else(|| {
        SnellProtocolError::Protocol("Snell UDP response port slice failed".to_owned())
    })?;
    Ok((
        Destination {
            host: host(ip)?,
            port: u16::from_be_bytes([port_bytes[0], port_bytes[1]]),
        },
        rest.get(port_end..).unwrap_or(&[]).to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{encode_udp_request, encode_udp_response, parse_udp_request, parse_udp_response};
    use rewrite_model::{Destination, Host};

    #[test]
    fn ipv4_request_roundtrip() {
        let dest = Destination {
            host: Host::Ip("192.0.2.1".parse().expect("ip")),
            port: 53,
        };
        let packet = encode_udp_request(&dest, b"ping").expect("encode");
        let (parsed, payload) = parse_udp_request(&packet).expect("parse");
        assert_eq!(parsed, dest);
        assert_eq!(payload, b"ping");
    }

    #[test]
    fn domain_request_roundtrip() {
        let dest = Destination {
            host: Host::Domain("dns.example".to_owned()),
            port: 53,
        };
        let packet = encode_udp_request(&dest, b"q").expect("encode");
        let (parsed, payload) = parse_udp_request(&packet).expect("parse");
        assert_eq!(parsed, dest);
        assert_eq!(payload, b"q");
    }

    #[test]
    fn ipv4_response_roundtrip() {
        let address = "198.51.100.9:5353".parse().expect("addr");
        let packet = encode_udp_response(address, b"pong").expect("encode");
        let (parsed, payload) = parse_udp_response(&packet).expect("parse");
        assert_eq!(parsed.host, Host::Ip(address.ip()));
        assert_eq!(parsed.port, 5353);
        assert_eq!(payload, b"pong");
    }
}

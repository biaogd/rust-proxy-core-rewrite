//! TUIC v5 command and address framing (Go `transport/tuic/v5/protocol.go`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rewrite_model::{Destination, Host};

use crate::TuicProtocolError;

pub const VERSION: u8 = 0x05;

pub const CMD_AUTHENTICATE: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;

pub const ATYP_DOMAIN: u8 = 0;
pub const ATYP_IPV4: u8 = 1;
pub const ATYP_IPV6: u8 = 2;
pub const ATYP_NONE: u8 = 255;

/// Encodes a TUIC v5 Authenticate uni-stream body: VER TYPE UUID TOKEN.
#[must_use]
pub fn encode_authenticate(uuid: [u8; 16], token: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 16 + 32);
    out.push(VERSION);
    out.push(CMD_AUTHENTICATE);
    out.extend_from_slice(&uuid);
    out.extend_from_slice(&token);
    out
}

/// Encodes a TUIC v5 Connect command (VER TYPE ADDR) for a TCP relay.
///
/// # Errors
///
/// Returns when the destination domain is empty or longer than 255 bytes.
pub fn encode_connect(destination: &Destination) -> Result<Vec<u8>, TuicProtocolError> {
    let mut out = Vec::new();
    out.push(VERSION);
    out.push(CMD_CONNECT);
    encode_address(&mut out, destination)?;
    Ok(out)
}

fn encode_address(out: &mut Vec<u8>, destination: &Destination) -> Result<(), TuicProtocolError> {
    match &destination.host {
        Host::Ip(ip) => match ip.to_canonical() {
            IpAddr::V4(addr) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&addr.octets());
            }
        },
        Host::Domain(domain) => {
            let host = domain.trim_end_matches('.');
            if host.is_empty() || host.len() > 255 {
                return Err(TuicProtocolError::Protocol(format!(
                    "invalid TUIC domain: {domain}"
                )));
            }
            out.push(ATYP_DOMAIN);
            out.push(u8::try_from(host.len()).unwrap_or(u8::MAX));
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

/// Decodes a TUIC address for unit tests and later UDP work.
///
/// # Errors
///
/// Returns when the buffer is truncated or the address type is unknown.
pub fn decode_address(buf: &[u8]) -> Result<(Destination, usize), TuicProtocolError> {
    let typ = *buf
        .first()
        .ok_or_else(|| TuicProtocolError::Protocol("truncated TUIC address type".to_owned()))?;
    let mut pos = 1_usize;
    let host = match typ {
        ATYP_IPV4 => {
            let bytes = buf.get(pos..pos + 4).ok_or_else(|| {
                TuicProtocolError::Protocol("truncated TUIC IPv4 address".to_owned())
            })?;
            pos += 4;
            Host::Ip(IpAddr::V4(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        }
        ATYP_IPV6 => {
            let bytes = buf.get(pos..pos + 16).ok_or_else(|| {
                TuicProtocolError::Protocol("truncated TUIC IPv6 address".to_owned())
            })?;
            pos += 16;
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(bytes);
            Host::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        ATYP_DOMAIN => {
            let len = usize::from(*buf.get(pos).ok_or_else(|| {
                TuicProtocolError::Protocol("truncated TUIC domain length".to_owned())
            })?);
            pos += 1;
            let bytes = buf
                .get(pos..pos + len)
                .ok_or_else(|| TuicProtocolError::Protocol("truncated TUIC domain".to_owned()))?;
            pos += len;
            Host::Domain(
                std::str::from_utf8(bytes)
                    .map_err(|_| TuicProtocolError::Protocol("non-UTF8 TUIC domain".to_owned()))?
                    .to_owned(),
            )
        }
        ATYP_NONE => {
            return Err(TuicProtocolError::Protocol(
                "TUIC address type none is not valid on Connect".to_owned(),
            ));
        }
        other => {
            return Err(TuicProtocolError::Protocol(format!(
                "unknown TUIC address type {other}"
            )));
        }
    };
    let port_bytes = buf
        .get(pos..pos + 2)
        .ok_or_else(|| TuicProtocolError::Protocol("truncated TUIC port".to_owned()))?;
    pos += 2;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    Ok((Destination { host, port }, pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticate_frame_is_50_bytes() {
        let frame = encode_authenticate([0x11; 16], [0x22; 32]);
        assert_eq!(frame.len(), 50);
        assert_eq!(frame[0], VERSION);
        assert_eq!(frame[1], CMD_AUTHENTICATE);
        assert_eq!(&frame[2..18], &[0x11; 16]);
        assert_eq!(&frame[18..], &[0x22; 32]);
    }

    #[test]
    fn connect_encodes_ipv4_domain_and_ipv6() {
        let ipv4 = encode_connect(&Destination {
            host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: 8080,
        })
        .expect("ipv4");
        assert_eq!(ipv4[0], VERSION);
        assert_eq!(ipv4[1], CMD_CONNECT);
        let (decoded, n) = decode_address(&ipv4[2..]).expect("decode ipv4");
        assert_eq!(n, ipv4.len() - 2);
        assert_eq!(decoded.port, 8080);
        assert_eq!(decoded.host, Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));

        let domain = encode_connect(&Destination {
            host: Host::Domain("echo.tuic.test".to_owned()),
            port: 443,
        })
        .expect("domain");
        let (decoded, _) = decode_address(&domain[2..]).expect("decode domain");
        assert_eq!(decoded.host, Host::Domain("echo.tuic.test".to_owned()));
        assert_eq!(decoded.port, 443);

        let ipv6 = encode_connect(&Destination {
            host: Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            port: 9,
        })
        .expect("ipv6");
        let (decoded, _) = decode_address(&ipv6[2..]).expect("decode ipv6");
        assert_eq!(decoded.host, Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(decoded.port, 9);
    }

    #[test]
    fn connect_unmaps_ipv4_mapped_ipv6() {
        let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        let frame = encode_connect(&Destination {
            host: Host::Ip(IpAddr::V6(mapped)),
            port: 80,
        })
        .expect("mapped");
        assert_eq!(frame[2], ATYP_IPV4);
        assert_eq!(&frame[3..7], &[127, 0, 0, 1]);
    }
}

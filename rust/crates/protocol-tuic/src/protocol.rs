//! TUIC v5 command and address framing (Go `transport/tuic/v5/protocol.go`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rewrite_model::{Destination, Host};

use crate::TuicProtocolError;

pub const VERSION: u8 = 0x05;

pub const CMD_AUTHENTICATE: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_PACKET: u8 = 0x02;
pub const CMD_DISSOCIATE: u8 = 0x03;
pub const CMD_HEARTBEAT: u8 = 0x04;

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

pub(crate) fn encode_address_none(out: &mut Vec<u8>) {
    out.push(ATYP_NONE);
}

/// Decodes a TUIC address, including Packet fragment type `None`.
///
/// # Errors
///
/// Returns when the buffer is truncated or the address type is unknown.
pub fn decode_address(buf: &[u8]) -> Result<(Destination, usize), TuicProtocolError> {
    match decode_optional_address(buf)? {
        (Some(destination), consumed) => Ok((destination, consumed)),
        (None, _) => Err(TuicProtocolError::Protocol(
            "TUIC address type none is not valid on Connect".to_owned(),
        )),
    }
}

pub(crate) fn decode_optional_address(
    buf: &[u8],
) -> Result<(Option<Destination>, usize), TuicProtocolError> {
    let typ = *buf
        .first()
        .ok_or_else(|| TuicProtocolError::Protocol("truncated TUIC address type".to_owned()))?;
    if typ == ATYP_NONE {
        return Ok((None, 1));
    }
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
    Ok((Some(Destination { host, port }), pos))
}

/// Go `PacketOverHead` via `Packet.BytesLen` for IPv6 unspecified (undercounts
/// the two fragment bytes that `WriteTo` actually emits).
pub const PACKET_OVERHEAD_GO: usize = 27;

/// Go `MaxFragSize` = `1200 - PacketOverHead - 3`.
pub const MAX_FRAG_SIZE: usize = 1200 - PACKET_OVERHEAD_GO - 3;

/// Clash `max-udp-relay-packet-size` after Go's frame-size and `MaxFragSize` caps.
#[must_use]
pub fn compute_max_udp_relay_packet_size(yaml: u64) -> usize {
    let mut max = if yaml == 0 {
        1252
    } else {
        usize::try_from(yaml).unwrap_or(usize::MAX)
    };
    let mut frame = max.saturating_add(PACKET_OVERHEAD_GO);
    if frame > 1400 {
        frame = 1400;
    }
    max = frame.saturating_sub(PACKET_OVERHEAD_GO);
    max.min(MAX_FRAG_SIZE)
}

/// TUIC v5 Packet command (TYPE=0x02).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    pub assoc_id: u16,
    pub pkt_id: u16,
    pub frag_total: u8,
    pub frag_id: u8,
    pub addr: Option<Destination>,
    pub data: Vec<u8>,
}

/// Encodes a Packet command. Later fragments use address type `None`.
///
/// # Errors
///
/// Returns when a first-fragment destination is missing or a domain is invalid.
pub fn encode_packet(packet: &Packet) -> Result<Vec<u8>, TuicProtocolError> {
    if packet.data.len() > usize::from(u16::MAX) {
        return Err(TuicProtocolError::Protocol(
            "TUIC UDP payload exceeds 65535 bytes".to_owned(),
        ));
    }
    let mut out = Vec::new();
    out.push(VERSION);
    out.push(CMD_PACKET);
    out.extend_from_slice(&packet.assoc_id.to_be_bytes());
    out.extend_from_slice(&packet.pkt_id.to_be_bytes());
    out.push(packet.frag_total);
    out.push(packet.frag_id);
    let size = u16::try_from(packet.data.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&size.to_be_bytes());
    match &packet.addr {
        Some(destination) => encode_address(&mut out, destination)?,
        None => encode_address_none(&mut out),
    }
    out.extend_from_slice(&packet.data);
    Ok(out)
}

#[must_use]
pub fn encode_dissociate(assoc_id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    out.push(VERSION);
    out.push(CMD_DISSOCIATE);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out
}

#[must_use]
pub fn encode_heartbeat() -> Vec<u8> {
    vec![VERSION, CMD_HEARTBEAT]
}

/// Decodes one Packet from a complete datagram or uni-stream buffer.
///
/// # Errors
///
/// Returns when the buffer is not a Packet or is truncated.
pub fn decode_packet(buf: &[u8]) -> Result<Packet, TuicProtocolError> {
    match try_decode_command(buf)? {
        DecodeProgress::Incomplete => Err(TuicProtocolError::Protocol(
            "truncated TUIC packet".to_owned(),
        )),
        DecodeProgress::Heartbeat => Err(TuicProtocolError::Protocol(
            "TUIC heartbeat is not a packet".to_owned(),
        )),
        DecodeProgress::Packet(packet) => Ok(packet),
        DecodeProgress::Other(kind) => Err(TuicProtocolError::Protocol(format!(
            "unexpected TUIC command {kind:#04x}"
        ))),
    }
}

#[derive(Debug)]
pub(crate) enum DecodeProgress {
    Incomplete,
    Heartbeat,
    Packet(Packet),
    Other(u8),
}

pub(crate) fn try_decode_command(buf: &[u8]) -> Result<DecodeProgress, TuicProtocolError> {
    if buf.len() < 2 {
        return Ok(DecodeProgress::Incomplete);
    }
    if buf[0] != VERSION {
        return Err(TuicProtocolError::Protocol(format!(
            "unsupported TUIC version {:#04x}",
            buf[0]
        )));
    }
    match buf[1] {
        CMD_HEARTBEAT => Ok(DecodeProgress::Heartbeat),
        CMD_PACKET => try_decode_packet_body(buf),
        other => Ok(DecodeProgress::Other(other)),
    }
}

fn try_decode_packet_body(buf: &[u8]) -> Result<DecodeProgress, TuicProtocolError> {
    if buf.len() < 10 {
        return Ok(DecodeProgress::Incomplete);
    }
    let assoc_id = u16::from_be_bytes([buf[2], buf[3]]);
    let pkt_id = u16::from_be_bytes([buf[4], buf[5]]);
    let frag_total = buf[6];
    let frag_id = buf[7];
    let size = usize::from(u16::from_be_bytes([buf[8], buf[9]]));
    let Some(addr_len) = address_wire_len(&buf[10..])? else {
        return Ok(DecodeProgress::Incomplete);
    };
    let data_start = 10 + addr_len;
    let data_end = data_start.saturating_add(size);
    if buf.len() < data_end {
        return Ok(DecodeProgress::Incomplete);
    }
    let (addr, _) = decode_optional_address(&buf[10..data_start])?;
    Ok(DecodeProgress::Packet(Packet {
        assoc_id,
        pkt_id,
        frag_total,
        frag_id,
        addr,
        data: buf[data_start..data_end].to_vec(),
    }))
}

fn address_wire_len(buf: &[u8]) -> Result<Option<usize>, TuicProtocolError> {
    let Some(&typ) = buf.first() else {
        return Ok(None);
    };
    let needed = match typ {
        ATYP_NONE => 1,
        ATYP_IPV4 => 7,
        ATYP_IPV6 => 19,
        ATYP_DOMAIN => {
            let Some(&len) = buf.get(1) else {
                return Ok(None);
            };
            2 + usize::from(len) + 2
        }
        other => {
            return Err(TuicProtocolError::Protocol(format!(
                "unknown TUIC address type {other}"
            )));
        }
    };
    if buf.len() < needed {
        Ok(None)
    } else {
        Ok(Some(needed))
    }
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

    #[test]
    fn packet_round_trip_and_none_address() {
        let first = Packet {
            assoc_id: 7,
            pkt_id: 9,
            frag_total: 2,
            frag_id: 0,
            addr: Some(Destination {
                host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                port: 9,
            }),
            data: b"ab".to_vec(),
        };
        let encoded = encode_packet(&first).expect("encode");
        let decoded = decode_packet(&encoded).expect("decode");
        assert_eq!(decoded, first);

        let rest = Packet {
            assoc_id: 7,
            pkt_id: 9,
            frag_total: 2,
            frag_id: 1,
            addr: None,
            data: b"cd".to_vec(),
        };
        let encoded = encode_packet(&rest).expect("encode rest");
        assert_eq!(encoded[10], ATYP_NONE);
        let decoded = decode_packet(&encoded).expect("decode rest");
        assert_eq!(decoded.addr, None);
        assert_eq!(decoded.data, b"cd");
    }

    #[test]
    fn go_overhead_and_max_frag_constants() {
        assert_eq!(PACKET_OVERHEAD_GO, 27);
        assert_eq!(MAX_FRAG_SIZE, 1170);
        assert_eq!(compute_max_udp_relay_packet_size(0), 1170);
        assert_eq!(compute_max_udp_relay_packet_size(1252), 1170);
        assert_eq!(
            encode_dissociate(0x0102),
            [VERSION, CMD_DISSOCIATE, 0x01, 0x02]
        );
    }

    #[test]
    fn heartbeat_and_malformed_commands() {
        assert_eq!(encode_heartbeat(), [VERSION, CMD_HEARTBEAT]);
        match try_decode_command(&[VERSION, CMD_HEARTBEAT]).expect("hb") {
            DecodeProgress::Heartbeat => {}
            other => panic!("unexpected {other:?}"),
        }
        match try_decode_command(&[VERSION, CMD_PACKET, 0, 1]).expect("short") {
            DecodeProgress::Incomplete => {}
            other => panic!("unexpected {other:?}"),
        }
        assert!(try_decode_command(&[0x04, CMD_PACKET]).is_err());
        match try_decode_command(&[VERSION, 0x7f]).expect("other") {
            DecodeProgress::Other(0x7f) => {}
            other => panic!("unexpected {other:?}"),
        }
        match try_decode_command(&[VERSION]).expect("one byte") {
            DecodeProgress::Incomplete => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}

//! `AnyTLS` session-layer frame helpers.

pub(crate) const CMD_WASTE: u8 = 0;
pub(crate) const CMD_SYN: u8 = 1;
pub(crate) const CMD_PSH: u8 = 2;
pub(crate) const CMD_FIN: u8 = 3;
pub(crate) const CMD_SETTINGS: u8 = 4;
pub(crate) const CMD_ALERT: u8 = 5;
pub(crate) const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
pub(crate) const CMD_SYNACK: u8 = 7;
pub(crate) const CMD_HEART_REQUEST: u8 = 8;
pub(crate) const CMD_HEART_RESPONSE: u8 = 9;
pub(crate) const CMD_SERVER_SETTINGS: u8 = 10;

pub(crate) const HEADER_OVERHEAD: usize = 1 + 4 + 2;
pub(crate) const MAX_FRAME_DATA_LEN: usize = 0xFFFF;

#[derive(Clone, Debug)]
pub(crate) struct Frame {
    pub cmd: u8,
    pub sid: u32,
    pub data: Vec<u8>,
}

impl Frame {
    pub(crate) fn new(cmd: u8, sid: u32) -> Self {
        Self {
            cmd,
            sid,
            data: Vec::new(),
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        encode_frame(self.cmd, self.sid, &self.data)
    }
}

/// Encode one frame header + payload in a single allocation (one data copy).
pub(crate) fn encode_frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_OVERHEAD + data.len());
    out.push(cmd);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Encode PSH frames for `data`, splitting at [`MAX_FRAME_DATA_LEN`].
///
/// Empty input yields an empty buffer (caller should skip the write).
pub(crate) fn encode_psh_payload(sid: u32, data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    if data.len() <= MAX_FRAME_DATA_LEN {
        return encode_frame(CMD_PSH, sid, data);
    }
    let frame_count = data.len().div_ceil(MAX_FRAME_DATA_LEN);
    let mut encoded = Vec::with_capacity(data.len() + HEADER_OVERHEAD * frame_count);
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + MAX_FRAME_DATA_LEN).min(data.len());
        encoded.extend_from_slice(&encode_frame(CMD_PSH, sid, &data[offset..end]));
        offset = end;
    }
    encoded
}

pub(crate) fn encode_settings(client_metadata: &str, padding_md5: &str) -> Vec<u8> {
    // Key order is not significant on the wire; servers parse by key.
    format!("v=2\nclient={client_metadata}\npadding-md5={padding_md5}").into_bytes()
}

pub(crate) fn decode_socks_address(
    buf: &[u8],
) -> Result<(rewrite_model::Destination, usize), crate::AnyTlsProtocolError> {
    use rewrite_model::{Destination, Host};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    if buf.is_empty() {
        return Err(crate::AnyTlsProtocolError::Protocol(
            "AnyTLS socks address is empty".to_owned(),
        ));
    }
    let (host, consumed) = match buf[0] {
        1 => {
            if buf.len() < 1 + 4 {
                return Err(crate::AnyTlsProtocolError::Protocol(
                    "AnyTLS IPv4 address is truncated".to_owned(),
                ));
            }
            let address = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            (Host::Ip(IpAddr::V4(address)), 1 + 4)
        }
        3 => {
            if buf.len() < 2 {
                return Err(crate::AnyTlsProtocolError::Protocol(
                    "AnyTLS domain address is truncated".to_owned(),
                ));
            }
            let length = usize::from(buf[1]);
            if buf.len() < 2 + length {
                return Err(crate::AnyTlsProtocolError::Protocol(
                    "AnyTLS domain address is truncated".to_owned(),
                ));
            }
            let domain = std::str::from_utf8(&buf[2..2 + length])
                .map_err(|error| {
                    crate::AnyTlsProtocolError::Protocol(format!(
                        "AnyTLS domain is not UTF-8: {error}"
                    ))
                })?
                .to_owned();
            (Host::Domain(domain), 2 + length)
        }
        4 => {
            if buf.len() < 1 + 16 {
                return Err(crate::AnyTlsProtocolError::Protocol(
                    "AnyTLS IPv6 address is truncated".to_owned(),
                ));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let address = Ipv6Addr::from(octets);
            (Host::Ip(IpAddr::V6(address)), 1 + 16)
        }
        ty => {
            return Err(crate::AnyTlsProtocolError::Protocol(format!(
                "AnyTLS socks address type {ty} is unsupported"
            )));
        }
    };
    if buf.len() < consumed + 2 {
        return Err(crate::AnyTlsProtocolError::Protocol(
            "AnyTLS socks port is truncated".to_owned(),
        ));
    }
    let port = u16::from_be_bytes([buf[consumed], buf[consumed + 1]]);
    Ok((Destination { host, port }, consumed + 2))
}

pub(crate) fn encode_socks_address(
    destination: &rewrite_model::Destination,
) -> Result<Vec<u8>, crate::AnyTlsProtocolError> {
    use rewrite_model::Host;
    let mut out = Vec::with_capacity(32);
    match &destination.host {
        Host::Ip(std::net::IpAddr::V4(address)) => {
            out.push(1);
            out.extend_from_slice(&address.octets());
        }
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len())
                .map_err(|_| crate::AnyTlsProtocolError::DomainTooLong)?;
            out.extend_from_slice(&[3, length]);
            out.extend_from_slice(domain.as_bytes());
        }
        Host::Ip(std::net::IpAddr::V6(address)) => {
            out.push(4);
            out.extend_from_slice(&address.octets());
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    Ok(out)
}

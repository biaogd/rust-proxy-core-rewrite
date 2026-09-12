use rewrite_model::{Destination, Host};

use crate::SnellProtocolError;

pub(crate) const WIRE_VERSION: u8 = 1;
pub(crate) const COMMAND_CONNECT: u8 = 1;
pub(crate) const COMMAND_CONNECT_V2: u8 = 5;
pub(crate) const COMMAND_TUNNEL: u8 = 0;
pub(crate) const COMMAND_ERROR: u8 = 2;

pub(crate) fn destination_host(destination: &Destination) -> String {
    match &destination.host {
        Host::Ip(address) => address.to_string(),
        Host::Domain(domain) => domain.clone(),
    }
}

pub(crate) fn encode_connect_header(
    destination: &Destination,
    version: u8,
) -> Result<Vec<u8>, SnellProtocolError> {
    let host = destination_host(destination);
    let host_len = u8::try_from(host.len()).map_err(|_| {
        SnellProtocolError::Protocol("Snell destination host exceeds 255 bytes".to_owned())
    })?;
    let command = if version == 2 {
        COMMAND_CONNECT_V2
    } else {
        COMMAND_CONNECT
    };
    let mut header = Vec::with_capacity(6 + host.len());
    header.push(WIRE_VERSION);
    header.push(command);
    header.push(0);
    header.push(host_len);
    header.extend_from_slice(host.as_bytes());
    header.extend_from_slice(&destination.port.to_be_bytes());
    Ok(header)
}

pub(crate) fn parse_connect_header(
    buffer: &[u8],
) -> Result<Option<(String, u16)>, SnellProtocolError> {
    if buffer.is_empty() {
        return Ok(None);
    }
    let version = *buffer
        .first()
        .ok_or_else(|| SnellProtocolError::Protocol("Snell header missing version".to_owned()))?;
    if version != WIRE_VERSION {
        return Err(SnellProtocolError::Protocol(format!(
            "unsupported Snell wire version {version}"
        )));
    }
    if buffer.len() < 4 {
        return Ok(None);
    }
    let command = buffer[1];
    if command != COMMAND_CONNECT && command != COMMAND_CONNECT_V2 {
        return Err(SnellProtocolError::Protocol(format!(
            "unsupported Snell command {command}"
        )));
    }
    let client_id_len = usize::from(buffer[2]);
    let host_len_index = 3 + client_id_len;
    let Some(&host_len) = buffer.get(host_len_index) else {
        return Ok(None);
    };
    let host_start = host_len_index + 1;
    let host_end = host_start + usize::from(host_len);
    let port_end = host_end + 2;
    if buffer.len() < port_end {
        return Ok(None);
    }
    let host = buffer
        .get(host_start..host_end)
        .ok_or_else(|| SnellProtocolError::Protocol("Snell header host slice failed".to_owned()))?;
    let host = std::str::from_utf8(host)
        .map_err(|_| SnellProtocolError::Protocol("Snell header host was not UTF-8".to_owned()))?
        .to_owned();
    let port_bytes = buffer
        .get(host_end..port_end)
        .ok_or_else(|| SnellProtocolError::Protocol("Snell header port slice failed".to_owned()))?;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    Ok(Some((host, port)))
}

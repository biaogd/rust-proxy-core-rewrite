use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rewrite_io::BoxedStream;
use rewrite_model::{Destination, Host};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{VlessClientOptions, VlessProtocolError};

const COMMAND_UDP: u8 = 2;
const COMMAND_MUX: u8 = 3;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 2;
const ADDRESS_IPV6: u8 = 3;
const PACKET_ADDR_MAGIC: &str = "sp.packet-addr.v2fly.arpa";
const VLESS_MAX_PACKET_FRAME: usize = 65_535;
const XUDP_STATUS_NEW: u8 = 1;
const XUDP_STATUS_KEEP: u8 = 2;
const XUDP_STATUS_END: u8 = 3;
const XUDP_STATUS_KEEPALIVE: u8 = 4;
const XUDP_OPTION_DATA: u8 = 1;
const XUDP_OPTION_ERROR: u8 = 2;
const XUDP_NETWORK_UDP: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VlessPacketMode {
    Standard,
    PacketAddr,
    Xudp,
}

pub struct VlessUdpAssociation {
    remote: BoxedStream,
    mode: VlessPacketMode,
    fixed_destination: Destination,
    uuid: [u8; 16],
    request_sent: bool,
    response_read: bool,
    xudp_global_id: [u8; 8],
    xudp_request_written: bool,
    xudp_read_buffer: Vec<u8>,
}

impl VlessUdpAssociation {
    /// Sends one UDP payload to `destination` over this VLESS association.
    ///
    /// # Errors
    ///
    /// Returns an I/O or framing error when the payload cannot be encoded or sent.
    pub async fn send(
        &mut self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), VlessProtocolError> {
        let frame = self.encode_frame(destination, payload)?;
        if frame.len() > VLESS_MAX_PACKET_FRAME {
            return Err(VlessProtocolError::Protocol(
                "VLESS UDP frame exceeds 65535 bytes".to_owned(),
            ));
        }
        if !self.request_sent {
            let request = request_header(self.mode, destination, self.uuid)?;
            self.remote.write_all(&request).await?;
            match self.mode {
                VlessPacketMode::Standard | VlessPacketMode::PacketAddr => {
                    let length = u16::try_from(frame.len()).map_err(|_| {
                        VlessProtocolError::Protocol(
                            "VLESS UDP frame exceeds 65535 bytes".to_owned(),
                        )
                    })?;
                    self.remote.write_all(&length.to_be_bytes()).await?;
                    self.remote.write_all(&frame).await?;
                }
                VlessPacketMode::Xudp => self.remote.write_all(&frame).await?,
            }
            self.request_sent = true;
            return Ok(());
        }
        match self.mode {
            VlessPacketMode::Xudp => self.remote.write_all(&frame).await?,
            VlessPacketMode::Standard | VlessPacketMode::PacketAddr => {
                let length = u16::try_from(frame.len()).map_err(|_| {
                    VlessProtocolError::Protocol("VLESS UDP frame exceeds 65535 bytes".to_owned())
                })?;
                self.remote.write_all(&length.to_be_bytes()).await?;
                self.remote.write_all(&frame).await?;
            }
        }
        Ok(())
    }

    /// Receives one UDP payload and its remote source from this VLESS association.
    ///
    /// # Errors
    ///
    /// Returns an I/O or framing error when the remote frame is invalid or truncated.
    pub async fn recv(&mut self) -> Result<(Destination, Vec<u8>), VlessProtocolError> {
        self.ensure_response_header().await?;
        match self.mode {
            VlessPacketMode::Standard => {
                let payload = read_length_prefixed(&mut self.remote).await?;
                Ok((self.fixed_destination.clone(), payload))
            }
            VlessPacketMode::PacketAddr => {
                let frame = read_length_prefixed(&mut self.remote).await?;
                let (destination, consumed) = decode_packet_address(&frame)?;
                Ok((destination, frame[consumed..].to_vec()))
            }
            VlessPacketMode::Xudp => self.recv_xudp().await,
        }
    }

    async fn ensure_response_header(&mut self) -> Result<(), VlessProtocolError> {
        if self.response_read {
            return Ok(());
        }
        read_response_header(&mut self.remote).await?;
        self.response_read = true;
        Ok(())
    }

    fn encode_frame(
        &mut self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<Vec<u8>, VlessProtocolError> {
        match self.mode {
            VlessPacketMode::Standard => {
                if destination != &self.fixed_destination {
                    return Err(VlessProtocolError::Protocol(
                        "VLESS UDP association destination changed".to_owned(),
                    ));
                }
                Ok(payload.to_vec())
            }
            VlessPacketMode::PacketAddr => {
                let mut frame = Vec::with_capacity(payload.len() + 19);
                encode_packet_address(&mut frame, destination)?;
                frame.extend_from_slice(payload);
                Ok(frame)
            }
            VlessPacketMode::Xudp => self.encode_xudp_frame(destination, payload),
        }
    }

    fn encode_xudp_frame(
        &mut self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<Vec<u8>, VlessProtocolError> {
        let payload_length = u16::try_from(payload.len()).map_err(|_| {
            VlessProtocolError::Protocol("XUDP payload exceeds 65535 bytes".to_owned())
        })?;
        let mut address = Vec::with_capacity(20);
        encode_xudp_address(&mut address, destination)?;
        let first = !self.xudp_request_written;
        let extension_length = if first { self.xudp_global_id.len() } else { 0 };
        let frame_header_length = 5_usize
            .checked_add(address.len())
            .and_then(|length| length.checked_add(extension_length))
            .ok_or_else(|| VlessProtocolError::Protocol("XUDP frame is too large".to_owned()))?;
        let frame_header_length = u16::try_from(frame_header_length)
            .map_err(|_| VlessProtocolError::Protocol("XUDP frame is too large".to_owned()))?;
        let mut frame =
            Vec::with_capacity(2 + usize::from(frame_header_length) + 2 + payload.len());
        frame.extend_from_slice(&frame_header_length.to_be_bytes());
        frame.extend_from_slice(&0_u16.to_be_bytes());
        frame.push(if first {
            XUDP_STATUS_NEW
        } else {
            XUDP_STATUS_KEEP
        });
        frame.push(XUDP_OPTION_DATA);
        frame.push(XUDP_NETWORK_UDP);
        frame.extend_from_slice(&address);
        if first {
            frame.extend_from_slice(&self.xudp_global_id);
            self.xudp_request_written = true;
        }
        frame.extend_from_slice(&payload_length.to_be_bytes());
        frame.extend_from_slice(payload);
        Ok(frame)
    }

    async fn recv_xudp(&mut self) -> Result<(Destination, Vec<u8>), VlessProtocolError> {
        loop {
            let length = {
                let bytes = self.take_xudp_bytes(2).await?;
                usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
            };
            if length < 4 {
                return Err(VlessProtocolError::Protocol(
                    "invalid XUDP frame header length".to_owned(),
                ));
            }
            let header = self.take_xudp_bytes(length).await?;
            let status = header[2];
            let option = header[3];
            if option & XUDP_OPTION_ERROR != 0 {
                return Err(VlessProtocolError::Protocol(
                    "remote closed XUDP association".to_owned(),
                ));
            }
            match status {
                XUDP_STATUS_NEW => {
                    return Err(VlessProtocolError::Protocol(
                        "unexpected XUDP new response frame".to_owned(),
                    ));
                }
                XUDP_STATUS_END => {
                    return Err(VlessProtocolError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "XUDP association ended",
                    )));
                }
                XUDP_STATUS_KEEP | XUDP_STATUS_KEEPALIVE => {}
                _ => {
                    return Err(VlessProtocolError::Protocol(
                        "invalid XUDP response status".to_owned(),
                    ));
                }
            }
            let destination = if length == 4 {
                self.fixed_destination.clone()
            } else {
                if header[4] != XUDP_NETWORK_UDP {
                    return Err(VlessProtocolError::Protocol(
                        "invalid XUDP response network".to_owned(),
                    ));
                }
                let (destination, consumed) = decode_xudp_address(&header[5..])?;
                if 5 + consumed != header.len() {
                    return Err(VlessProtocolError::Protocol(
                        "invalid XUDP response address length".to_owned(),
                    ));
                }
                destination
            };
            if option & XUDP_OPTION_DATA == 0 {
                continue;
            }
            let payload_length = {
                let bytes = self.take_xudp_bytes(2).await?;
                usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
            };
            let payload = self.take_xudp_bytes(payload_length).await?;
            return Ok((destination, payload));
        }
    }

    async fn take_xudp_bytes(&mut self, length: usize) -> Result<Vec<u8>, VlessProtocolError> {
        while self.xudp_read_buffer.len() < length {
            let mut buffer = vec![0_u8; 4096];
            let read = self.remote.read(&mut buffer).await?;
            if read == 0 {
                return Err(VlessProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated XUDP frame",
                )));
            }
            self.xudp_read_buffer.extend_from_slice(&buffer[..read]);
        }
        Ok(self.xudp_read_buffer.drain(..length).collect())
    }
}

/// Opens a VLESS UDP association over an established outer transport.
///
/// # Errors
///
/// Returns an error when the destination cannot be represented by the VLESS
/// version-zero address format.
pub async fn associate_vless_udp_on_stream(
    remote: BoxedStream,
    destination: &Destination,
    options: VlessClientOptions,
    mode: VlessPacketMode,
    xudp_global_id: [u8; 8],
) -> Result<VlessUdpAssociation, VlessProtocolError> {
    Ok(VlessUdpAssociation {
        remote,
        mode,
        fixed_destination: destination.clone(),
        uuid: options.uuid,
        request_sent: false,
        response_read: false,
        xudp_global_id,
        xudp_request_written: false,
        xudp_read_buffer: Vec::new(),
    })
}

fn request_header(
    mode: VlessPacketMode,
    destination: &Destination,
    uuid: [u8; 16],
) -> Result<Vec<u8>, VlessProtocolError> {
    let mut request = Vec::with_capacity(38);
    request.push(0);
    request.extend_from_slice(&uuid);
    request.push(0);
    match mode {
        VlessPacketMode::Xudp => request.push(COMMAND_MUX),
        VlessPacketMode::Standard => {
            request.push(COMMAND_UDP);
            append_address(&mut request, destination)?;
        }
        VlessPacketMode::PacketAddr => {
            request.push(COMMAND_UDP);
            append_address(
                &mut request,
                &Destination {
                    host: Host::Domain(PACKET_ADDR_MAGIC.to_owned()),
                    port: 443,
                },
            )?;
        }
    }
    Ok(request)
}

fn append_address(
    request: &mut Vec<u8>,
    destination: &Destination,
) -> Result<(), VlessProtocolError> {
    request.extend_from_slice(&destination.port.to_be_bytes());
    match &destination.host {
        Host::Ip(IpAddr::V4(address)) => {
            request.push(ADDRESS_IPV4);
            request.extend_from_slice(&address.octets());
        }
        Host::Ip(IpAddr::V6(address)) => {
            request.push(ADDRESS_IPV6);
            request.extend_from_slice(&address.octets());
        }
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                VlessProtocolError::Protocol("destination domain exceeds 255 bytes".to_owned())
            })?;
            request.push(ADDRESS_DOMAIN);
            request.push(length);
            request.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(())
}

async fn read_response_header(remote: &mut BoxedStream) -> Result<(), VlessProtocolError> {
    let mut response = [0_u8; 2];
    remote.read_exact(&mut response).await?;
    if response[0] != 0 {
        return Err(VlessProtocolError::Protocol(format!(
            "unexpected response version {}",
            response[0]
        )));
    }
    if response[1] != 0 {
        let mut addons = vec![0_u8; usize::from(response[1])];
        remote.read_exact(&mut addons).await?;
    }
    Ok(())
}

async fn read_length_prefixed(remote: &mut BoxedStream) -> Result<Vec<u8>, VlessProtocolError> {
    let mut length_bytes = [0_u8; 2];
    remote.read_exact(&mut length_bytes).await?;
    let length = usize::from(u16::from_be_bytes(length_bytes));
    let mut payload = vec![0_u8; length];
    remote.read_exact(&mut payload).await?;
    Ok(payload)
}

fn encode_packet_address(
    output: &mut Vec<u8>,
    destination: &Destination,
) -> Result<(), VlessProtocolError> {
    match destination.host {
        Host::Ip(IpAddr::V4(address)) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        Host::Ip(IpAddr::V6(address)) => {
            output.push(2);
            output.extend_from_slice(&address.octets());
        }
        Host::Domain(_) => {
            return Err(VlessProtocolError::Protocol(
                "packet-address mode requires a resolved IP destination".to_owned(),
            ));
        }
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

fn decode_packet_address(input: &[u8]) -> Result<(Destination, usize), VlessProtocolError> {
    let (host, address_length) = decode_ip_address(input, 1, 2)?;
    let port_offset = 1 + address_length;
    let port = read_u16(input, port_offset)?;
    Ok((Destination { host, port }, port_offset + 2))
}

fn encode_xudp_address(
    output: &mut Vec<u8>,
    destination: &Destination,
) -> Result<(), VlessProtocolError> {
    output.extend_from_slice(&destination.port.to_be_bytes());
    match &destination.host {
        Host::Ip(IpAddr::V4(address)) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                VlessProtocolError::Protocol("XUDP domain exceeds 255 bytes".to_owned())
            })?;
            if length == 0 {
                return Err(VlessProtocolError::Protocol(
                    "XUDP destination domain is empty".to_owned(),
                ));
            }
            output.push(2);
            output.push(length);
            output.extend_from_slice(domain.as_bytes());
        }
        Host::Ip(IpAddr::V6(address)) => {
            output.push(3);
            output.extend_from_slice(&address.octets());
        }
    }
    Ok(())
}

fn decode_xudp_address(input: &[u8]) -> Result<(Destination, usize), VlessProtocolError> {
    let port = read_u16(input, 0)?;
    let address_type = *input
        .get(2)
        .ok_or_else(|| VlessProtocolError::Protocol("truncated XUDP address".to_owned()))?;
    let (host, consumed) = match address_type {
        1 => {
            let octets: [u8; 4] = input
                .get(3..7)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| VlessProtocolError::Protocol("truncated XUDP IPv4".to_owned()))?;
            (Host::Ip(Ipv4Addr::from(octets).into()), 7)
        }
        2 => {
            let length =
                usize::from(*input.get(3).ok_or_else(|| {
                    VlessProtocolError::Protocol("truncated XUDP domain".to_owned())
                })?);
            let end = 4 + length;
            let domain = input
                .get(4..end)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .filter(|domain| !domain.is_empty())
                .ok_or_else(|| VlessProtocolError::Protocol("invalid XUDP domain".to_owned()))?;
            (Host::Domain(domain.to_owned()), end)
        }
        3 => {
            let octets: [u8; 16] = input
                .get(3..19)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| VlessProtocolError::Protocol("truncated XUDP IPv6".to_owned()))?;
            (Host::Ip(Ipv6Addr::from(octets).into()), 19)
        }
        _ => {
            return Err(VlessProtocolError::Protocol(
                "invalid XUDP address type".to_owned(),
            ));
        }
    };
    Ok((Destination { host, port }, consumed))
}

fn decode_ip_address(
    input: &[u8],
    ipv4_type: u8,
    ipv6_type: u8,
) -> Result<(Host, usize), VlessProtocolError> {
    match input.first().copied() {
        Some(value) if value == ipv4_type => {
            let octets: [u8; 4] = input
                .get(1..5)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    VlessProtocolError::Protocol("truncated packet-address IPv4".to_owned())
                })?;
            Ok((Host::Ip(Ipv4Addr::from(octets).into()), 4))
        }
        Some(value) if value == ipv6_type => {
            let octets: [u8; 16] = input
                .get(1..17)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    VlessProtocolError::Protocol("truncated packet-address IPv6".to_owned())
                })?;
            Ok((Host::Ip(Ipv6Addr::from(octets).into()), 16))
        }
        _ => Err(VlessProtocolError::Protocol(
            "invalid packet-address family".to_owned(),
        )),
    }
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, VlessProtocolError> {
    let bytes = input
        .get(offset..offset + 2)
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .ok_or_else(|| VlessProtocolError::Protocol("truncated integer".to_owned()))?;
    Ok(u16::from_be_bytes(bytes))
}
